use std::io;

use ironrdp_acceptor::DesktopSize;
use ironrdp_core::{Encode as _, EncodeResult, cast_int, cast_length, other_err};
use ironrdp_graphics::color_conversion::to_64x64_ycbcr_tile;
use ironrdp_graphics::rlgr::RlgrError;
use ironrdp_pdu::WriteCursor;
use ironrdp_pdu::codecs::rfx::{
    self, Block, ChannelsPdu, CodecChannel, CodecVersionsPdu, FrameBeginPdu, FrameEndPdu, OperatingMode, Quant,
    RegionPdu, RfxChannel, SyncPdu, TileSetPdu,
};
use ironrdp_pdu::rdp::capability_sets::EntropyBits;

use super::rfx_component::encode_component;
use crate::BitmapUpdate;

/// The most one component of a tile may take. A component that needs more fails its tile, as it
/// always has: the encoder gives each component this much room.
const COMPONENT_MAX: usize = 4096;

#[derive(Debug, Clone)]
pub(crate) struct RfxEncoder {
    entropy_algorithm: rfx::EntropyAlgorithm,
    quant: Quant,
}

impl RfxEncoder {
    pub(crate) fn new(entropy_bits: EntropyBits, quant: Quant) -> Self {
        let entropy_algorithm = match entropy_bits {
            EntropyBits::Rlgr1 => rfx::EntropyAlgorithm::Rlgr1,
            EntropyBits::Rlgr3 => rfx::EntropyAlgorithm::Rlgr3,
        };
        Self {
            entropy_algorithm,
            quant,
        }
    }

    /// The RemoteFX message for `bitmap`, in a buffer of exactly its length.
    ///
    /// Warpgate: upstream encodes into a buffer the caller sizes and zeroes, and when that was too
    /// small, grows it and encodes every tile again; its tiles share one more zeroed buffer, three
    /// worst-case components per tile. Here each tile is encoded into a buffer of exactly its size,
    /// and the message is then written once, into a buffer of exactly the size the tiles add up to.
    /// The bytes are the same.
    pub(crate) fn encode(&self, bitmap: &BitmapUpdate, desktop_size: Option<DesktopSize>) -> EncodeResult<Vec<u8>> {
        let entropy_algorithm = self.entropy_algorithm;
        let quant = self.quant.clone();
        quant.validate()?;

        let encoded = encode_tiles(bitmap, &quant, entropy_algorithm)?;
        let tiles = encoded.iter().map(EncodedTile::as_tile).collect();

        let mut blocks = Vec::with_capacity(8);

        // header messages
        if let Some(desktop_size) = desktop_size {
            blocks.push(Block::Sync(SyncPdu));
            blocks.push(Block::CodecChannel(CodecChannel::Context(rfx::ContextPdu {
                flags: OperatingMode::IMAGE_MODE,
                entropy_algorithm,
            })));
            blocks.push(Block::Channels(ChannelsPdu(vec![RfxChannel {
                width: cast_length!("width", desktop_size.width)?,
                height: cast_length!("height", desktop_size.height)?,
            }])));
            blocks.push(Block::CodecVersions(CodecVersionsPdu));
        }

        // data messages
        blocks.push(Block::CodecChannel(CodecChannel::FrameBegin(FrameBeginPdu {
            index: 0,
            number_of_regions: 1,
        })));
        blocks.push(Block::CodecChannel(CodecChannel::Region(RegionPdu {
            rectangles: vec![rfx::RfxRectangle {
                x: 0,
                y: 0,
                width: bitmap.width.get(),
                height: bitmap.height.get(),
            }],
        })));
        blocks.push(Block::CodecChannel(CodecChannel::TileSet(TileSetPdu {
            entropy_algorithm,
            quants: vec![quant],
            tiles,
        })));
        blocks.push(Block::CodecChannel(CodecChannel::FrameEnd(FrameEndPdu)));

        let mut output = vec![0; blocks.iter().map(|block| block.size()).sum()];
        let len = {
            let mut cursor = WriteCursor::new(&mut output);
            for block in &blocks {
                block.encode(&mut cursor)?;
            }
            cursor.pos()
        };
        output.truncate(len);
        Ok(output)
    }
}

/// One tile, its three components encoded back to back.
struct EncodedTile {
    x: u16,
    y: u16,
    data: Vec<u8>,
    y_len: usize,
    cb_len: usize,
}

impl EncodedTile {
    fn as_tile(&self) -> rfx::Tile<'_> {
        let (y_data, rest) = self.data.split_at(self.y_len);
        let (cb_data, cr_data) = rest.split_at(self.cb_len);
        rfx::Tile {
            y_quant_index: 0,
            cb_quant_index: 0,
            cr_quant_index: 0,
            x: self.x,
            y: self.y,
            y_data,
            cb_data,
            cr_data,
        }
    }
}

/// Every tile of `bitmap`, row by row, encoded in parallel when the `rayon` feature is on.
fn encode_tiles(
    bitmap: &BitmapUpdate,
    quant: &Quant,
    entropy_algorithm: rfx::EntropyAlgorithm,
) -> EncodeResult<Vec<EncodedTile>> {
    #[cfg(feature = "rayon")]
    use rayon::prelude::*;

    let tiles_x = usize::from(bitmap.width.get().div_ceil(64));
    let tiles_y = usize::from(bitmap.height.get().div_ceil(64));
    let positions: Vec<(usize, usize)> = (0..tiles_y)
        .flat_map(|y| (0..tiles_x).map(move |x| (x, y)))
        .collect();

    #[cfg(feature = "rayon")]
    let positions = positions.into_par_iter();
    #[cfg(not(feature = "rayon"))]
    let positions = positions.into_iter();

    positions
        .map(|(tile_x, tile_y)| {
            let x = cast_int!("tile_x", tile_x)?;
            let y = cast_int!("tile_y", tile_y)?;
            let (data, y_len, cb_len) = encode_tile(bitmap, quant, entropy_algorithm, tile_x, tile_y)
                .map_err(|e| other_err!("rfxenc", source: e))?;
            Ok(EncodedTile {
                x,
                y,
                data,
                y_len,
                cb_len,
            })
        })
        .collect()
}

/// The Y, Cb and Cr components of one tile, back to back, with the lengths of the first two.
fn encode_tile(
    bitmap: &BitmapUpdate,
    quant: &Quant,
    entropy_algorithm: rfx::EntropyAlgorithm,
    tile_x: usize,
    tile_y: usize,
) -> Result<(Vec<u8>, usize, usize), RlgrError> {
    #![allow(clippy::similar_names)] // It’s hard to find better names for cr, cb, etc.

    let bpp: usize = bitmap.format.bytes_per_pixel().into();
    let width: usize = bitmap.width.get().into();
    let height: usize = bitmap.height.get().into();

    let x = tile_x * 64;
    let y = tile_y * 64;
    let tile_width = u32::try_from(core::cmp::min(width - x, 64)).expect("can always fit in u32");
    let tile_height = u32::try_from(core::cmp::min(height - y, 64)).expect("can always fit in u32");
    let stride = bitmap.stride.get();
    let input = &bitmap.data[y * stride + x * bpp..];

    let stride = u32::try_from(stride).map_err(io::Error::other)?;
    let y = &mut [0i16; 4096];
    let cb = &mut [0i16; 4096];
    let cr = &mut [0i16; 4096];

    to_64x64_ycbcr_tile(input, tile_width, tile_height, stride, bitmap.format, y, cb, cr).map_err(RlgrError::Yuv)?;

    let mut components = [0u8; 3 * COMPONENT_MAX];
    let (y_data, rest) = components.split_at_mut(COMPONENT_MAX);
    let (cb_data, cr_data) = rest.split_at_mut(COMPONENT_MAX);

    // Warpgate: `encode_component` writes what `ironrdp_graphics::rfx_encode_component`
    // would, faster; see its module.
    let temp = &mut [0i16; 4096];
    let y_len = encode_component(y, temp, y_data, quant, entropy_algorithm)?;
    let cb_len = encode_component(cb, temp, cb_data, quant, entropy_algorithm)?;
    let cr_len = encode_component(cr, temp, cr_data, quant, entropy_algorithm)?;

    let mut data = Vec::with_capacity(y_len + cb_len + cr_len);
    data.extend_from_slice(&y_data[..y_len]);
    data.extend_from_slice(&cb_data[..cb_len]);
    data.extend_from_slice(&cr_data[..cr_len]);
    Ok((data, y_len, cb_len))
}

#[cfg(feature = "__bench")]
#[expect(clippy::missing_panics_doc, reason = "panics in benches are allowed")]
pub(crate) mod bench {
    use super::*;

    pub fn rfx_enc_tile(
        bitmap: &BitmapUpdate,
        quant: &Quant,
        algo: rfx::EntropyAlgorithm,
        tile_x: usize,
        tile_y: usize,
    ) {
        encode_tile(bitmap, quant, algo, tile_x, tile_y).expect("cannot propagate error in benchmark");
    }

    pub fn rfx_enc(bitmap: &BitmapUpdate, quant: &Quant, algo: rfx::EntropyAlgorithm) {
        encode_tiles(bitmap, quant, algo).expect("cannot propagate error in benchmark");
    }
}

/// Warpgate: the message is the one upstream's encoder writes, byte for byte, here rebuilt from
/// IronRDP's own component coder and block encoding.
#[cfg(test)]
mod tests {
    use core::num::{NonZeroU16, NonZeroUsize};

    use ironrdp_core::Encode as _;
    use ironrdp_graphics::rfx::MessageDecoder;
    use ironrdp_graphics::rfx_encode_component;

    use super::*;
    use crate::PixelFormat;

    fn bitmap(width: u16, height: u16, seed: u64) -> BitmapUpdate {
        let mut state = seed;
        let data: Vec<u8> = (0..usize::from(width) * usize::from(height) * 4)
            .map(|i| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                // Smooth areas and noise both, as desktops have.
                if (i / 4) % 7 < 3 {
                    (i / 97) as u8
                } else {
                    state.to_le_bytes()[0]
                }
            })
            .collect();
        BitmapUpdate {
            x: 0,
            y: 0,
            width: NonZeroU16::new(width).unwrap(),
            height: NonZeroU16::new(height).unwrap(),
            format: PixelFormat::BgrA32,
            data: data.into(),
            stride: NonZeroUsize::new(usize::from(width) * 4).unwrap(),
        }
    }

    /// The message as upstream builds it: every tile through `rfx_encode_component`, each
    /// component in a 4096-byte slot, the blocks written one after another.
    fn upstream_message(
        bitmap: &BitmapUpdate,
        quant: &Quant,
        entropy_algorithm: rfx::EntropyAlgorithm,
        desktop_size: Option<DesktopSize>,
    ) -> Vec<u8> {
        let tiles_x = usize::from(bitmap.width.get().div_ceil(64));
        let tiles_y = usize::from(bitmap.height.get().div_ceil(64));
        let mut slots = vec![[0u8; 3 * COMPONENT_MAX]; tiles_x * tiles_y];
        let mut lens = Vec::new();
        for (index, slot) in slots.iter_mut().enumerate() {
            let (tile_x, tile_y) = (index % tiles_x, index / tiles_x);
            let (x, y) = (tile_x * 64, tile_y * 64);
            let stride = bitmap.stride.get();
            let (mut luma, mut cb, mut cr) = ([0i16; 4096], [0i16; 4096], [0i16; 4096]);
            to_64x64_ycbcr_tile(
                &bitmap.data[y * stride + x * 4..],
                u32::try_from((usize::from(bitmap.width.get()) - x).min(64)).unwrap(),
                u32::try_from((usize::from(bitmap.height.get()) - y).min(64)).unwrap(),
                u32::try_from(stride).unwrap(),
                bitmap.format,
                &mut luma,
                &mut cb,
                &mut cr,
            )
            .unwrap();
            let (y_slot, rest) = slot.split_at_mut(COMPONENT_MAX);
            let (cb_slot, cr_slot) = rest.split_at_mut(COMPONENT_MAX);
            lens.push((
                rfx_encode_component(&mut luma, y_slot, quant, entropy_algorithm).unwrap(),
                rfx_encode_component(&mut cb, cb_slot, quant, entropy_algorithm).unwrap(),
                rfx_encode_component(&mut cr, cr_slot, quant, entropy_algorithm).unwrap(),
            ));
        }
        let tiles = slots
            .iter()
            .zip(&lens)
            .enumerate()
            .map(|(index, (slot, &(y_len, cb_len, cr_len)))| rfx::Tile {
                y_quant_index: 0,
                cb_quant_index: 0,
                cr_quant_index: 0,
                x: u16::try_from(index % tiles_x).unwrap(),
                y: u16::try_from(index / tiles_x).unwrap(),
                y_data: &slot[..y_len],
                cb_data: &slot[COMPONENT_MAX..COMPONENT_MAX + cb_len],
                cr_data: &slot[2 * COMPONENT_MAX..2 * COMPONENT_MAX + cr_len],
            })
            .collect();

        let mut output = vec![0; 64 * 1024 + tiles_x * tiles_y * 3 * COMPONENT_MAX];
        let mut cursor = WriteCursor::new(&mut output);
        if let Some(desktop_size) = desktop_size {
            Block::Sync(SyncPdu).encode(&mut cursor).unwrap();
            Block::CodecChannel(CodecChannel::Context(rfx::ContextPdu {
                flags: OperatingMode::IMAGE_MODE,
                entropy_algorithm,
            }))
            .encode(&mut cursor)
            .unwrap();
            Block::Channels(ChannelsPdu(vec![RfxChannel {
                width: i16::try_from(desktop_size.width).unwrap(),
                height: i16::try_from(desktop_size.height).unwrap(),
            }]))
            .encode(&mut cursor)
            .unwrap();
            Block::CodecVersions(CodecVersionsPdu).encode(&mut cursor).unwrap();
        }
        Block::CodecChannel(CodecChannel::FrameBegin(FrameBeginPdu {
            index: 0,
            number_of_regions: 1,
        }))
        .encode(&mut cursor)
        .unwrap();
        Block::CodecChannel(CodecChannel::Region(RegionPdu {
            rectangles: vec![rfx::RfxRectangle {
                x: 0,
                y: 0,
                width: bitmap.width.get(),
                height: bitmap.height.get(),
            }],
        }))
        .encode(&mut cursor)
        .unwrap();
        Block::CodecChannel(CodecChannel::TileSet(TileSetPdu {
            entropy_algorithm,
            quants: vec![quant.clone()],
            tiles,
        }))
        .encode(&mut cursor)
        .unwrap();
        Block::CodecChannel(CodecChannel::FrameEnd(FrameEndPdu))
            .encode(&mut cursor)
            .unwrap();
        let len = cursor.pos();
        output.truncate(len);
        output
    }

    #[test]
    fn messages_are_what_upstream_writes() {
        let desktop = DesktopSize {
            width: 1920,
            height: 1080,
        };
        let sizes = [(1, 1), (3, 70), (64, 64), (65, 63), (130, 129), (200, 1), (1, 200)];
        for (seed, (width, height)) in (1u64..).zip(sizes) {
            let bitmap = bitmap(width, height, seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            for (entropy_bits, entropy_algorithm) in [
                (EntropyBits::Rlgr1, rfx::EntropyAlgorithm::Rlgr1),
                (EntropyBits::Rlgr3, rfx::EntropyAlgorithm::Rlgr3),
            ] {
                let encoder = RfxEncoder::new(entropy_bits, Quant::default());
                for desktop_size in [Some(desktop), None] {
                    let ours = encoder.encode(&bitmap, desktop_size).unwrap();
                    let theirs = upstream_message(&bitmap, &Quant::default(), entropy_algorithm, desktop_size);
                    assert!(
                        ours == theirs,
                        "{width}x{height} {entropy_bits:?}: {} bytes against {}",
                        ours.len(),
                        theirs.len()
                    );
                }
            }
        }
    }

    #[test]
    fn every_tile_is_in_the_message_in_order() {
        let bitmap = bitmap(200, 150, 7);
        let message = RfxEncoder::new(EntropyBits::Rlgr3, Quant::default())
            .encode(
                &bitmap,
                Some(DesktopSize {
                    width: 800,
                    height: 600,
                }),
            )
            .unwrap();
        let parsed = MessageDecoder::new().parse(&message).unwrap();
        assert_eq!(parsed.frames.len(), 1);
        let frame = &parsed.frames[0];
        assert_eq!(frame.rectangles.len(), 1);
        assert_eq!((frame.rectangles[0].width, frame.rectangles[0].height), (200, 150));
        let positions: Vec<_> = frame.tile_set.tiles.iter().map(|tile| (tile.x, tile.y)).collect();
        let expected: Vec<_> = (0..3u16).flat_map(|y| (0..4u16).map(move |x| (x, y))).collect();
        assert_eq!(positions, expected);
    }
}
