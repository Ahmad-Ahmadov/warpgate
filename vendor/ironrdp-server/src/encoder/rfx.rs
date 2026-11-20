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
use tracing::debug;

use super::DISPLAY_TARGET;
use super::rfx_component::encode_component;
use crate::BitmapUpdate;

/// The room each component of a tile gets at first, as upstream gives it; almost every
/// component fits.
const COMPONENT_SLOT: usize = 4096;

/// The most one component of a tile can take: TS_RFX_TILE carries its length in 16 bits.
const COMPONENT_MAX: usize = u16::MAX as usize;

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
    /// The message is laid out as upstream lays it out; its tiles differ, as `encode_tile_into`
    /// pads edge tiles with their edges and the quantization rounds (see `rfx_component`).
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
    encode_tile_in(
        bitmap,
        quant,
        entropy_algorithm,
        tile_x,
        tile_y,
        &mut [0u8; 3 * COMPONENT_SLOT],
    )
}

/// `encode_tile`, each component given a third of `slots` first.
///
/// Warpgate: upstream fails the tile when a component needs more than its slot, and with it the
/// update, and the error ends the viewer's connection. Fine detail at fine quantization can need
/// more, so such a tile is encoded again with as much room as a component can take.
fn encode_tile_in(
    bitmap: &BitmapUpdate,
    quant: &Quant,
    entropy_algorithm: rfx::EntropyAlgorithm,
    tile_x: usize,
    tile_y: usize,
    slots: &mut [u8],
) -> Result<(Vec<u8>, usize, usize), RlgrError> {
    match encode_tile_into(bitmap, quant, entropy_algorithm, tile_x, tile_y, slots) {
        Err(RlgrError::OutputTooSmall { needed, available }) => {
            debug!(
                target: DISPLAY_TARGET,
                needed, available, tile_x, tile_y, "RemoteFX tile component larger than its slot, encoding again"
            );
            encode_tile_into(
                bitmap,
                quant,
                entropy_algorithm,
                tile_x,
                tile_y,
                &mut vec![0u8; 3 * COMPONENT_MAX],
            )
        }
        result => result,
    }
}

/// One attempt at `encode_tile`, each component given a third of `slots`.
fn encode_tile_into(
    bitmap: &BitmapUpdate,
    quant: &Quant,
    entropy_algorithm: rfx::EntropyAlgorithm,
    tile_x: usize,
    tile_y: usize,
    slots: &mut [u8],
) -> Result<(Vec<u8>, usize, usize), RlgrError> {
    #![allow(clippy::similar_names)] // It’s hard to find better names for cr, cb, etc.

    let bpp: usize = bitmap.format.bytes_per_pixel().into();
    let width: usize = bitmap.width.get().into();
    let height: usize = bitmap.height.get().into();

    let x = tile_x * 64;
    let y = tile_y * 64;
    let tile_width = core::cmp::min(width - x, 64);
    let tile_height = core::cmp::min(height - y, 64);
    let stride = bitmap.stride.get();
    let input = &bitmap.data[y * stride + x * bpp..];

    let stride = u32::try_from(stride).map_err(io::Error::other)?;
    let y = &mut [0i16; 4096];
    let cb = &mut [0i16; 4096];
    let cr = &mut [0i16; 4096];

    to_64x64_ycbcr_tile(
        input,
        u32::try_from(tile_width).expect("at most 64"),
        u32::try_from(tile_height).expect("at most 64"),
        stride,
        bitmap.format,
        y,
        cb,
        cr,
    )
    .map_err(RlgrError::Yuv)?;
    for plane in [&mut *y, &mut *cb, &mut *cr] {
        extend_edges(plane, tile_width, tile_height);
    }

    let slot = slots.len() / 3;
    let (y_data, rest) = slots.split_at_mut(slot);
    let (cb_data, rest) = rest.split_at_mut(slot);
    let cr_data = &mut rest[..slot];

    // Warpgate: `encode_component` is `ironrdp_graphics::rfx_encode_component`, faster, with
    // its quantization rounded to the nearest step; see its module.
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

/// Fill what lies outside the `width` by `height` picture in a 64x64 component plane with
/// copies of the picture's last column, then of its last row.
///
/// Warpgate: upstream leaves it as the colour conversion left it, zero, which is mid grey. The
/// wavelet carries the step from the picture to that grey back into the picture's last columns
/// and rows, and quantization leaves it there: a tile at the right or bottom edge of an update
/// shows a fringe along that edge, and most tiles are edge tiles when updates are the size of a
/// line of text. FreeRDP's encoder repeats the edge, as here. The client paints only the
/// update's rectangle, so what fills the rest is never seen.
fn extend_edges(plane: &mut [i16; 4096], width: usize, height: usize) {
    if width == 0 || height == 0 {
        return;
    }
    if width < 64 {
        for row in plane.chunks_exact_mut(64).take(height) {
            let last = row[width - 1];
            row[width..].fill(last);
        }
    }
    if height < 64 {
        let (picture, below) = plane.split_at_mut(height * 64);
        let last_row = &picture[(height - 1) * 64..];
        for row in below.chunks_exact_mut(64) {
            row.copy_from_slice(last_row);
        }
    }
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

/// Warpgate: the messages, read back by IronRDP's own decoder, as a client would.
#[cfg(test)]
mod tests {
    use core::num::{NonZeroU16, NonZeroUsize};

    use ironrdp_graphics::rfx::{MessageDecoder, TileDecoder};

    use super::*;
    use crate::PixelFormat;

    const DESKTOP: DesktopSize = DesktopSize {
        width: 1920,
        height: 1080,
    };

    /// No quantization beyond taking off the colour conversion's fractional bits.
    const FINEST: Quant = Quant {
        ll3: 6,
        lh3: 6,
        hl3: 6,
        hh3: 6,
        lh2: 6,
        hl2: 6,
        hh2: 6,
        lh1: 6,
        hl1: 6,
        hh1: 6,
    };

    /// A `width` by `height` BGRA bitmap, `pixel(x, y)` at each pixel.
    fn bitmap(width: u16, height: u16, pixel: impl Fn(usize, usize) -> [u8; 4]) -> BitmapUpdate {
        let mut data = Vec::with_capacity(usize::from(width) * usize::from(height) * 4);
        for y in 0..usize::from(height) {
            for x in 0..usize::from(width) {
                data.extend_from_slice(&pixel(x, y));
            }
        }
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

    /// A desktop: a soft gradient, with lines of strokes in dark, red and blue ink.
    fn desktop(x: usize, y: usize) -> [u8; 4] {
        let line = y / 16;
        if (3..12).contains(&(y % 16)) && (x * 7 + line * 13) % 11 < 3 {
            match line % 3 {
                0 => [20, 20, 20, 0xff],
                1 => [40, 40, 210, 0xff],
                _ => [230, 140, 50, 0xff],
            }
        } else {
            [(90 + y / 4) as u8, (60 + (x + y) / 8) as u8, (40 + x / 4) as u8, 0xff]
        }
    }

    /// Noise, the most a tile can take to encode.
    fn noise(x: usize, y: usize) -> [u8; 4] {
        let mut state = (x as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ ((y as u64 + 7) << 32);
        state ^= state >> 29;
        state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        state ^= state >> 32;
        let [b, g, r, ..] = state.to_le_bytes();
        [b, g, r, 0xff]
    }

    /// What a client paints for `message`, the message for a `width` by `height` bitmap: BGRA,
    /// row by row. Every pixel must be painted, and once.
    fn decode(message: &[u8], width: usize, height: usize) -> Vec<[u8; 4]> {
        let parsed = MessageDecoder::new().parse(message).unwrap();
        assert_eq!(parsed.frames.len(), 1);
        let frame = &parsed.frames[0];
        let tile_set = &frame.tile_set;
        let mut decoder = TileDecoder::new();
        let mut painted = vec![None; width * height];
        for tile in &tile_set.tiles {
            let rgba = decoder
                .decode(tile, &tile_set.quants, tile_set.entropy_algorithm)
                .unwrap();
            for (row, pixels) in rgba.chunks_exact(64 * 4).enumerate() {
                for (column, pixel) in pixels.chunks_exact(4).enumerate() {
                    let x = usize::from(tile.x) * 64 + column;
                    let y = usize::from(tile.y) * 64 + row;
                    if x < width && y < height {
                        let slot = &mut painted[y * width + x];
                        assert!(slot.is_none(), "({x}, {y}) is painted twice");
                        *slot = Some([pixel[2], pixel[1], pixel[0], pixel[3]]);
                    }
                }
            }
        }
        painted
            .into_iter()
            .enumerate()
            .map(|(at, pixel)| pixel.unwrap_or_else(|| panic!("({}, {}) is not painted", at % width, at / width)))
            .collect()
    }

    /// The largest difference, in any colour channel, between `bitmap` and what `message` paints.
    fn worst_error(bitmap: &BitmapUpdate, message: &[u8]) -> u8 {
        let width = usize::from(bitmap.width.get());
        let height = usize::from(bitmap.height.get());
        decode(message, width, height)
            .iter()
            .zip(bitmap.data.chunks_exact(4))
            .flat_map(|(painted, source)| (0..3).map(move |channel| painted[channel].abs_diff(source[channel])))
            .max()
            .unwrap()
    }

    #[test]
    fn messages_decode_to_their_bitmap() {
        let sizes = [(1, 1), (3, 70), (64, 64), (65, 63), (130, 129), (200, 1), (1, 200)];
        for (width, height) in sizes {
            let bitmap = bitmap(width, height, desktop);
            for entropy_bits in [EntropyBits::Rlgr1, EntropyBits::Rlgr3] {
                // The finest quantization only rounds; the default one, Windows', drops detail.
                // Rounding down, and padding edge tiles with grey, were off by twice as much.
                for (quant, bound) in [(FINEST, 12), (Quant::default(), 40)] {
                    let encoder = RfxEncoder::new(entropy_bits, quant);
                    let message = encoder.encode(&bitmap, Some(DESKTOP)).unwrap();
                    let worst = worst_error(&bitmap, &message);
                    assert!(
                        worst <= bound,
                        "{width}x{height} {entropy_bits:?}: off by {worst}, more than {bound}"
                    );

                    // Without the header blocks, the same message less them.
                    let bare = encoder.encode(&bitmap, None).unwrap();
                    assert!(message.len() > bare.len() && message.ends_with(&bare));
                }
            }
        }
    }

    #[test]
    fn flat_colour_decodes_as_itself_at_any_size() {
        // Nothing in a flat picture for quantization to drop, if what pads its tiles out to
        // 64x64 is more of it. Mid grey, as upstream padded them, leaves a fringe.
        let colours = [[0xff, 0xff, 0xff, 0xff], [38, 34, 32, 0xff], [200, 120, 30, 0xff], [13, 200, 77, 0xff]];
        for colour in colours {
            for (width, height) in [(40, 17), (1, 1), (63, 64), (64, 5), (7, 33), (64, 64)] {
                let bitmap = bitmap(width, height, |_, _| colour);
                for quant in [FINEST, Quant::default()] {
                    let message = RfxEncoder::new(EntropyBits::Rlgr3, quant)
                        .encode(&bitmap, Some(DESKTOP))
                        .unwrap();
                    let worst = worst_error(&bitmap, &message);
                    assert!(worst <= 2, "{colour:?} {width}x{height}: off by {worst}");
                }
            }
        }
    }

    #[test]
    fn a_component_larger_than_its_slot_is_encoded_with_more_room() {
        let bitmap = bitmap(64, 64, noise);
        for algorithm in [rfx::EntropyAlgorithm::Rlgr1, rfx::EntropyAlgorithm::Rlgr3] {
            // Sixteen bytes are not enough for any component of noise.
            let cramped = &mut [0u8; 3 * 16];
            assert!(matches!(
                encode_tile_into(&bitmap, &FINEST, algorithm, 0, 0, cramped),
                Err(RlgrError::OutputTooSmall { .. })
            ));
            let roomy = encode_tile(&bitmap, &FINEST, algorithm, 0, 0).unwrap();
            let retried = encode_tile_in(&bitmap, &FINEST, algorithm, 0, 0, cramped).unwrap();
            assert!(retried == roomy);
        }

        // And the message that carries it decodes.
        let message = RfxEncoder::new(EntropyBits::Rlgr3, FINEST)
            .encode(&bitmap, Some(DESKTOP))
            .unwrap();
        let worst = worst_error(&bitmap, &message);
        assert!(worst <= 24, "noise off by {worst}");
    }

    #[test]
    fn every_tile_is_in_the_message_in_order() {
        let bitmap = bitmap(200, 150, desktop);
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
