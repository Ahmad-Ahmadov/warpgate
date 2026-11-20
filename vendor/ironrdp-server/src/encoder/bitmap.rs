//! Warpgate: RDP 6.0 bitmap updates (MS-RDPBCGR 2.2.9.1.1.3.1.2), lossless, for a client that
//! shares no bitmap codec with the server or takes no surface commands.
//!
//! Upstream's snapshot sent the first kind of client raw 32-bit surface bits, about 8 MB for a
//! 1080p screen, and sent the second bitmaps as tall as a fast-path update allows, failing any
//! whose width is not a multiple of four. Here a bitmap goes as tiles of at most 64x64, as
//! Windows servers send them and as FreeRDP's planar decoder requires, each padded to a width
//! that is a multiple of four. The padding repeats the last column and lies outside the tile's
//! destination rectangle, so no client shows it. Each tile is RLE-compressed unless that comes
//! out larger than its planes, and the tiles are encoded in parallel.

use ironrdp_core::{Encode as _, WriteCursor, cast_length};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_graphics::rdp6::{
    ABgrChannels, ARgbChannels, BgrAChannels, BitmapEncodeError, BitmapStreamEncoder, RgbAChannels,
};
use ironrdp_pdu::bitmap::{BitmapData, BitmapUpdateData, CompressedDataHeader, Compression};
use ironrdp_pdu::geometry::InclusiveRectangle;

use crate::BitmapUpdate;

/// The largest tile, per side.
pub(crate) const TILE_SIZE: u16 = 64;

/// A tile's place in its bitmap: x, y, width, height.
type TileRect = (u16, u16, u16, u16);

struct EncodedTile {
    rect: TileRect,
    /// The width the tile is sent at, a multiple of four.
    padded_width: u16,
    stream: Vec<u8>,
}

/// The TS_UPDATE_BITMAP_DATA that paints `bitmap`.
pub(crate) fn encode(bitmap: &BitmapUpdate) -> Result<Vec<u8>, BitmapEncodeError> {
    #[cfg(feature = "rayon")]
    use rayon::prelude::*;

    let rects = tile_rects(bitmap.width.get(), bitmap.height.get());
    #[cfg(feature = "rayon")]
    let rects = rects.into_par_iter();
    #[cfg(not(feature = "rayon"))]
    let rects = rects.into_iter();
    let tiles: Vec<EncodedTile> = rects.map(|rect| encode_tile(bitmap, rect)).collect::<Result<_, _>>()?;

    let bits_per_pixel = u16::from(bitmap.format.bytes_per_pixel()) * 8;
    let mut rectangles = Vec::with_capacity(tiles.len());
    for tile in &tiles {
        let (x, y, width, height) = tile.rect;
        let left = bitmap.x + x;
        let top = bitmap.y + y;
        rectangles.push(BitmapData {
            rectangle: InclusiveRectangle {
                left,
                top,
                right: left + width - 1,
                bottom: top + height - 1,
            },
            width: tile.padded_width,
            height,
            bits_per_pixel,
            compression_flags: Compression::BITMAP_COMPRESSION,
            compressed_data_header: Some(CompressedDataHeader {
                main_body_size: cast_length!("main body size", tile.stream.len()).map_err(BitmapEncodeError::Encode)?,
                scan_width: tile.padded_width,
                uncompressed_size: tile.padded_width * height * u16::from(bitmap.format.bytes_per_pixel()),
            }),
            bitmap_data: &tile.stream,
        });
    }

    let update = BitmapUpdateData { rectangles };
    let mut output = vec![0; update.size()];
    update
        .encode(&mut WriteCursor::new(&mut output))
        .map_err(BitmapEncodeError::Encode)?;
    Ok(output)
}

/// The tiles that cover a `width` by `height` bitmap, row by row.
fn tile_rects(width: u16, height: u16) -> Vec<TileRect> {
    let step = usize::from(TILE_SIZE);
    (0..height)
        .step_by(step)
        .flat_map(|y| {
            (0..width)
                .step_by(step)
                .map(move |x| (x, y, TILE_SIZE.min(width - x), TILE_SIZE.min(height - y)))
        })
        .collect()
}

fn encode_tile(bitmap: &BitmapUpdate, rect: TileRect) -> Result<EncodedTile, BitmapEncodeError> {
    let (x, y, width, height) = rect;
    let padded_width = width.next_multiple_of(4);
    let bpp = usize::from(bitmap.format.bytes_per_pixel());
    let stride = bitmap.stride.get();
    let row_len = usize::from(width) * bpp;

    // Bottom-up, as a bitmap's rows go, each padded with copies of its last pixel.
    let mut pixels = Vec::with_capacity(usize::from(padded_width) * usize::from(height) * bpp);
    for row in (usize::from(y)..usize::from(y) + usize::from(height)).rev() {
        let start = row * stride + usize::from(x) * bpp;
        let line = &bitmap.data[start..start + row_len];
        pixels.extend_from_slice(line);
        let last = &line[row_len - bpp..];
        for _ in width..padded_width {
            pixels.extend_from_slice(last);
        }
    }

    // A header byte, the three planes, and a padding byte: the stream without RLE. RLE is kept
    // only if it fits in that, which is all the room it gets.
    let planes = 3 * usize::from(padded_width) * usize::from(height);
    let mut stream = vec![0; planes + 2];
    let mut encoder = BitmapStreamEncoder::new(usize::from(padded_width), usize::from(height));
    let len = match encode_planes(&mut encoder, bitmap.format, &pixels, &mut stream, true) {
        Ok(len) => len,
        Err(_) => encode_planes(&mut encoder, bitmap.format, &pixels, &mut stream, false)?,
    };
    stream.truncate(len);

    Ok(EncodedTile {
        rect,
        padded_width,
        stream,
    })
}

fn encode_planes(
    encoder: &mut BitmapStreamEncoder,
    format: PixelFormat,
    pixels: &[u8],
    dst: &mut [u8],
    rle: bool,
) -> Result<usize, BitmapEncodeError> {
    match format {
        PixelFormat::ARgb32 | PixelFormat::XRgb32 => encoder.encode_bitmap::<ARgbChannels>(pixels, dst, rle),
        PixelFormat::RgbA32 | PixelFormat::RgbX32 => encoder.encode_bitmap::<RgbAChannels>(pixels, dst, rle),
        PixelFormat::ABgr32 | PixelFormat::XBgr32 => encoder.encode_bitmap::<ABgrChannels>(pixels, dst, rle),
        PixelFormat::BgrA32 | PixelFormat::BgrX32 => encoder.encode_bitmap::<BgrAChannels>(pixels, dst, rle),
    }
}

#[cfg(test)]
mod tests {
    use core::num::{NonZeroU16, NonZeroUsize};

    use ironrdp_core::decode;
    use ironrdp_graphics::rdp6::BitmapStreamDecoder;

    use super::*;

    /// A `width` by `height` BGRA bitmap at (`x`, `y`), from `pixel(column, row)`.
    fn bitmap(x: u16, y: u16, width: u16, height: u16, pixel: impl Fn(usize, usize) -> [u8; 4]) -> BitmapUpdate {
        let mut data = Vec::new();
        for row in 0..usize::from(height) {
            for column in 0..usize::from(width) {
                data.extend_from_slice(&pixel(column, row));
            }
        }
        BitmapUpdate {
            x,
            y,
            width: NonZeroU16::new(width).unwrap(),
            height: NonZeroU16::new(height).unwrap(),
            format: PixelFormat::BgrA32,
            data: data.into(),
            stride: NonZeroUsize::new(usize::from(width) * 4).unwrap(),
        }
    }

    fn noise(column: usize, row: usize) -> [u8; 4] {
        let mut state = (column as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ (row as u64 + 7) << 32;
        state ^= state >> 29;
        state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        state ^= state >> 32;
        let [b, g, r, ..] = state.to_le_bytes();
        [b, g, r, 0xff]
    }

    fn flat(_: usize, row: usize) -> [u8; 4] {
        [0x30, 0x60, 0x90 + (row / 16) as u8, 0xff]
    }

    /// Decode what `encode` wrote and check that it paints exactly `bitmap`.
    fn assert_paints(bitmap: &BitmapUpdate) {
        let update_data = encode(bitmap).unwrap();
        let update: BitmapUpdateData<'_> = decode(&update_data).unwrap();
        let (left, top) = (usize::from(bitmap.x), usize::from(bitmap.y));
        let (width, height) = (usize::from(bitmap.width.get()), usize::from(bitmap.height.get()));
        let mut painted = vec![false; width * height];

        for tile in &update.rectangles {
            let rect = &tile.rectangle;
            let tile_width = usize::from(rect.right - rect.left) + 1;
            let tile_height = usize::from(rect.bottom - rect.top) + 1;
            assert!(tile_width <= 64 && tile_height <= 64, "{rect:?} is larger than 64x64");
            assert_eq!(tile.width % 4, 0, "{rect:?} is sent {} wide", tile.width);
            assert!(usize::from(tile.width) >= tile_width && usize::from(tile.width) < tile_width + 4);
            assert_eq!(usize::from(tile.height), tile_height);
            assert_eq!(tile.bits_per_pixel, 32);
            assert!(tile.compression_flags.contains(Compression::BITMAP_COMPRESSION));
            let header = tile.compressed_data_header.as_ref().unwrap();
            assert_eq!(usize::from(header.main_body_size), tile.bitmap_data.len());
            assert_eq!(header.scan_width, tile.width);

            let mut rgb = Vec::new();
            BitmapStreamDecoder::default()
                .decode_bitmap_stream_to_rgb24(tile.bitmap_data, &mut rgb, usize::from(tile.width), tile_height)
                .unwrap();
            assert_eq!(rgb.len(), usize::from(tile.width) * tile_height * 3);
            let tile_left = usize::from(rect.left) - left;
            for (bottom_up, line) in rgb.chunks_exact(usize::from(tile.width) * 3).enumerate() {
                let row = usize::from(rect.top) - top + tile_height - 1 - bottom_up;
                for (column, decoded) in line.chunks_exact(3).enumerate() {
                    // The padding repeats the last column.
                    let source_column = tile_left + column.min(tile_width - 1);
                    let start = (row * width + source_column) * 4;
                    let expected = [bitmap.data[start + 2], bitmap.data[start + 1], bitmap.data[start]];
                    assert_eq!(decoded, expected, "pixel ({source_column}, {row}) of {rect:?}");
                    if column < tile_width {
                        let pixel = &mut painted[row * width + source_column];
                        assert!(!*pixel, "pixel ({source_column}, {row}) is painted twice");
                        *pixel = true;
                    }
                }
            }
        }
        assert!(painted.iter().all(|&painted| painted), "some pixels are not painted");
    }

    #[test]
    fn a_bitmap_is_painted_exactly_in_tiles_of_at_most_64x64() {
        for (width, height) in [(1, 1), (3, 5), (4, 4), (63, 2), (64, 64), (65, 70), (130, 3), (2, 130), (257, 129)] {
            assert_paints(&bitmap(0, 0, width, height, noise));
            assert_paints(&bitmap(17, 33, width, height, flat));
        }
    }

    #[test]
    fn flat_content_is_compressed_and_noise_is_never_larger_than_its_planes() {
        let flat = encode(&bitmap(0, 0, 64, 64, flat)).unwrap();
        let noisy = encode(&bitmap(0, 0, 64, 64, noise)).unwrap();
        let raw = 64 * 64 * 4;
        assert!(flat.len() < raw / 10, "{} bytes for a flat tile", flat.len());
        // A header byte, three planes, a padding byte, and the update's own headers.
        assert!(noisy.len() <= 3 * 64 * 64 + 2 + 64, "{} bytes for a noisy tile", noisy.len());
    }

    #[test]
    fn tiles_cover_the_bitmap_row_by_row() {
        assert_eq!(
            tile_rects(130, 70),
            [
                (0, 0, 64, 64),
                (64, 0, 64, 64),
                (128, 0, 2, 64),
                (0, 64, 64, 6),
                (64, 64, 64, 6),
                (128, 64, 2, 6)
            ]
        );
    }
}
