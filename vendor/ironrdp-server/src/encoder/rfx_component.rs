//! Encoding of one 64x64 RemoteFX tile component: forward DWT, quantization, sub-band
//! reconstruction and RLGR entropy coding ([MS-RDPRFX] 3.1.8.1).
//!
//! A Warpgate replacement for `ironrdp_graphics::rfx_encode_component`, which every tile of
//! every frame goes through three times. It produces the same bytes (the tests below compare
//! the two on many inputs) with the same arithmetic, arranged for speed:
//!
//! - The vertical DWT pass walks whole rows rather than one column at a time, so each step
//!   is the same operation over contiguous memory, which the compiler vectorises.
//! - RLGR output goes through a 64-bit bit accumulator that writes whole bytes, rather than
//!   a `bitvec` range fill or store per code, which was its main cost.
//!
//! Quantization and sub-band reconstruction are IronRDP's own.
//!
//! [MS-RDPRFX]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdprfx/62495a4a-a495-46ea-b459-5cde04c44549

use core::cmp::min;

use ironrdp_graphics::rlgr::RlgrError;
use ironrdp_graphics::{quantization, subband_reconstruction};
use ironrdp_pdu::codecs::rfx::{EntropyAlgorithm, Quant};

const TILE_PIXELS: usize = 64 * 64;

/// Where the LL3 sub-band starts once the DWT has run, as `rfx_encode_component` has it.
const LL3_START: usize = 4032;

/// Encode one component of a tile into `output`, returning the number of bytes written.
/// `input` is consumed as scratch space, and `temp` is scratch space of the same size.
pub(crate) fn encode_component(
    input: &mut [i16; TILE_PIXELS],
    temp: &mut [i16; TILE_PIXELS],
    output: &mut [u8],
    quant: &Quant,
    mode: EntropyAlgorithm,
) -> Result<usize, RlgrError> {
    dwt_encode(input, temp);
    quantization::encode(input, quant);
    subband_reconstruction::encode(&mut input[LL3_START..]);
    rlgr_encode(mode, input, output)
}

// --- Forward DWT ---------------------------------------------------------------------------

/// The three-level forward DWT, sub-bands laid out as `ironrdp_graphics::dwt::encode` lays
/// them out: HL1, LH1, HH1, then the second and third levels in place of LL1 and LL2.
fn dwt_encode(buffer: &mut [i16; TILE_PIXELS], temp: &mut [i16; TILE_PIXELS]) {
    dwt_level::<32>(&mut buffer[..], &mut temp[..]);
    dwt_level::<16>(&mut buffer[3072..], &mut temp[..]);
    dwt_level::<8>(&mut buffer[3840..], &mut temp[..]);
}

/// One level of the DWT over the `2 * SW` by `2 * SW` block at the start of `buffer`.
fn dwt_level<const SW: usize>(buffer: &mut [i16], temp: &mut [i16]) {
    let width = SW * 2;

    // Vertical: each pair of rows becomes a row of L (the top half of `temp`) and a row of
    // H (its bottom half).
    {
        let src = &buffer[..width * width];
        let (low, high) = temp[..width * width].split_at_mut(SW * width);
        for n in 0..SW {
            let even = row(src, width, 2 * n);
            let odd = row(src, width, 2 * n + 1);
            // The last pair mirrors at the edge.
            let next = if n < SW - 1 { row(src, width, 2 * n + 2) } else { even };

            let (high_done, high_rest) = high.split_at_mut(n * width);
            let h = &mut high_rest[..width];
            for (((h, &e), &o), &x) in h.iter_mut().zip(even).zip(odd).zip(next) {
                *h = high_pass(e, o, x);
            }

            let l = &mut low[n * width..(n + 1) * width];
            if n == 0 {
                for ((l, &e), &h) in l.iter_mut().zip(even).zip(&*h) {
                    *l = low_pass_first(e, h);
                }
            } else {
                let h_prev = &high_done[(n - 1) * width..];
                for (((l, &e), &hp), &h) in l.iter_mut().zip(even).zip(h_prev).zip(&*h) {
                    *l = low_pass(e, hp, h);
                }
            }
        }
    }

    // Horizontal: each row of L becomes a row of HL and LL, each row of H a row of HH and
    // LH, stored as four consecutive `SW` by `SW` sub-bands.
    let (hl, rest) = buffer.split_at_mut(SW * SW);
    let (lh, rest) = rest.split_at_mut(SW * SW);
    let (hh, ll) = rest.split_at_mut(SW * SW);
    let (low, high) = temp[..width * width].split_at(SW * width);
    for r in 0..SW {
        let out = r * SW..(r + 1) * SW;
        let l_row = row(low, width, r);
        let h_row = row(high, width, r);
        horizontal(l_row, &mut hl[out.clone()], &mut ll[out.clone()]);
        horizontal(h_row, &mut hh[out.clone()], &mut lh[out]);
    }
}

fn row(block: &[i16], width: usize, y: usize) -> &[i16] {
    &block[y * width..(y + 1) * width]
}

/// One row of the horizontal pass: the odd samples' high-pass into `high`, then the even
/// samples' low-pass, which reads it, into `low`.
fn horizontal(src: &[i16], high: &mut [i16], low: &mut [i16]) {
    let (pairs, _) = src.as_chunks::<2>();
    for (n, (h, &[even, odd])) in high.iter_mut().zip(pairs).enumerate() {
        // The last pair mirrors at the edge.
        let next = src.get(2 * n + 2).copied().unwrap_or(even);
        *h = high_pass(even, odd, next);
    }

    let mut lows = low.iter_mut().zip(pairs).zip(high.iter());
    if let Some(((l, &[even, _]), &h)) = lows.next() {
        *l = low_pass_first(even, h);
    }
    for (((l, &[even, _]), &h), &h_prev) in lows.zip(high.iter()) {
        *l = low_pass(even, h_prev, h);
    }
}

// As in `ironrdp_graphics::dwt`, computed in i32 and truncated to i16.

#[inline(always)]
fn high_pass(even: i16, odd: i16, next: i16) -> i16 {
    ((i32::from(odd) - ((i32::from(even) + i32::from(next)) >> 1)) >> 1) as i16
}

#[inline(always)]
fn low_pass_first(even: i16, h: i16) -> i16 {
    (i32::from(even) + i32::from(h)) as i16
}

#[inline(always)]
fn low_pass(even: i16, h_prev: i16, h: i16) -> i16 {
    (i32::from(even) + ((i32::from(h_prev) + i32::from(h)) >> 1)) as i16
}

// --- RLGR ----------------------------------------------------------------------------------

const KP_MAX: u32 = 80;
const LS_GR: u32 = 3;
const UP_GR: u32 = 4;
const DN_GR: u32 = 6;
const UQ_GR: u32 = 3;
const DQ_GR: u32 = 3;

/// RLGR-encode `input` into `output`: the bytes `ironrdp_graphics::rlgr::encode` leaves in
/// a zeroed `output`, whatever `output` held before.
fn rlgr_encode(mode: EntropyAlgorithm, input: &[i16], output: &mut [u8]) -> Result<usize, RlgrError> {
    if input.is_empty() {
        return Err(RlgrError::EmptyTile);
    }

    let mut k: u32 = 1;
    let kr: u32 = 1;
    let mut kp: u32 = k << LS_GR;
    let mut krp: u32 = kr << LS_GR;
    let mut bits = BitWriter::new(output);
    let mut input = input.iter().copied();

    while let Some(first) = input.next() {
        if k != 0 {
            // Run-length mode: a run of zeros, then the value that ended it.
            let mut val = first;
            let mut nz: u32 = 0;
            // A run reaching the end of the input has no value after it, and none is coded:
            // this mode codes the magnitude minus one, so it cannot express a zero.
            let mut run_to_end = false;
            while val == 0 {
                nz += 1;
                match input.next() {
                    Some(next) => val = next,
                    None => {
                        run_to_end = true;
                        break;
                    }
                }
            }

            let mut runmax: u32 = 1 << k;
            while nz >= runmax {
                bits.put(1, 0);
                nz -= runmax;
                kp = min(kp + UP_GR, KP_MAX);
                k = kp >> LS_GR;
                runmax = 1 << k;
            }
            bits.put(1, 1);
            bits.put(k, nz);

            if !run_to_end {
                let mag = u32::from(val.unsigned_abs());
                bits.put(1, u32::from(val < 0));
                code_gr(&mut bits, &mut krp, mag - 1);
            }

            kp = kp.saturating_sub(DN_GR);
            k = kp >> LS_GR;
        } else {
            // Golomb-Rice mode.
            match mode {
                EntropyAlgorithm::Rlgr1 => {
                    let two_ms = get_2magsign(first);
                    code_gr(&mut bits, &mut krp, two_ms);
                    if two_ms == 0 {
                        kp = min(kp + UQ_GR, KP_MAX);
                    } else {
                        kp = kp.saturating_sub(DQ_GR);
                    }
                    k = kp >> LS_GR;
                }
                EntropyAlgorithm::Rlgr3 => {
                    let two_ms1 = get_2magsign(first);
                    let two_ms2 = input.next().map_or(0, get_2magsign);
                    let sum2ms = two_ms1 + two_ms2;
                    code_gr(&mut bits, &mut krp, sum2ms);

                    let m = 32 - sum2ms.leading_zeros();
                    if m != 0 {
                        bits.put(m, two_ms1);
                    }

                    if two_ms1 != 0 && two_ms2 != 0 {
                        kp = kp.saturating_sub(2 * DQ_GR);
                        k = kp >> LS_GR;
                    } else if two_ms1 == 0 && two_ms2 == 0 {
                        kp = min(kp + 2 * UQ_GR, KP_MAX);
                        k = kp >> LS_GR;
                    }
                }
            }
        }
    }

    bits.finish()
}

fn get_2magsign(val: i16) -> u32 {
    u32::from(val.unsigned_abs()) * 2 - u32::from(val < 0)
}

fn code_gr(bits: &mut BitWriter<'_>, krp: &mut u32, val: u32) {
    let kr = *krp >> LS_GR;

    let vk = val >> kr;
    bits.put_ones(vk);
    bits.put(1, 0);

    if kr != 0 {
        bits.put(kr, val & ((1 << kr) - 1));
    }

    if vk == 0 {
        *krp = krp.saturating_sub(2);
    } else if vk > 1 {
        *krp = min(*krp + vk, KP_MAX);
    }
}

/// Writes bits most significant first, a whole byte at a time.
struct BitWriter<'a> {
    output: &'a mut [u8],
    /// Bytes completed, including any that did not fit in `output`.
    len: usize,
    /// The bits not yet written are the low `pending` bits.
    acc: u64,
    /// Fewer than 8 between calls.
    pending: u32,
}

impl<'a> BitWriter<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            len: 0,
            acc: 0,
            pending: 0,
        }
    }

    /// Write the low `count` bits of `value`, `count` being at most 32.
    #[inline(always)]
    fn put(&mut self, count: u32, value: u32) {
        debug_assert!(count <= 32);
        self.acc = (self.acc << count) | (u64::from(value) & ((1u64 << count) - 1));
        self.pending += count;
        while self.pending >= 8 {
            self.pending -= 8;
            self.push((self.acc >> self.pending) as u8);
        }
    }

    fn put_ones(&mut self, mut count: u32) {
        while count >= 32 {
            self.put(32, u32::MAX);
            count -= 32;
        }
        self.put(count, u32::MAX);
    }

    #[inline(always)]
    fn push(&mut self, byte: u8) {
        // Past the end, keep counting, so the error can say how much the tile needed.
        if let Some(slot) = self.output.get_mut(self.len) {
            *slot = byte;
        }
        self.len += 1;
    }

    /// Pad the last byte with zeros, and return the encoded length.
    fn finish(mut self) -> Result<usize, RlgrError> {
        if self.pending > 0 {
            let byte = (self.acc << (8 - self.pending)) as u8;
            self.push(byte);
        }
        if self.len > self.output.len() {
            return Err(RlgrError::OutputTooSmall {
                needed: self.len,
                available: self.output.len(),
            });
        }
        Ok(self.len)
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_graphics::{dwt, rfx_encode_component, rlgr};

    use super::*;

    /// A small deterministic generator, so a failure reproduces.
    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// A value in `-range..range`.
        fn sample(&mut self, range: i32) -> i16 {
            let span = (2 * range) as u64;
            ((self.next() % span) as i32 - range) as i16
        }
    }

    /// Component inputs covering what tiles look like and what they could be: flat,
    /// gradients, edges, noise of several amplitudes, sparse spikes, and the extremes.
    fn inputs() -> Vec<[i16; TILE_PIXELS]> {
        let mut rng = Xorshift(0x2545_f491_4f6c_dd1d);
        let mut inputs = vec![[0; TILE_PIXELS], [i16::MAX; TILE_PIXELS], [i16::MIN; TILE_PIXELS]];

        let mut gradient = [0; TILE_PIXELS];
        for (i, v) in gradient.iter_mut().enumerate() {
            *v = ((i % 64) * 64 + i / 64) as i16 - 2048;
        }
        inputs.push(gradient);

        let mut edges = [0; TILE_PIXELS];
        for (i, v) in edges.iter_mut().enumerate() {
            *v = if (i % 64) / 8 % 2 == (i / 64) / 8 % 2 {
                4000
            } else {
                -4000
            };
        }
        inputs.push(edges);

        for range in [1, 4, 64, 1024, 4096, 32768] {
            for _ in 0..8 {
                let mut noise = [0; TILE_PIXELS];
                for v in &mut noise {
                    *v = rng.sample(range);
                }
                inputs.push(noise);
            }
        }

        for _ in 0..8 {
            let mut sparse = [0; TILE_PIXELS];
            for _ in 0..40 {
                let at = (rng.next() % TILE_PIXELS as u64) as usize;
                sparse[at] = rng.sample(32768);
            }
            inputs.push(sparse);
        }
        inputs
    }

    #[test]
    fn the_dwt_matches_ironrdp() {
        for input in inputs() {
            let (mut ours, mut theirs) = (input, input);
            dwt_encode(&mut ours, &mut [0; TILE_PIXELS]);
            dwt::encode(&mut theirs, &mut [0; TILE_PIXELS]);
            assert!(ours == theirs, "DWT differs for input starting {:?}", &input[..8]);
        }
    }

    #[test]
    fn rlgr_matches_ironrdp() {
        // Small values code compactly, large ones exercise long unary prefixes, and the
        // DWT's quantized output is what the encoder actually feeds it.
        let mut cases: Vec<Vec<i16>> = inputs().iter().map(|input| input.to_vec()).collect();
        for input in inputs() {
            let mut quantized = input;
            dwt::encode(&mut quantized, &mut [0; TILE_PIXELS]);
            quantization::encode(&mut quantized, &Quant::default());
            cases.push(quantized.to_vec());
        }
        cases.push(vec![0]);
        cases.push(vec![-1]);
        cases.push(vec![0, 0, 0, 5]);
        cases.push(vec![7, 0, 0, 0]);

        for mode in [EntropyAlgorithm::Rlgr1, EntropyAlgorithm::Rlgr3] {
            for input in &cases {
                // Room for the worst case: up to 18 bits a value, and the unary prefixes.
                let capacity = input.len() * 16 + 64 * 1024;
                let mut ours = vec![0u8; capacity];
                let mut theirs = vec![0u8; capacity];
                let ours_len = rlgr_encode(mode, input, &mut ours).unwrap();
                let theirs_len = rlgr::encode(mode, input, &mut theirs).unwrap();
                assert_eq!(
                    ours_len,
                    theirs_len,
                    "{mode:?} length differs for {:?}",
                    &input[..input.len().min(8)]
                );
                assert!(
                    ours == theirs,
                    "{mode:?} bytes differ for {:?}",
                    &input[..input.len().min(8)]
                );
            }
        }
    }

    #[test]
    fn too_small_an_output_is_reported_as_ironrdp_reports_it() {
        let mut rng = Xorshift(7);
        let input: Vec<i16> = (0..TILE_PIXELS).map(|_| rng.sample(32768)).collect();
        for mode in [EntropyAlgorithm::Rlgr1, EntropyAlgorithm::Rlgr3] {
            let ours = rlgr_encode(mode, &input, &mut [0; 100]);
            let theirs = rlgr::encode(mode, &input, &mut [0; 100]);
            match (ours, theirs) {
                (
                    Err(RlgrError::OutputTooSmall { needed, available }),
                    Err(RlgrError::OutputTooSmall {
                        needed: their_needed,
                        available: their_available,
                    }),
                ) => {
                    assert_eq!(needed, their_needed);
                    assert_eq!(available, their_available);
                }
                other => panic!("{mode:?}: unexpected {other:?}"),
            }
        }
        assert!(matches!(
            rlgr_encode(EntropyAlgorithm::Rlgr1, &[], &mut [0; 8]),
            Err(RlgrError::EmptyTile)
        ));
    }

    #[test]
    fn a_whole_component_matches_ironrdp() {
        let finest = Quant::default();
        let coarse = Quant {
            ll3: 8,
            lh3: 9,
            hl3: 9,
            hh3: 10,
            lh2: 10,
            hl2: 10,
            hh2: 11,
            lh1: 11,
            hl1: 11,
            hh1: 12,
        };
        for quant in [&finest, &coarse] {
            for mode in [EntropyAlgorithm::Rlgr1, EntropyAlgorithm::Rlgr3] {
                for input in inputs() {
                    // As the encoder sizes it.
                    let mut ours = [0u8; 4096];
                    let mut theirs = [0u8; 4096];
                    let ours_len = encode_component(&mut input.clone(), &mut [0; TILE_PIXELS], &mut ours, quant, mode);
                    let theirs_len = rfx_encode_component(&mut input.clone(), &mut theirs, quant, mode);
                    match (ours_len, theirs_len) {
                        (Ok(ours_len), Ok(theirs_len)) => {
                            assert_eq!(ours_len, theirs_len);
                            assert!(ours[..ours_len] == theirs[..theirs_len], "{mode:?} bytes differ");
                        }
                        (Err(_), Err(_)) => {}
                        other => panic!("{mode:?}: one failed, the other did not: {other:?}"),
                    }
                }
            }
        }
    }
}
