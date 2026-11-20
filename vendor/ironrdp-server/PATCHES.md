Snapshot of `ironrdp-server` from IronRDP master at `1f4dee6b` (2026-10-27, "fix(server):
size the display for non-resizing clients before input", #2261), version `0.14.0`.

## Why a git snapshot

IronRDP published the rest of its crates on 2026-10-27/28 (`ironrdp-pdu` 0.11,
`ironrdp-connector` 0.12, `ironrdp-session` 0.13, `ironrdp-egfx` 0.5, ...) but not
`ironrdp-server`, whose last release (0.13.0) only builds against the previous generation.
`1f4dee6b` is the latest server commit whose dependencies are all those published
releases: the commits after it (#2232, #2272, #2293, #2107, ...) rely on changes to
`ironrdp-acceptor`, `ironrdp-error` and `ironrdp-dvc` that have no release yet.

Re-vendor from a published `ironrdp-server` 0.14+ once one exists.

## RemoteFX header blocks lost to a buffer retry

`RemoteFxHandler` carries the desktop size as an `Option`, and `Some` is what makes
`RfxEncoder::encode` emit the once-per-connection RFX header blocks (`TS_RFX_SYNC`,
`TS_RFX_CONTEXT`, `TS_RFX_CHANNELS`, `TS_RFX_CODEC_VERSIONS`). The snapshot `take()`s that
`Option` *inside* the loop that grows the output buffer on `NotEnoughBytes`, so a first
frame whose encoding overruns the buffer consumes the headers on the attempt that failed
and re-encodes without them. The buffer is sized from the frame's raw BGRA length, and RFX
always emits whole 64x64 tiles, so anything tile-padded — a few-pixel rect, or a thin strip
like a 1px window border — encodes larger than its source and takes that path. The headers
are never re-armed, so every later frame is rejected (FreeRDP: `rfx_process_message:
incomplete header blocks processing`) and the viewer stays black for the life of the
connection while input still works; see warp-tech/warpgate#2606.

`warpgate.patch` reads the size without consuming it, so every message carries the headers
(the `.take()` removed in its `encoder/mod.rs` hunk). Upstream fixed the same bug
differently in #2274 (take before the loop, buffer reused), which is past the snapshot.

## A faster RemoteFX tile coder

Every 64x64 tile of every frame goes through `ironrdp_graphics::rfx_encode_component` three
times (Y, Cb, Cr). Two of its four steps dominate: the forward DWT's vertical pass walks the
tile a column at a time, with a bounds check and a branch per sample, and RLGR writes each
code through a `bitvec` range `fill`/`store_be`, several per coefficient.
`src/encoder/rfx_component.rs` replaces both and keeps IronRDP's quantization and sub-band
reconstruction. The vertical pass works on whole rows, which the compiler vectorises. The
RLGR coder packs bits in a 64-bit accumulator and writes whole bytes. The arithmetic and the
output are the same, byte for byte, and its tests compare the DWT, the RLGR coder (both
modes, including the too-small-buffer error) and the whole component against IronRDP's on
flat, gradient, edge, noise and sparse inputs and the i16 extremes. Run them with
`cargo test -p ironrdp-server --lib rfx_component` (the crate sets `test = false`, so they
only run when the library is named).

## Default and hidden pointers that were never sent

`UpdateFragmenter` (`src/encoder/fast_path.rs`) ended as soon as no payload was left, before
writing anything, so an update without a payload produced no PDU. The default pointer and the
hidden pointer are exactly those (MS-RDPBCGR 2.2.9.1.2.1.5 and 2.2.9.1.2.1.6), so a client
never heard of either, and kept showing the last pointer shape it had been sent. In Warpgate
that was the text cursor after the pointer left a text field, whenever the target's next
pointer was its system default one (or one Warpgate falls back to the default for). The patch
takes upstream's later fix: an empty update is sent as one empty `Single` fragment.

## Pointer shapes a client cannot take

Upstream drops an `RGBAPointer` or `LargePointer` that the client's negotiated pointer
capabilities do not cover, which leaves the client on the shape before it. `pointer_shape`
in `src/encoder/mod.rs` sends either kind as a New Pointer Update if the client takes one that
size, as a Large Pointer Update if the client takes those, and as the default pointer
otherwise, so a target's large cursors (a scaled display, a larger pointer size) are shown
where the client allows and never leave a stale shape where it does not.

## RemoteFX output buffer

`RemoteFxHandler` sized its output buffer from the bitmap's own length and, when RemoteFX
needed more, doubled it and encoded every tile again. Tiles are padded to 64x64, so small
and thin updates (a caret, a one-pixel border) routinely needed more and were encoded two or
three times over. The buffer now starts at the most a message can take
(`rfx_message_size_bound`): 19 bytes plus three 4096-byte components per tile, which is all
`rfx::UpdateEncoder` gives a tile, and a kilobyte for the other blocks. For a whole desktop
that is less than the bitmap's length.

The pointer and RemoteFX tests are in `src/encoder/mod.rs` (`pointer_tests`) and
`src/encoder/fast_path.rs`: `cargo test -p ironrdp-server --lib encoder`.

## Manifest

`Cargo.toml` is the snapshot's with the `*.workspace = true` package fields inlined, the
`path = "../..."` dependency entries removed (every dependency resolves to its crates.io
release), `[lints] workspace = true` replaced by `warnings = { level = "allow", priority = 1 }`
under `[lints.rust]`, and `zstd-safe = "8.2"` (upstream pins `7.2`; the streaming API the
code uses is unchanged). `LICENSE-*` are copies: in the IronRDP repository they are
symlinks to the workspace root. None of this is in `warpgate.patch` (source-only).
