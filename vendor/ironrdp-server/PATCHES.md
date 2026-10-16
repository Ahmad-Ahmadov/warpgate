Fork of `ironrdp-server` 0.13.0.

## RemoteFX header blocks lost to a buffer retry

`RemoteFxHandler` carries the desktop size as an `Option`, and `Some` is what makes
`RfxEncoder::encode` emit the once-per-connection RFX header blocks (`TS_RFX_SYNC`,
`TS_RFX_CONTEXT`, `TS_RFX_CHANNELS`, `TS_RFX_CODEC_VERSIONS`). Upstream `take()`s that
`Option` *inside* the loop that grows the output buffer on `NotEnoughBytes`, so a first
frame whose encoding overruns the buffer consumes the headers on the attempt that failed
and re-encodes without them. The buffer is sized from the frame's raw BGRA length, and RFX
always emits whole 64x64 tiles, so anything tile-padded — a few-pixel rect, or a thin strip
like a 1px window border — encodes larger than its source and takes that path. The headers
are never re-armed, so every later frame is rejected (FreeRDP: `rfx_process_message:
incomplete header blocks processing`) and the viewer stays black for the life of the
connection while input still works. Which frame arrives first is the target's choice, which
is why this strikes some deployments and not others; see warp-tech/warpgate#2606.

`warpgate.patch` reads the size without consuming it and clears it only once a message
carrying the headers has been built. It also drops a `* 2` from the adjacent buffer-resize
`debug!`, which reported twice the size actually allocated.

## Malformed access denial: mstsc "protocol error" 0xd06 on a rejected sign-in

With a `CredentialValidator` configured, `client_accepted` validates the viewer's
credentials once the connection is fully established, and on rejection `send_access_denied`
told the client why with a `ServerSetErrorInfoPdu(ServerDeniedConnection)`. Upstream encoded
that PDU on its own — the bare 4-byte `errorInfo` field (`07 00 00 00`) as the whole payload
of the Send Data Indication — without the Share Control and Share Data headers [MS-RDPBCGR]
2.2.5.1.1 requires. A client in the active phase reads the I/O channel as Share Control
PDUs, and those four bytes are neither one (`totalLength` 7 with 4 bytes present,
`pduType` 0) nor valid security-header framing (`flags` 0x0007 would claim a
security-exchange and multitransport packet). So the client cannot read the reason, and
reports a protocol error instead: mstsc shows "Because of a protocol error, this session will
be disconnected" with error code 0xd06, FreeRDP a transport error. The same bytes come from
upstream's acceptor, where a `FIXME` already doubts them; that path is only reached through
`ServerEvent::SetCredentials`, which Warpgate does not use, so it is left alone.

`warpgate.patch` frames the PDU the way the acceptor frames its connection-finalization Share
Data PDUs — which every client already accepts from this server — except that `pduSource` is
0, as the spec requires for this PDU. It then sends an MCS Disconnect Provider Ultimatum
(`rn-provider-initiated`), completing the server-initiated disconnection sequence of
[MS-RDPBCGR] 1.3.1.4.2, so the client ends the connection itself instead of only seeing the
transport close. The denial is still sent only after the validator has rejected, and the
connection is still closed afterwards; the error code is unchanged. Unit tests at the end of
`server.rs` parse the result with IronRDP's client-side decoder and check the spec fields on
the wire.

Getting the PDU right is not enough by itself: Warpgate tore down its byte relay as soon as
the server ended, discarding the denial before it reached the viewer. That half of the fix
is in `warpgate-protocol-rdp/src/server/mod.rs` (`relay`, `drive_session`).

`Cargo.toml` additionally sets `[lints.rust] warnings = { level = "allow", priority = 1 }`
so this vendored path dependency's warnings don't surface in Warpgate's builds. This is not
in `warpgate.patch` (which is source-only); re-apply it by hand on re-vendor.
