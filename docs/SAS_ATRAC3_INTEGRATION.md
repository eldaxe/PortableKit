# PSP SAS ATRAC3 integration plan

Target: God Eater Burst (ULUS10563). This document records the source-level
integration boundary discovered while auditing PortableKit's current
`god-eater-burst` branch. It deliberately does not add success-only handlers.

## Existing components

- `host/audio/atrac_decoder.hpp/.cpp`: FFmpeg-backed frame decoder for ATRAC3
  and ATRAC3plus. `AtracDecoder::open()` requires codec, channel count,
  encoded frame size, and (for ATRAC3) the 14-byte codec extradata.
- `host/hle/hle_atrac.cpp`: tracks and streaming state are private
  `AtracContext` objects. Each owns an `AtracDecoder`, parsed track metadata,
  cached decoded frames, and a copied streaming byte window.
- `host/audio/sas_core.hpp/.cpp`: each `SasVoice` currently has VAG, PCM, or
  noise source state. `advance_source()` is the single source-sample boundary
  used by the SAS interpolation/mixer.

## Required PSP behavior

PPSSPP's `SceAtracContext` is 256 bytes: a 128-byte codec state followed by
128-byte `SceAtracIdInfo`. Relevant info offsets relative to the full 256-byte context (the 128-byte codec state precedes `SceAtracIdInfo`):

| Field | Full context offset |
|---|---:|
| `numChan` | 151 |
| `sampleSize` | 152 |
| `codec` | 154 |
| `fileDataEnd` | 164 |
| `streamDataByte` | 172 |
| `buffer` | 184 |
| `secondBuffer` | 188 |
| `bufferByte` | 192 |
| `secondBufferByte` | 196 |

The codec field is `0x1001` for ATRAC3 and `0x1000` for ATRAC3plus.
`secondBuffer == 0xFFFFFFFF` is the streaming handshake indicating that SAS
can accept another buffer. It is not a normal host pointer.

The import `_sceAtracGetContextAddress` (NID `0x231FC6B7`) is also absent
from the current ATRAC HLE. It must be implemented as part of the context
bridge; otherwise the game cannot obtain the guest context it passes to
`__sceSasSetVoiceATRAC3`.

## Correct integration design

1. Add a stable ATRAC stream object shared by the ATRAC HLE and SAS layer.
   The object must own the decoder and stream cursor; do not duplicate the
   FFmpeg decoder in a second independent map.
2. Give each stream a guest-visible, 256-byte context allocation and mirror
   the hardware-visible fields. The host object remains authoritative for
   FFmpeg state; guest fields remain authoritative for game-controlled
   buffer pointers/sizes and the documented SAS handshake.
3. Implement `_sceAtracGetContextAddress` to return that context pointer for
   the requested ATRAC ID, with the correct invalid-ID behavior.
4. `__sceSasSetVoiceATRAC3(core, voice, context)` must validate the context,
   associate it with the voice, write the context pointer at
   `core + 56 * voice + 20`, and start the SAS source in ATRAC mode.
5. `__sceSasConcatenateATRAC3(core, voice, data, size)` must enqueue a
   second buffer only when the context says it is ready. The handoff must
   update both the guest-visible context and the host stream cursor.
6. `__sceSasUnsetATRAC3(core, voice)` must detach the context, stop the voice,
   clear the guest core pointer and reset pause/source state.
7. The SAS mixer must request ATRAC decoded frames from the shared stream,
   then resample/mix them through the existing pitch, volume, and envelope
   path. Do not route ATRAC through the VAG ADPCM decoder.
8. Handle end-of-stream and decode failures explicitly. Do not turn a decoder
   error into an infinite stream of silent successful frames.

## Why a standalone HLE extension is insufficient

The public HLE extension interface can register missing imports, but it cannot
reach the private `AtracContext` table in `hle_atrac.cpp`, nor can it add a
new source type to `SasVoice`. An extension-only implementation would need a
new stable PortableKit interface for obtaining and advancing an ATRAC stream.
Until that interface exists, the implementation belongs in PortableKit core,
on this feature branch, with Sekhmet only pinning the resulting commit.

## Verification required

- Build PortableKit host tests and Sekhmet Android arm64 target.
- Unit-test the context offsets and invalid pointer/voice/ID cases.
- Test a complete in-memory ATRAC3 stream, then a two-buffer streamed track.
- Verify that `secondBuffer` changes to `0xFFFFFFFF` only when SAS requests
  another buffer, and to zero at end-of-stream.
- Verify key-on, key-off, unset, loop, pitch, envelope, and end flags.
- Run God Eater Burst with `TRACE_ATRAC` and `TRACE_AUDIO`; compare actual
  calls and audible output. Import presence alone is not a runtime test.

Reference behavior: PPSSPP `Core/HLE/sceSas.cpp`, `AtracBase.h`,
`AtracCtx2.h/.cpp`, and `sceAtrac.cpp`. These are behavioral references;
do not copy their GPL implementation into PortableKit without a deliberate
licensing decision.

## Implementation status on feature branch

The branch now contains a first end-to-end source bridge:

- `_sceAtracGetContextAddress` allocates and returns a 256-byte guest block
  for a loaded ATRAC ID. The host `AtracContext` remains the sole owner of
  the FFmpeg decoder and stream cursor.
- The guest `SceAtracIdInfo` fields are mirrored at their 128-byte-offset
  positions. The status becomes `ATRAC_STATUS_FOR_SCESAS` (16) while bound
  to a SAS voice and returns to the normal full/halfway/streamed state on
  unset.
- `__sceSasSetVoiceATRAC3` validates the context, installs a callback-backed
  SAS source, and stores the context pointer at `core + 56 * voice + 20`.
- The SAS mixer obtains decoded ATRAC samples through the existing
  `AtracDecoder`; it does not feed ATRAC bytes into the VAG ADPCM decoder.
  The source is downmixed to mono before the existing SAS pan/volume stage.
- `__sceSasConcatenateATRAC3` appends guest-supplied bytes to the same host
  stream. When the SAS reader reaches unavailable streamed data while more
  file bytes remain, the guest context's `secondBuffer` is set to
  `0xFFFFFFFF`; a successful concatenate clears that request. Unset clears
  the SAS core pointer and restores the ATRAC context's non-SAS state.

### Important limitations and verification

This is still an initial integration, not a claim of hardware-complete
ATRAC streaming. The stream bridge currently appends into the host's retained
stream data; it does not model every PSP double-buffer/ring transition or
all second-buffer timing rules. Decode failures and temporary stream
underruns still need more detailed classification. The 128-byte codec-state
half of the guest context is reserved/zeroed; FFmpeg state remains private to
the host and is not serialized into that area.

No local build or runtime test has been performed in this environment. The
container cannot resolve GitHub, so the source could not be cloned for a
local CMake build. CI must confirm that all changed C++ signatures compile.
Required runtime tests remain: a complete ATRAC3 track, a streamed track with
at least one concatenate, loop boundaries, voice key-on/key-off, unset and
end flags, and audible output in God Eater Burst. Do not treat registration
or a passing compile as proof of game compatibility.

Reference behavior was checked against PPSSPP's public source for the
256-byte `SceAtracContext`, the three SAS ATRAC function signatures, the
context pointer location in the SAS core, and the mono SAS handoff. PPSSPP is
used as a behavioral reference only; its GPL implementation was not copied.
