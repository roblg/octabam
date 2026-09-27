# 4-VOICE KIT

A rhythm machine on a FLEX track. A FLEX track whose sample is named
`KIT4*.wav` plays four sample voices, not the file, and they ring over
each other. `Kind.CF_PATCH`: one DRAM unit (`kit.s`, 1.8 KB) and one
`SymbolRef` on the kind table's FLEX renderer entry. No DSP code, no FX2
row, no page.

## Using it

1. Make a sample called `KIT4.wav` (or `KIT4-anything.wav`) holding four
   hits.
   - With slices (the audio editor's SLICE menu, or a `.ot`), slices 1–4
     are voices V1–V4. Slices past the fourth are ignored.
   - With no slices, the trim is cut into four equal quarters, so four
     equal-length hits laid end to end need no editing.
   - Fewer than four slices leave the missing voices silent.
2. Load it into a FLEX slot and assign the slot to a FLEX track.
3. Set **STRT** per trig to choose the voices it strikes. The value is a
   mask: 1 = V1, 2 = V2, 4 = V3, 8 = V4, and sums strike several (3 = V1 +
   V2, 15 = all four). 0, the default, strikes V1. Only the low four bits
   count.
4. Set **AMP ATK 0, HOLD INF (127)**. The track's AMP envelope restarts at
   every trig and shapes the whole mix, so a short HOLD cuts voices that
   are still ringing.

A struck voice restarts from its slice's start. The voices not struck keep
playing, so a hat does not cut the kick under it. Each voice plays its
slice to the end at unity gain; the four are summed and the sum saturates
at full scale.

Everything after the source stays the track's:
- PTCH and RATE tune the whole kit, because the DSP resamples the mix.
- The AMP envelope, filter, FX1/FX2, level, pan, LFOs and scenes act on
  the sum.
- LEN, RTRG and RTIM do nothing to the voices.
- On a stock OS the same project plays `KIT4.wav` as an ordinary sample.

**It cannot be in a remix with SYNTH MACHINE.** Both repoint the kind
table's FLEX entry `0x400d6438`, and the ledger refuses the pair by that
address. The remix that carries it is `kit4` (stock effects).

## How it works

This uses the SYNTH machine's method
([timhastie/octatrick-modules](https://github.com/timhastie/octatrick-modules)
`synth/synth.s`). The per-frame record packer renders every track through
the kind table `0x400d6434`, and its FLEX entry now points at `kv_render`.
`kv_render` does three things:

1. **It calls the stock FLEX renderer.** The voice lifecycle, the rate and
   the record headers stay stock's.
2. **It overwrites the source pairs that call just shipped** with the
   kit's mix. It walks the records from the cursor where the call started
   to where it stopped.
3. **It fetches the voices' audio through the stock FLEX fetch
   `0x40095bdc`.** Each track gets a *shadow* voice: the playing voice's
   slot (`+21`) and format (`+30`), loop off, forward, with the struck
   slice as its region (`+40..+63`). So the audio-page arithmetic, and the
   arena base that the DRAM platform moves, stay the stock routine's. All
   four sample formats are handled: 16/24-bit, mono/stereo.

The marker and the mask are read on a frame's second renderer call when
the voice-start bit (`0x46104d0c + track`, bit 4) is set. By then the start
handler has written the new voice. The first call of that frame renders
the old voices' tail, and the second call renders the struck voices from
the trig's sub-frame position. The mask is the STRT byte of the per-frame
parameter record (`0x800062a8`, `+2`), so step locks apply.

`kit.s`'s header lists every layout it relies on:
- the settings record: path at `+0`, trim at `+300`, slice `k` at
  `+312 + 12k`, count at `+1092`, read from the voice start
  `0x4000f6b8..0x4000f6da`;
- the fetch and its region helper `0x40001494`;
- the stock copy loop's format table `0x4000874e`.

`docs/firmware/COLDFIRE_PORT.md` gives the slice entry as
`+300 + 20·(slice+1)`, but the voice start computes `12·(slice+1)`
(`lsl #4` minus `lsl #2`).

## Measured

**Under the port (27 Sep 2026), `tools/verify/verify_kit4.py`**, which runs
in `make check REMIX=kit4` with `OT_PROJECT`:
- **Setup.** A generated `KIT4.wav` has four slices of unequal length,
  each a different signal, with L and R distinct. It sits on T1 at 300 BPM,
  with trigs on steps 1–5 locked to STRT 1, 2, 4, 8, 15.
- **Result.** T1's source stream, cut from the host-port block dump,
  equals a model built only from the slices, **sample for sample**:
  - 19,820 pairs with slices;
  - 17,088 pairs without slices, where the voices read the trim's
    quarters.
- **What the model covers.** Every voice starts on exactly the steps
  whose mask names it, and the earlier voices keep ringing underneath.
- **Controls.**
  - Striking all four voices on every step does not match the stream.
  - The same card on the `restock` image (no module) differs on every
    pair: T1 plays the file as one sample there.
- **ColdFire cost.** 27,584 instructions per 16-sample frame against
  26,165 on `restock` with the same card. That is about 1,400 more per
  frame, averaged over a run where one to four voices sound on one track.

## Open

- **Not run on a unit.** The unit runs from the arena reserve inside the
  audio interrupt, as SYNTH does, and SYNTH has run there (OCTATRICK9,
  26 Sep 2026).
- **The cost of eight kit tracks at four voices each is unmeasured.**
  Scaling the one-track figure gives roughly 11,000 extra instructions a
  frame (inferred).
- **No page yet.** STRT shows a number, not voice names. Per-voice level,
  tune and choke would need a PLAYBACK page clone, as SYNTH's `page.s`
  does.
- **A retriggered voice restarts hard, with no declick.** Stock does the
  same for a sample.
- **RTRG retrigs the stock stream, which the kit discards, not the
  voices.**
