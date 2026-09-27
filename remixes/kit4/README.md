# `kit4` — the 4-VOICE KIT rhythm machine

One ColdFire module and the stock effects. For anyone who wants four drum sounds on one track, each ringing under the next, instead of one sample per track.

## What is in it

- **4-VOICE KIT**: a FLEX track whose sample is named `KIT4*.wav` plays its first four slices as four voices (or the four quarters of its trim when it has no slices).
  - STRT on each trig is a mask of the voices it strikes: 1, 2, 4, 8, and sums for several (0 = V1).
  - A struck voice restarts; the others keep ringing.
  - The track's PTCH, AMP, filter and FX act on the mix.
  - Set AMP ATK 0 / HOLD INF so a trig does not cut the voices still ringing.
  - The details are in `modules/4-voice-kit/README.md`.
- The 14 stock FX2 effects, listed so the chooser is stock's.

SYNTH MACHINE cannot join this remix: both modules repoint the kind table's FLEX renderer.

## Status

Measured under the ColdFire port (`tools/verify/verify_kit4.py`, 27 Sep 2026): a KIT4 track's source stream equals its slice voices, struck by the STRT mask and summed, sample for sample. **Not yet run on a unit.**

## Build

```bash
OT_PROJECT=<any project> make check REMIX=kit4    # every gate, verify_kit4 included
make image REMIX=kit4 BUILD=1                      # -> out/OCTATRACK_OCTABAM1.bin
```

[BUILDING.md](../../docs/remixes/BUILDING.md) is the walk-through from a fresh machine to a flashed unit.
