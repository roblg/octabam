# Remixes

A remix is a named selection of modules; `make image REMIX=<name>` builds it into a card-flashable image from your own OS 1.40C. [BUILDING.md](BUILDING.md) is the step-by-step guide. Each remix is a directory, `remixes/<name>/`: `remix.py` is the selection and `README.md` says what is in it and where it has run. This index is rendered from the selections (`make docs`).

## The rig

| remix | contains | proof |
|---|---|---|
| [`bamsep26`](../../remixes/bamsep26/README.md) | The rig: bus (BusVerb on T5 + BusDelay on T1) + three stations. | on hardware: Sam's MKII, image 43 (OCTABAM43, 21 Sep 2026) |
| [`bottleservice`](../../remixes/bottleservice/README.md) | The rig + USB MIDI + USB AUDIO + Octakit. | port-gated: `make check` with the stress project; Kit save, reload and copy measured |
| [`rig-kits`](../../remixes/rig-kits/README.md) | The rig + Octakit. | `make check` |
| [`rig-mods`](../../remixes/rig-mods/README.md) | The rig + MIDI SCENES + Octakit, bridged. | `make check` |
| [`rig-scenes`](../../remixes/rig-scenes/README.md) | The rig + MIDI SCENES. | `make check` |
| [`usb`](../../remixes/usb/README.md) | bamsep26 + USB MIDI (class-compliant, mirrors DIN). | `make check` |
| [`usb-audio`](../../remixes/usb-audio/README.md) | usb + USB AUDIO: the tracks, MAIN and CUE over USB (UAC2, 20 channels). | on hardware: Sam's MKII, image 64, 25 Sep 2026 |

## Effects

| remix | contains | proof |
|---|---|---|
| [`bus`](../../remixes/bus/README.md) | The plain two-server image: BusVerb + BusDelay + send bus + tempo sync. | on hardware: under earlier names |
| [`euclid`](../../remixes/euclid/README.md) | Euclid rhythmic modulation: 12 dB LP/BP/HP or AMP, both FX slots. | local render: the module's render gates |
| [`miniverb`](../../remixes/miniverb/README.md) | Minimal allocator-owned FDN reverb. | local render: `make verify-miniverb` |
| [`tapeecho`](../../remixes/tapeecho/README.md) | Tape Echo replacing Spring Reverb, alone. | on hardware: the author's unit (OCTACLID4): six instances; a seventh freezes it, open |

## Firmware mods on the stock effects

| remix | contains | proof |
|---|---|---|
| [`kit4`](../../remixes/kit4/README.md) | 4-VOICE KIT on the stock effects. | port-gated: `verify_kit4` |
| [`kits`](../../remixes/kits/README.md) | All the firmware mods of the Octakit family, no effects: 256 Kits, the LO-FI AMF fix, CC to page 2. | port-gated |
| [`lofi-amf-fix`](../../remixes/lofi-amf-fix/README.md) | Reference minimal build: the LO-FI AMF mpysu->mpyuu fix, alone. | `make check` |
| [`midi-scenes`](../../remixes/midi-scenes/README.md) | Reference minimal build: the MIDI SCENES ColdFire patch, alone. | `make check`: on hardware inside `ok-ms` |
| [`mods`](../../remixes/mods/README.md) | MIDI SCENES + Octakit + the LO-FI AMF fix + CC to page 2, bridged, on the stock effects. | port-gated |
| [`octakit`](../../remixes/octakit/README.md) | Em's Octakit alone -- must reproduce her own build byte for byte. | `make check`: on hardware inside `ok-ms` |
| [`octatrick`](../../remixes/octatrick/README.md) | SYNTH MACHINE + SCALE QUANTIZER + DIRECT JUMP on the stock effects. | `make check` |
| [`octatrick-usb`](../../remixes/octatrick-usb/README.md) | SYNTH MACHINE + SCALE QUANTIZER + DIRECT JUMP + USB MIDI + USB AUDIO on the stock effects. | on hardware: Tim's MKI, 26 Sep 2026 (OCTATRICK9), USB audio on all 20 channels |
| [`ok-ms`](../../remixes/ok-ms/README.md) | Octakit + MIDI SCENES on the stock effects: the two mods alone. | on hardware: midisc's author's unit, 14 Sep 2026 (OKMS2) |
| [`recfix`](../../remixes/recfix/README.md) | The recorder loop click: the four ColdFire fixes beside the stock FX2 chooser, no DSP code of our own. | on hardware: with the bus, 12 Sep 2026 (OCTABAM83); RECORDER HOLD and RLEN PLEN port-gated |
| [`repitch`](../../remixes/repitch/README.md) | stock effects with variable-speed REPITCH in the TSTR selector. | on hardware: repeat98's MKII, 16 Sep 2026 (OCTABAM81) |
| [`scenes`](../../remixes/scenes/README.md) | All the firmware mods of the MIDI SCENES family, no effects: scenes over MIDI, the LO-FI AMF fix, CC to page 2. | port-gated |
| [`usb-lean`](../../remixes/usb-lean/README.md) | stock + USB MIDI + USB AUDIO (20 ch: tracks, MAIN, CUE). | port-gated |

## Reference

| remix | contains | proof |
|---|---|---|
| [`restock`](../../remixes/restock/README.md) | every stock FX2 effect, all fourteen: put my unit back. | `make check` |

Never share a built image: it contains Elektron's OS.
