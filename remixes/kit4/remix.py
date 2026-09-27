"""kit4 -- the 4-VOICE KIT rhythm machine on the stock effects.

A FLEX track whose sample is named KIT4*.wav plays four slice voices
(modules/4-voice-kit). The fourteen stock effects are listed with fallback
NONE, as in repitch and octatrick, so both DSP payloads, their dispatch and
the chooser stay stock. SYNTH MACHINE cannot join it: both modules claim
the kind table's FLEX entry.
"""

from remix.schema import Proof, Remix

REMIX = Remix(
    name="kit4",
    family="mods", proof=Proof.PORT, proof_note="`verify_kit4`",
    doc="4-VOICE KIT on the stock effects.",
    modules=("4-VOICE KIT", "FILTER", "EQUALIZER", "DJ EQ", "PHASER", "FLANGER",
             "CHORUS", "SPATIALIZER", "COMB FILTER", "COMPRESSOR", "LO-FI",
             "DELAY", "PLATE REV", "SPRING REV", "DARK REV"),
    fallback="NONE",
)
