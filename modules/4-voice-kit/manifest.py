"""4-VOICE KIT -- a rhythm machine on a FLEX track: a FLEX track whose sample
is named KIT4* plays four sample voices, the sample's first four slices (or
its four equal quarters when it has none), each struck by the trigs whose
STRT mask names it (1 = V1, 2 = V2, 4 = V3, 8 = V4, sums for several, 0 =
V1) and ringing to its slice's end while the others strike. The DSP shapes
the mix as a sample: PTCH/RATE tune the kit, AMP, filter, FX1/FX2, level
and pan act on the sum.

The SYNTH machine's method (modules/synth, timhastie/octatrick-modules): a
SymbolRef on the kind table's FLEX renderer entry 0x400d6438 points it at
kv_render in a DRAM unit, which calls the stock renderer and overwrites the
source pairs it shipped. The voices read the sample through the stock FLEX
fetch 0x40095bdc with a per-track shadow voice, so the arena's page
arithmetic stays stock's. kit.s's header has the layouts it relies on.

Mutually exclusive with SYNTH MACHINE: both claim 0x400d6438, and the
ledger refuses the pair by that address.

Measured under the port (verify_kit4, 27 Sep 2026): README.md.
"""

from remix.schema import Kind, Linked, Module, Proof, SymbolRef

KIND_TABLE_FLEX = 0x400d6438             # the kind table 0x400d6434, entry 1 (FLEX)
STOCK_RENDERER = 0x40004008              # the sample renderer (STATIC, FLEX, PICKUP)

MODULE = Module(
    name="4-voice-kit",
    key="4-VOICE KIT",
    kind=Kind.CF_PATCH,
    proof=Proof.PORT, proof_note="`verify_kit4`; nothing on hardware",
    doc="A FLEX track whose sample is named KIT4* plays four sample voices "
        "(its first four slices, or quarters), struck by the STRT mask "
        "(1/2/4/8, sums for several) and ringing over each other.",
    linked=(
        Linked("kit", "modules/4-voice-kit/kit.s", cpu="5475", dram=True),
    ),
    symbol_refs=(
        SymbolRef(KIND_TABLE_FLEX, STOCK_RENDERER, "kit", "kv_render",
                  "kind table FLEX renderer -> kv_render (KIT4*-named samples "
                  "play four slice voices)"),
    ),
)
