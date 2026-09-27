# Ghidra: the MAIN OS and both DSP payloads, one project

```bash
make ghidra-install GHIDRA=~/ghidra_12.1.4_PUBLIC   # once: a copy with the processor modules below
make ghidra GHIDRA=out/ghidra/ghidra_12.1.4_PUBLIC-octabam [IMAGE=out/mainos_bus.bin]
python3 tools/ghidra/ot_ghidra.py import --ghidra DIR [--project DIR] [--only DSP_A,DSP_B] [--image [PATH]] [--no-analysis]
python3 tools/ghidra/ot_ghidra.py layout [--image [PATH]]  # the memory images + layout files only, no Ghidra
```

Needs `out/raw/section_3_MAIN_OS.bin` (`make os && make recon`) and a
JDK that your Ghidra accepts. The project is `out/ghidra/octatrack.gpr`. A
worktree under `.claude/` gets it in the temp directory instead, because
Ghidra refuses any path element that starts with `.`. Each program's
headless log is `out/ghidra/<program>.log`. `DEBUG=1` streams Ghidra's
output and lists every layout directive as it is applied.

| program | language | what is in it |
|---|---|---|
| `MAIN_OS` | `68000:BE:32:Coldfire_EMAC_frac`, else `68000:BE:32:Coldfire` | the image at `0x40000400`; the board map (`ARCHITECTURE.md` §7) as blocks, including `0x48000000`, the uncached view of SDRAM, as an empty block of its own (a byte-mapped copy doubled the analysis); the peripheral registers the docs read; the interrupt handlers (`KERNEL.md`); the DSP boot routines; the four DSP blobs marked as data; every stock address a module names with `.set`/`.equ` (the source file is in a repeatable comment) |
| `DSP_A`, `DSP_B` | `DSP56300:LE:24:default` | P/X/Y as the ColdFire uploads them (`dsp_modmap.py`), each load record's source address commented; internal memory to the default map's extents (P 8K, X 36K, Y 48K words, `CHIP.md` §3); the shared window `0x30000`–`0x3FFFF` with both bootstraps and payload A's shared records, X and Y mapped onto P there (they alias on the chip); the X/Y I/O registers; the vectors; both dispatch tables with every effect's init and process named (`DSP.md` §5); payload A's named routines |
| `REMIX` (with `--image`/`IMAGE=`) | as `MAIN_OS` | a built image (default `out/mainos_bus.bin`) under `MAIN_OS`'s layout; the bytes the build appends after the OS are one data block (`build_appended`), and each runtime in the loader's table is unpacked (`depack.py`) into its own block `DRAM_RUNTIME_n` at the address the loader copies it to, so a module's calls into stock (and the stock callers it detours) are in one listing |

Nothing from the image is committed. The tool reads your image, writes
`out/ghidra/load/`, and `OtLayout.java` applies the layout as
`analyzeHeadless`'s pre-script, so analysis starts from the right map.
`OtReport.java` prints each program's function, instruction and
error-bookmark counts. A layout file is plain text: add a finding to the
tables in `ot_ghidra.py` and re-import.

## The processor modules

Stock Ghidra has no DSP56300 and decodes the ColdFire's EMAC wrongly. Both
are here, in the form they are offered to Ghidra upstream (`roblg/ghidra`
#3 and #2):

| here | what it adds |
|---|---|
| `processors/DSP56300/` | the DSP56300 processor: P/X/Y word spaces, parallel moves, hardware loops, a loop-end analyzer; languages `DSP56300:LE:24:default` (linear AGU, what the import uses) and `DSP56300:LE:24:modulo` (every address update through the user op `agu_modulo`) |
| `patches/coldfire-emac.patch` | ColdFire ISA_C and EMAC decoding and semantics in `Ghidra/Processors/68000`, and the `68000:BE:32:Coldfire_EMAC_frac` variant (`MACSR` fractional, as this firmware runs it) |

`make ghidra-install GHIDRA=<stock install>` (`install.sh`) never touches
the stock install. It copies it to `out/ghidra/<name>-octabam`
(`GHIDRA_DEST=` to choose), applies the patch, adds the module without its
`build.gradle` (the distribution's `support/gradle` includes every
directory holding one, and the module's needs a source tree), compiles
both processors' SLEIGH with the release's own compiler and the loop-end
analyzer against the release's jars (`lib/DSP56300.jar`), and builds the
native decompiler with the release's gradle wrapper
(`support/gradle/gradlew buildNatives`) when the release has none for the
machine (the platform of the JDK's `java`, as Ghidra picks it, so an
x86_64 `bash` under Rosetta still gets `mac_arm_64`). The 12.1.4 release ships them for `linux_x86_64` and
`win_x86_64` only; without one no DSP function decompiles and MAIN_OS
drops to 2,147 functions / 181,378 instructions, two of the three callers
of `0x40054cd8` missing (measured without one in
sambanks/octabam#483). That build needs
a C++ toolchain (Xcode's command line tools on macOS) and the network for
gradle, and takes about two minutes. It needs a JDK 21+ (`JAVA_HOME`).
`DEBUG=1` streams every step; otherwise the output goes to
`<dest>.install.log`.

It is written against the 12.1.4 release, whose `68000.sinc` and
`68000.ldefs` are byte-identical to the patch's base; another version is
attempted only if the patch applies. With a stock Ghidra the MAIN OS still
imports, as `68000:BE:32:Coldfire`, and the DSP programs are skipped with a
message.

Not here: the decompiler printing `__Y(*p)` for a dereference outside the
default data space (`roblg/ghidra` #1, `decomp-space-qualifier`). It changes
the native decompiler, so it waits for upstream; without it X and Y reads
print as plain `*p`.

## What the import prints

With `make ghidra-install` on Ghidra 12.1.4 and OS 1.40C, each program
reports 0 layout warnings. The error bookmarks are flows into memory the
image does not hold:

| program | functions | instructions | error bookmarks |
|---|---|---|---|
| `MAIN_OS` | 2,176 | 191,064 | 9: calls into flash (`jsr 0x0000eae0`) and into `0x40000000`, below the image |
| `DSP_A` | 109 | 6,921 | 1: `P:0`'s `jmp $fff000`, the boot ROM |
| `DSP_B` | 102 | 6,377 | 1: the same |

Measured 26 Sep 2026, macOS arm64, Ghidra 12.1.4 (the release zip, the
decompiler built by `install.sh`). Every non-thunk function decompiles
(20 s timeout each): 107 in DSP_A, 100 in DSP_B, 2,171 in MAIN_OS. The same
programs on Ghidra 12.3-DEV with the `roblg/ghidra` branches merged
(26 Sep 2026): MAIN_OS 2,175 / 190,956 / 9, DSP_A 109 / 6,921 / 1, DSP_B
102 / 6,377 / 1.

`IMAGE=out/mainos_bus.bin` after `make check` (the shipping build,
`bamsep26` BUILD 79) adds `REMIX`: 2,228 functions, 192,175 instructions,
the same 9 error bookmarks as MAIN_OS, 0 layout warnings. Its one DRAM
runtime (2,612 bytes at `0x40a955e0`, where scenes-p2's detour at
`0x4000cf40` jumps) holds 18 functions / 497 instructions. The page-1
writer `0x40054cd8` has the three stock callers (`0x40062530`,
`0x400625aa`, `0x400a15f0`) and a fourth, `0x400d75d6`, in the ColdFire
cave the build fills (`0x400d6b00`..`0x400d7c3c`, `tools/remix/state.py`).

## `make lint-ghidra`: static checks on a built image

```bash
make bus && make lint-ghidra GHIDRA=out/ghidra/ghidra_12.1.4_PUBLIC-octabam
python3 tools/ghidra/ot_ghidra.py lint --ghidra DIR [--image out/mainos_bus.bin] [--project DIR]
```

The gate fails when no Ghidra is given, or when the Ghidra given has no DSP56300
module (`make ghidra-install` above makes one). The first run imports the stock project if it is missing, which takes a
few minutes. After that a run takes about 20 s.

The built image goes into the stock programs for one read-only headless run,
and nothing is saved. That includes each DRAM runtime, unpacked from the
image's appended payloads (`depack.py`). A finding prints as
`LINT <check> <key>: <what>`, and any finding not waived fails the gate.

| check | where | what it catches |
|---|---|---|
| `hook-boundary` | ColdFire | a patch whose last instruction falls through (a `jsr`'s return) ends inside a stock instruction |
| `branch-into-span` | ColdFire | stock code reaches an instruction a patch overwrote |
| `detour-target` | ColdFire | a hook, a call, or a flow out of new code lands inside an instruction, on nothing, or mid-routine in new code |
| `reg-liveness` | ColdFire | where a cave comes back to stock, a register or flag live there (stock liveness) differs from what the displaced instructions would have left. For a cave that returns for the hooked routine, it is compared with stock's own way out |
| `reg-contract` | DSP | a dispatch-table entry writes a register the dispatcher reads after its call. The contract comes from stock: live after the call, and written by no stock effect. `init` must keep r1 and m0 |
| `call-clobber` | DSP | the caller sets a register just before a `bsr`/`jsr`, the callee writes it without reading it first, and the caller reads it after |
| `do-loop-end` | DSP | a loop holding changed words ends on a change of flow or loop control, or its LA is not an instruction's last word |
| `wild-target` | DSP | a flow or dispatch entry goes to a word no record loads, or into a two-word instruction |
| `novel-form` | DSP | an encoding neither stock payload uses. The key is the tree of SLEIGH constructors that decoded it, each named by its display template, operands and length (not its line, which moves), with register choices collapsed. A parallel instruction's ALU op and its move are keyed separately: the chip decodes each from its own field |

`reg-liveness` follows the cave with a small symbolic interpreter over p-code.
- Stack slots are tracked, so a register that is saved and restored counts as
  preserved.
- Each callee is summarised by the same interpreter, falling back to the ABI:
  d0/d1/a0/a1 and the flags are scratch.
- Flags read wholesale into SR/CCR do not count as uses.
- X counts as used only by the extend arithmetic and the rotates.
- A callee's prologue saving d2-d7/a2-a6 does not count as using them.

### Waivers

A finding that is safe goes in `lint_waivers.py`, with the reason and the
evidence. A `reg-liveness` waiver names its registers (`regs="D6"`), so a new
clobber at the same site still fails. `DEBUG=1` lists each waiver applied and
each waiver the image did not need. upstream main (68af650, `bamsep26`)
needs these:

- **Four intentional outputs:**
  - rig-hosts' a0/a1 at `0x40005830`/`0x40005840`;
  - scenes-p2's d6 at `0x40037840`/`0x40037bdc`.

  Each is waived with the module's own statement.
- **11 DSP encoding parts with no stock precedent:** entered as **BASELINE,
  unreviewed**. Each needs hardware evidence, or a rewrite to a form stock
  uses. They include `div`/`andi`/`rep`, an `or` from a register, moves and a
  `lua` with a negative displacement (Character's deliberate `lua (r3-$2)`),
  and two Y parallel-move forms.

A waiver covers a part wherever it appears. The negative-displacement `lua`
waiver would also pass a wrapped `lua (r7+$46)`, which is the same encoding.
That incident is a read below the r7 instance block, and an r7 slot-bounds
check is the place to catch it.

### Replayed incidents

These are images of known failures (`docs/remixer/FAILURE_MODES.md`, the
history), rebuilt from their commits or reconstructed where the broken state
was never committed. Each was built with the assembler of its time. Measured
on Ghidra 12.1.4 with `make ghidra-install`; the same on 12.3-DEV with the
`roblg/ghidra` branches.

| incident | image | flagged |
|---|---|---|
| image 99: Spectrum `init` moves r1 | 8a40a31 | `reg-contract` X:0x219, both payloads |
| fs_rset clobbers x1 | 563d32c | `call-clobber` A P:0x147f, B P:0xfc0 |
| midisc bank_sw saves only d0 | d556acf | `reg-liveness` d3 at `0x40087d44` |
| midisc WRITE_HOOK: the continuation `0x40055390` lands inside `move.l #0x18b2` (midisc TECH.md) | d556acf | `detour-target` |
| V6: a detour into the middle of `save_stub` | reconstruction | `detour-target` `0x40009664` |
| a 6-byte `jmp` over `move.l; lea`, the cave back into it | reconstruction | `detour-target` `0x400d741a` |
| a `do` whose loop end resolved by label prefix | 59332e8 | `wild-target` + `do-loop-end` |
| `lua (r7+$46)` wrapped to `-$3a` | reconstruction | `novel-form` against stock; passed by main's baseline waiver (above) |
| the corrected V6; upstream main | 40a1f19; 68af650 | nothing unwaived |

Not caught:
- **Image 44's `move a,y:(r3+$1)`.** Stock uses the same encoding (payload A
  P:0xc73, `move b,y:(r4+$2)`), and image 45 wedged without it.
- **`max`/`rnd` from the old assembler.** Stock uses both encodings; the
  build's round-trip check covers them.
- **The `jsr` planted at P:0x57.** The loop's LA is 0x56.
- **Tcc flag and `asr` Z-flag cases.** They are about what the flags mean, not
  whether they survive.
- **Timing, cross-core and DMA failures.**

## Reading the DSP programs

- Addresses are words: `P:0x7d1` is word `0x7d1`. The DSP is little-endian,
  three bytes per word, as the payloads store it.
- `X:0x30000` is `P:0x30000` (byte-mapped). A write through Y shows up in
  P's listing at the same address, which is what the chip does.
- The DSP56300 names in the listing come from the DSP56362 register map,
  the same names `dsp56kDisassemble` prints. The DSP56720's ESAI and host
  port read correctly under them (`DSP.md` §6c); a register the docs have
  not read is unverified on this chip.
- The vectors are labelled `vec_XX` and not named. The DSP56720's vector
  map differs from the DSP56362's: the live vectors are `0x10`–`0x1c`, the
  host-port handlers (`DSP.md` §6c).
- `fx_null_init`/`fx_null_process` is the passthrough every unused id
  points at, DELAY (`0x08`) included: the stock DELAY runs on the ColdFire.
