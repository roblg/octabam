#!/usr/bin/env python3
"""4-VOICE KIT under the ColdFire port: the source stream a KIT4 track ships
to the DSP is the four slice voices, struck by the STRT mask and summed.

    python3 tools/verify/verify_kit4.py [remix] --project <any project dir>
    OT_PROJECT=... make check REMIX=kit4        # the same, from make verify

A copy of the project (its .work files only; nothing of it is kept but the
file skeleton) gets a generated KIT4.wav in FLEX slot 1 -- four slices of
unequal length, each a different deterministic signal, L and R distinct --
with its trim and slices written into markers.work, and bank A pattern 1 is
cleared to one T1 FLEX track at PTCH 64 / RATE 127 / TSTR OFF, 300 BPM,
trigs on steps 1-5 locked to STRT 1, 2, 4, 8, 15 (V1, V2, V3, V4, all).
The port runs it; the per-frame records T1 ships to the DSP (the host-port
block dump) are cut into their source pairs and joined into T1's source
stream, which is then checked against a model built from the slices alone:

  strikes   each voice's onsets in the stream are the steps whose mask
            names it (V1 at steps 1 and 5, V2 at 2 and 5, ...), one step
            (2,205 samples at 300 BPM) apart
  mix       the stream equals the model sample for sample over the whole
            run: every struck voice from its slice's start, the voices
            ringing over each other, summed (16-bit sources are exact in
            the DSP's top 24 bits)

SKIPs without a project, the port (`make emu-cf`) or the .venv, or when
the remix does not carry 4-VOICE KIT. DEBUG=1 prints every step.
"""
import argparse, os, pathlib, re, shutil, struct, subprocess, sys, wave

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1])); import toolpath  # noqa: E402,F401
from remix import registry  # noqa: E402
import ot_project as otp  # noqa: E402
import ot_bank as ob  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
EMU = ROOT / "out/emu/ot_emu"
PY = ROOT / ".venv/bin/python3"
OUT = ROOT / "out/kit4verify"
DEBUG = bool(os.environ.get("DEBUG"))

KEY = "4-VOICE KIT"
RATE = 44100
BPM = 300
STEP = RATE * 60 // (BPM * 4)            # 2,205 samples: one 16th at 300 BPM
# The slices: unequal, so a quarters reading of the file is visibly wrong;
# every one longer than a step, so strikes overlap.
SLICES = ((0, 9000), (9000, 15000), (15000, 26000), (26000, 33075))
FRAMES = SLICES[-1][1]
MASKS = (1, 2, 4, 8, 15)                 # steps 1..5
AMP = 5000                               # per voice: five overlapping stay far from full scale


def log(*a):
    if DEBUG:
        print("   ", *a)


def voice_sample(v, n):
    """Voice v's frame n (from its slice's start): a decaying square-ish
    wave at a voice-specific period, L and R of different periods and
    signs, integers only so the model is exact."""
    period_l, period_r = (37, 53, 71, 97)[v], (41, 59, 67, 89)[v]
    env = max(0, 4096 - n * 4096 // 12000)
    sq = lambda p: 1 if (n % p) < p // 2 else -1
    return (AMP * env // 4096 * sq(period_l) + v * 100,
            -(AMP * env // 4096) * sq(period_r) - v * 100)


def make_sample(path):
    frames = [(0, 0)] * FRAMES
    for v, (s, e) in enumerate(SLICES):
        for n in range(e - s):
            frames[s + n] = voice_sample(v, n)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2); w.setsampwidth(2); w.setframerate(RATE)
        w.writeframes(b"".join(struct.pack("<hh", l, r) for l, r in frames))
    return frames


def set_project_text(dest):
    block = ("[SAMPLE]\r\nTYPE=FLEX\r\nSLOT=001\r\nPATH=../AUDIO/KIT4.wav"
             "\r\nTRIM_BARSx100=100\r\nLOOP_BARSx100=100\r\nBPMx24=2880"
             "\r\nTSMODE=0\r\nLOOPMODE=0\r\nGAIN=48"
             "\r\nTRIGQUANTIZATION=-1\r\n[/SAMPLE]\r\n\r\n").encode()
    for path in (dest / "project.work", dest / "project.strd"):
        if not path.exists():
            continue
        raw = path.read_bytes()
        raw = re.sub(rb"\[SAMPLE\]\r?\nTYPE=FLEX\r?\nSLOT=001\r?\n.*?\[/SAMPLE\]\r?\n\r?\n",
                     b"", raw, flags=re.S)
        at = raw.find(b"[SAMPLE]")
        if at < 0:
            sys.exit(f"verify_kit4: {path} has no sample section")
        raw = raw[:at] + block + raw[at:]
        for key in (b"BANK", b"PATTERN", b"TRACK"):
            raw, k = re.subn(rb"(\r?\n)" + key + rb"=\d+",
                             lambda m: m.group(1) + key + b"=0", raw, count=1)
            if k != 1:
                sys.exit(f"verify_kit4: {path} has no {key.decode()} key")
        raw = raw.replace(b"MASTER_TRACK=1", b"MASTER_TRACK=0")
        path.write_bytes(raw)
    otp.set_tempo(dest, BPM)


def set_markers(dest, slices):
    """FLEX slot 1's 784-byte record: trim start/end/loop, 64 slices of
    start/end/loop, the slice count (ot_project's layout, the markers
    parser 0x40086396). No slices: the kit reads quarters of the trim."""
    rec = struct.pack(">III", 0, FRAMES, 0)
    for s, e in slices:
        rec += struct.pack(">III", s, e, 0)
    rec += bytes(12 * (64 - len(slices))) + struct.pack(">I", len(slices))
    assert len(rec) == 784
    for path in (dest / "markers.work", dest / "markers.strd"):
        if not path.exists():
            continue
        data = bytearray(path.read_bytes())
        data[0x16:0x16 + 784] = rec
        data[-2:] = (sum(data[0x10:-2]) & 0xFFFF).to_bytes(2, "big")
        path.write_bytes(data)


def mutate_bank(data):
    ob.check_tags(data)
    for part in range(otp.NPARTS_ALL):
        base = otp.PART_BASE + part * otp.PART_STRIDE
        data[base + otp.MTYPE_OFF] = 1                # T1 FLEX
        data[base + 0x2d3 + 1] = 0                    # FLEX slot 1
        setup = base + 0x1e3 + 6                      # T1's FLEX SETUP
        data[setup] = 0                               # LOOP off
        data[setup + 4] = 0                           # TSTR off
        values = base + 0x033 + 6                     # T1's FLEX PLAYBACK
        data[values] = 64                             # PTCH 0
        data[values + 1] = 0                          # STRT
        data[values + 3] = 127                        # RATE 1.0
    tail = ob.PTRN_BASE + ob.PTRN_STRIDE - 5          # pattern 1 -> part 1
    data[tail] = 0
    for track in range(8):
        off = otp.trac_off(0, track)
        data[off:off + 64] = bytes(64)                # every trig mask
        data[off + 0x59:off + 0x59 + 64 * 32] = b"\xff" * (64 * 32)   # no locks
    off = otp.trac_off(0, 0)
    for step, mask in enumerate(MASKS):
        data[off + 7 - step // 8] |= 1 << (step % 8)
        rec = off + 0x59 + step * 32
        data[rec + 0] = 64                            # PTCH
        data[rec + 1] = mask                          # STRT: the voices
    for pat in range(16):                             # 16 steps at 1X
        tail = ob.PTRN_BASE + pat * ob.PTRN_STRIDE + ob.PTRN_STRIDE - 11
        data[tail + 2] = 16; data[tail + 3] = 2


def build_project(src, dest, slices):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for f in src.iterdir():
        if f.is_file() and f.suffix in (".work", ".strd"):
            shutil.copy2(f, dest / f.name)
    set_project_text(dest)
    set_markers(dest, slices)
    otp._bank_write(dest, 1, mutate_bank, guard=False)
    otp.write_stored(dest)


def model(frames, regions, onsets, n):
    """The stream the kit should ship: every strike of voice v at stream
    position p plays its region of the file from the start; the four
    summed. onsets: [(position, mask)]."""
    out = [[0, 0] for _ in range(n)]
    for v, (s, e) in enumerate(regions):
        starts = [p for p, m in onsets if m & (1 << v)]
        for i, p in enumerate(starts):
            stop = min(n, starts[i + 1] if i + 1 < len(starts) else n, p + e - s)
            for k in range(p, stop):
                l, r = frames[s + k - p]
                out[k][0] += l; out[k][1] += r
    return out


def run_port(a, image, proj):
    """Stage the project and KIT4.wav onto a card, boot the image, play."""
    card, dump, text = OUT / "card.img", OUT / "port.dump", OUT / "port.txt"
    wav = OUT / "KIT4.wav"
    frames = make_sample(wav)
    cmd = [str(PY), str(ROOT / "tools/emu/ot_emu/stage_card.py"), str(proj), a.set_name, a.name,
           "--tree", str(OUT / "tree"), "--out", str(card), "--image-mb", "64",
           "--audio", f"{wav}:AUDIO/KIT4.wav"]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"verify_kit4: stage_card failed:\n{r.stdout[-1000:]}{r.stderr[-1000:]}")
    cmd = [str(EMU), "--image", str(image), "--card", str(card), "--set", a.set_name,
           "--project", a.name, "--sequencer", "--internal-clock", "--frames", str(a.frames),
           "--load-ms", str(a.load_ms), "--dsp", "--block-dump", str(dump)]
    log(" ".join(cmd))
    with open(text, "w") as f:
        f.write(" ".join(cmd) + "\n"); f.flush()
        r = subprocess.run(cmd, cwd=ROOT, stdout=f, stderr=subprocess.STDOUT)
    if r.returncode:
        sys.exit(f"verify_kit4: ot_emu exit {r.returncode} -- {text}")
    return frames, dump, text.read_text()


def t1_stream(dump):
    """T1's source stream: every frame's two records (the packer's two
    renderer calls), their pairs in order, as (L, R) of the DSP's top
    16 bits. T1-T4's records reach core 1 as one host-port block per
    ping (0x80001c90 + ping * 0xa80, 336 bytes a track); T1's is first.
    Returns the stream and every pair's low bits (zero for 16-bit sources
    at unity)."""
    import blockdump
    blocks = sorted((frame, w) for d, frame, ch, core, ram, w in blockdump.read(str(dump))
                    if d == ">" and core == 1 and ram in (0x80001c90, 0x80002710))
    out, low = [], 0
    for _frame, w in blocks:
        long_ = lambda i: w[2 * i] << 16 | w[2 * i + 1]
        at = 0                                     # in longs
        for _call in range(2):
            n = long_(at) & 0xff
            for k in range(n):
                l, r = long_(at + 4 + 2 * k), long_(at + 5 + 2 * k)
                low |= (l | r) & 0xffff
                sgn = lambda x: (x >> 16) - 65536 if x >> 31 else x >> 16
                out.append((sgn(l), sgn(r)))
            at += 4 + 2 * n
    return out, low


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("remix", nargs="?", default="kit4")
    ap.add_argument("--project", default=os.environ.get("OT_PROJECT", ""))
    ap.add_argument("--frames", type=int, default=1400)
    ap.add_argument("--load-ms", type=int, default=20000)
    ap.add_argument("--set-name", default="OCTABAM")
    ap.add_argument("--name", default="KIT")
    ap.add_argument("--image", default="", help="a built image instead of building the remix")
    a = ap.parse_args()

    if KEY not in registry.remix(a.remix).modules:
        print(f"  [SKIP] verify_kit4: {a.remix} does not carry {KEY}")
        return 0
    if not a.project:
        print("  [SKIP] verify_kit4: no project (OT_PROJECT=<dir> or --project)")
        return 0
    src = pathlib.Path(a.project).expanduser()
    if not (src / "project.work").is_file() or not (src / "bank01.work").is_file():
        sys.exit(f"verify_kit4: {src} is not an Octatrack project directory with bank01.work")
    if not EMU.exists():
        print("  [SKIP] verify_kit4: the ColdFire port is not built (make emu-cf)")
        return 0
    if not PY.exists():
        print("  [SKIP] verify_kit4: no .venv (make emu-setup)")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    image = OUT / "image.bin"
    if a.image:
        shutil.copy2(a.image, image)
    else:
        env = dict(os.environ, REMIX=a.remix, XBUS="1", SPEC="1"); env.setdefault("BUILD", "0")
        r = subprocess.run([sys.executable, str(ROOT / "tools/build/build_bus.py")], env=env,
                           capture_output=True, text=True, cwd=ROOT)
        if r.returncode:
            sys.exit(f"verify_kit4: building {a.remix} failed:\n{(r.stdout + r.stderr)[-1500:]}")
        shutil.copy2(ROOT / "out/mainos_bus.bin", image)
    fails = 0
    def check(label, ok, detail=""):
        nonlocal fails
        fails += 0 if ok else 1
        print(f"  [{'ok' if ok else 'FAIL'}] {label}{'  ' + detail if detail else ''}")

    q = FRAMES // 4
    layouts = (("slices", SLICES, SLICES),
               ("no slices", (), tuple((v * q, v * q + q) for v in range(4))))
    for what, slices, regions in layouts:
        print(f"  -- {what}: the voices read {', '.join(f'{s}..{e}' for s, e in regions)}")
        proj = OUT / "project"
        build_project(src, proj, slices)
        frames, dump, text = run_port(a, image, proj)
        ran = re.search(r"frames run : (\d+) since transport start \(target (\d+)\), run ended (\w+)", text)
        check("load: LOAD PROJECT completed and the frames ran",
              "LOAD PROJECT posted: yes" in text and ran is not None and ran.group(3) == "REACHED",
              f"frames {ran.group(1)}/{ran.group(2)} {ran.group(3)}" if ran else "no frames line")
        cpu = re.search(r"\((\d+) per frame of 16 samples\)", text)
        log(f"ColdFire instructions per frame: {cpu.group(1) if cpu else '?'}")
        stream, low = t1_stream(dump)
        first = next((i for i, x in enumerate(stream) if x != (0, 0)), None)
        need = (len(MASKS) - 1) * STEP + max(e - s for s, e in regions)
        check("stream: T1 ships audio", first is not None and len(stream) - first >= need,
              f"{len(stream)} source pairs, the first non-zero at {first}" if first is not None
              else f"{len(stream)} source pairs, all silent")
        if first is None or len(stream) - first < need:
            continue
        check("stream: every pair's low 16 bits are zero (16-bit sources at unity)", low == 0,
              f"OR of the low halves {low:#06x}")
        onsets = [(k * STEP, m) for k, m in enumerate(MASKS)]
        body = stream[first:first + need]
        want = model(frames, regions, onsets, need)
        diff = [i for i in range(need) if body[i] != tuple(want[i])]
        for v in range(4):
            log(f"V{v + 1} strikes on steps {[k + 1 for k, m in enumerate(MASKS) if m & (1 << v)]}")
        check(f"mix: the stream == the model, {need} pairs from the first strike "
              f"(strikes {STEP} apart, masks {'/'.join(map(str, MASKS))})",
              not diff, "" if not diff else
              f"{len(diff)} differ, the first at +{diff[0]} (step {diff[0] // STEP + 1}): "
              f"got {body[diff[0]]} want {tuple(want[diff[0]])}")
        # the model must discriminate: every voice on every step is another stream
        wrong = model(frames, regions, [(p, 15) for p, _ in onsets], need)
        check("control: all four voices on every step does NOT match",
              any(body[i] != tuple(wrong[i]) for i in range(need)))
    print(f"  verify_kit4: {'PASS' if not fails else f'{fails} FAIL'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
