#!/usr/bin/env python3
"""The per-remix half of `make check` for several remixes, N worktrees at a time.

    python3 tools/verify/check_shards.py [--jobs N] [--keep] [--shards DIR] <remix> ...
    make check-remixes REMIXES="a b c" [JOBS=4]
    make reach RUN=1 JOBS=4            # the check-remix lines through this

Every `make check-remix` builds over out/mainos_bus.bin and its verifiers
read out/, so one tree runs one remix at a time; PR #486's 25-remix table
was three worktrees driven by hand. This makes N detached worktrees of HEAD
plus the tree's uncommitted changes under out/shards/<i>, each with the
shared vendor/ and .venv/ links, the stock slice, its submodules and its
OWN port build (out/emu is never shared between trees: AGENTS.md), then
hands the remixes out from one queue as shards come free, so the dear ones
(bottleservice, rig-kits) do not decide the wall time. Logs land in
out/check_shards/<remix>.log; one table at the end; exit 1 when a remix
failed. The shards are removed unless --keep.
"""
import argparse
import os
import pathlib
import queue
import re
import shutil
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
SKIP = re.compile(r"^\s*(?:\[SKIP\]|SKIP:)")


def git(*args, cwd=ROOT, check=True):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=check)


def make_shard(path, log):
    """A detached worktree of HEAD with this tree's uncommitted changes, the
    shared toolchain links, the stock slice, its submodules and its own
    port build."""
    remove_shard(path)
    git("worktree", "add", "--detach", str(path), "HEAD")
    diff = subprocess.run(["git", "diff", "HEAD", "--binary", "--ignore-submodules=all"],
                          cwd=ROOT, capture_output=True, check=True).stdout
    if diff.strip():
        subprocess.run(["git", "apply", "--binary"], cwd=path, input=diff, check=True)
    for rel in git("ls-files", "--others", "--exclude-standard", "-z").stdout.split("\0"):
        if rel and (ROOT / rel).is_file():
            (path / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, path / rel)
    for name in ("vendor", ".venv"):
        if (ROOT / name).exists():
            os.symlink(os.path.realpath(ROOT / name), path / name)
    (path / "out/raw").mkdir(parents=True)
    shutil.copy2(ROOT / "out/raw/section_3_MAIN_OS.bin", path / "out/raw/section_3_MAIN_OS.bin")
    with log.open("w") as f:
        for cmd in (["git", "submodule", "update", "--init"], ["make", "emu-cf"]):
            f.write(f"$ {' '.join(cmd)}\n")
            f.flush()
            r = subprocess.run(cmd, cwd=path, stdout=f, stderr=subprocess.STDOUT, env=clean_env())
            if r.returncode:
                raise SystemExit(f"check_shards: {' '.join(cmd)} failed in {path} ({r.returncode}): {log}")


def remove_shard(path):
    if path.exists():
        git("worktree", "remove", "--force", str(path), check=False)
        shutil.rmtree(path, ignore_errors=True)
    git("worktree", "prune", check=False)


def clean_env():
    env = dict(os.environ)
    for var in ("MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES"):
        env.pop(var, None)
    return env


def run_remix(shard, remix, logdir):
    log = logdir / f"{remix}.log"
    t0 = time.monotonic()
    with log.open("w") as f:
        r = subprocess.run(["make", "check-remix", f"REMIX={remix}"], cwd=shard,
                           stdout=f, stderr=subprocess.STDOUT, env=clean_env())
    text = log.read_text(errors="replace")
    skips = [l.strip() for l in text.splitlines() if SKIP.match(l)]
    return dict(remix=remix, rc=r.returncode, seconds=time.monotonic() - t0, skips=skips, log=log)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("remixes", nargs="+")
    ap.add_argument("--jobs", type=int, default=4, help="worktrees at a time")
    ap.add_argument("--shards", type=pathlib.Path, default=ROOT / "out/shards")
    ap.add_argument("--keep", action="store_true", help="leave the shard worktrees for a look")
    a = ap.parse_args(argv)
    remixes = list(dict.fromkeys(a.remixes))
    if not (ROOT / "out/raw/section_3_MAIN_OS.bin").is_file():
        sys.exit("check_shards: out/raw/section_3_MAIN_OS.bin is missing (make os && make recon)")
    jobs = max(1, min(a.jobs, len(remixes)))
    a.shards.mkdir(parents=True, exist_ok=True)
    logdir = ROOT / "out/check_shards"
    logdir.mkdir(parents=True, exist_ok=True)
    shards = [a.shards / str(i) for i in range(jobs)]

    print(f"check_shards: {len(remixes)} remixes over {jobs} shards under {a.shards} (setup: submodules + make emu-cf each)", flush=True)
    errors = []

    def setup(i):
        try:
            make_shard(shards[i], a.shards / f"{i}.setup.log")
        except (SystemExit, subprocess.CalledProcessError, OSError) as exc:
            errors.append(str(exc))
    threads = [threading.Thread(target=setup, args=(i,)) for i in range(jobs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        sys.exit("check_shards: " + "; ".join(errors))

    todo = queue.Queue()
    for r in remixes:
        todo.put(r)
    results = {}
    lock = threading.Lock()

    def worker(i):
        while True:
            try:
                remix = todo.get_nowait()
            except queue.Empty:
                return
            res = run_remix(shards[i], remix, logdir)
            res["shard"] = i
            status = "ok" if res["rc"] == 0 else f"FAILED ({res['rc']})"
            with lock:
                results[remix] = res
                print(f"check_shards: {status:12} {res['seconds']:6.0f} s  {remix:16} shard {i}"
                      + (f"  {len(res['skips'])} SKIP" if res["skips"] else ""), flush=True)
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(jobs)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.monotonic() - t0

    print(f"\ncheck_shards: results ({wall:.0f} s wall, {sum(r['seconds'] for r in results.values()):.0f} s of remix time)")
    for remix in remixes:
        r = results[remix]
        status = "ok" if r["rc"] == 0 else f"FAILED ({r['rc']})"
        print(f"  {status:12} {r['seconds']:6.0f} s  {remix:16} {r['log'].relative_to(ROOT)}")
        for s in r["skips"]:
            print(f"               {s}")
    if not a.keep:
        for s in shards:
            remove_shard(s)
    bad = [r for r in results.values() if r["rc"]]
    if bad:
        print(f"check_shards: {len(bad)} of {len(results)} remixes failed")
        return 1
    print("check_shards: every remix passed its per-remix half")
    return 0


if __name__ == "__main__":
    sys.exit(main())
