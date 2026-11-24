#!/usr/bin/env -S uv run --locked
"""
Non-kernel user-space profiler for preflate container compression.

Uses valgrind --tool=callgrind (pure CPU-instruction simulation; no kernel
privileges, perf events, or kernel modules required).

What it does:
  1. Builds preflate_util in release mode (debug symbols already on by default
     via [profile.release] debug = true in Cargo.toml).
  2. Runs the binary under callgrind against a sample directory.
  3. Runs callgrind_annotate to aggregate per-function costs.
  4. Prints a ranked hotspot table (self instruction count) and a per-crate
     breakdown.

Usage:
    uv run --locked corpus/profile_container.py [options]

Options:
    --input  DIR    input files to compress (default: samples/)
    --top    N      hottest functions to display (default: 40)
    --output FILE   where to save the raw callgrind data
                    (default: /tmp/callgrind_preflate.out)
    --no-build      skip cargo build (use existing binary)
    --keep          keep the callgrind output file after finishing
    --filter STR    only show functions whose name/path contains STR
                    (e.g. --filter preflate  or  --filter lepton)

Requirements:
    uv (manages the project Python environment)
    valgrind   (sudo apt install valgrind)
    cargo + Rust 1.89+
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

# ---------------------------------------------------------------------------
# ANSI colour helpers (auto-disabled when stdout is not a tty)
# ---------------------------------------------------------------------------

def _tty(code: str) -> str:
    return code if sys.stdout.isatty() else ""

BOLD  = _tty("\033[1m")
RESET = _tty("\033[0m")
DIM   = _tty("\033[2m")
RED   = _tty("\033[31m")
GRN   = _tty("\033[32m")
YEL   = _tty("\033[33m")
CYN   = _tty("\033[36m")
MAG   = _tty("\033[35m")

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

def _require(tool: str, hint: str = "") -> None:
    if not shutil.which(tool):
        print(f"ERROR: '{tool}' not found on PATH.")
        if hint:
            print(f"       {hint}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_binary(root: Path) -> Path:
    print(f"{BOLD}==> cargo build --release -p preflate_util{RESET}")
    r = subprocess.run(["cargo", "build", "--release", "-p", "preflate_util"], cwd=root)
    if r.returncode != 0:
        sys.exit("Build failed.")
    binary = root / "target" / "release" / "preflate_util"
    if not binary.exists():
        sys.exit(f"Binary not found: {binary}")
    print(f"  binary: {binary}")
    return binary


# ---------------------------------------------------------------------------
# Run callgrind
# ---------------------------------------------------------------------------

def run_callgrind(binary: Path, input_dir: Path, out_file: Path) -> None:
    cmd = [
        "valgrind",
        "--tool=callgrind",
        f"--callgrind-out-file={out_file}",
        str(binary),
        str(input_dir),
    ]
    print()
    print(f"{BOLD}==> Running callgrind (user-space only — no kernel privs needed){RESET}")
    print("  Simulates every CPU instruction: expect 20-50× slowdown.")
    print(f"  Input : {input_dir}")
    print(f"  Output: {out_file}")
    print()
    r = subprocess.run(cmd)
    # preflate_util exits 0 on success; any non-zero is unexpected
    if r.returncode not in (0,):
        print(f"  Warning: preflate_util exited with code {r.returncode}")


# ---------------------------------------------------------------------------
# Parse callgrind_annotate output
# ---------------------------------------------------------------------------

class Func(NamedTuple):
    ir: int          # self instruction count
    pct: float       # % of program total
    name: str        # demangled, shortened function name
    src: str         # source file (best effort)
    crate: str       # top-level crate / library


# callgrind_annotate --auto=no --tree=none produces single-column Ir output.
# Function lines look like:
#   819,083,903 ( 8.15%)  preflate/src/hash_chain_holder.rs:SomeName [/path/binary]
#   316,389,238 ( 3.15%)  ./string/.../memset-vec-unaligned-erms.S:__memset_... [/usr/lib/...]
_FUNC_RE = re.compile(
    r"^\s*([\d,]+)"             # instruction count (comma-separated)
    r"\s*\(\s*(\d+\.\d+)%\)"   # percentage in parens
    r"\s+"
    r"(.+)$"                    # rest: location:func  [binary]
)

_TOTAL_RE = re.compile(r"^\s*([\d,]+)\s*\(100\.0%\)\s+PROGRAM TOTALS")


def _strip_int(s: str) -> int:
    return int(s.replace(",", ""))


def _shorten(name: str) -> str:
    """Remove hash suffixes and collapse deep generic parameters."""
    name = re.sub(r"::h[0-9a-f]{15,}$", "", name)
    name = re.sub(r"::h[0-9a-f]{15,}::", "::", name)
    # Collapse anything beyond the first level of < >
    out, depth = [], 0
    for ch in name:
        if ch == "<":
            depth += 1
            if depth == 2:
                out.append("<…>")
            elif depth == 1:
                out.append(ch)
        elif ch == ">":
            if depth == 1:
                out.append(ch)
            depth = max(0, depth - 1)
        elif depth < 2:
            out.append(ch)
    return "".join(out)


def _crate_from_path(location: str, name: str) -> str:
    """Infer the owning crate/library from the source location or function name."""
    # registry path: .../crates.io-.../CRATE-VERSION/...
    m = re.search(r"index\.crates\.io-[^/]+/([a-zA-Z0-9_-]+)-[\d.]+/", location)
    if m:
        return m.group(1).replace("-", "_")
    # workspace src: preflate/src/... or container/src/...
    m = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)/src/", location)
    if m:
        return m.group(1)
    # rustc stdlib
    if "/rustc/" in location or location.startswith("/rustc/"):
        seg = re.search(r"library/(core|std|alloc|proc_macro)", location)
        return seg.group(1) if seg else "rust_stdlib"
    # glibc / system
    if location.startswith("./") or "/usr/lib/" in location:
        return "[system]"
    # fall back to first segment of the Rust function path
    m = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)(::|$)", name)
    if m:
        return m.group(1)
    return "?"


def parse_annotate(out_file: Path, top_n: int,
                   filter_str: str | None) -> tuple[int, list[Func]]:
    cmd = ["callgrind_annotate", "--auto=no", "--tree=none", str(out_file)]
    try:
        raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError as e:
        sys.exit(f"callgrind_annotate failed: {e}")

    total_ir = 0
    funcs: list[Func] = []

    for line in raw.splitlines():
        mt = _TOTAL_RE.match(line)
        if mt:
            total_ir = _strip_int(mt.group(1))
            continue

        m = _FUNC_RE.match(line)
        if not m:
            continue

        ir  = _strip_int(m.group(1))
        pct = float(m.group(2))
        rest = m.group(3).strip()

        # Strip trailing [/path/to/binary]
        rest = re.sub(r"\s+\[[^\]]+\]$", "", rest).strip()

        # Split location:funcname  (the colon separates file from function)
        colon = rest.find(":")
        if colon != -1:
            location = rest[:colon]
            raw_name = rest[colon + 1:]
        else:
            location = "?"
            raw_name = rest

        # Skip the PROGRAM TOTALS pseudo-line
        if "PROGRAM TOTALS" in raw_name:
            continue

        name  = _shorten(raw_name)
        crate = _crate_from_path(location, raw_name)
        src   = location.split("/")[-1] if "/" in location else location

        funcs.append(Func(ir=ir, pct=pct, name=name, src=src, crate=crate))

    # Sort by self cost descending (callgrind_annotate already does this, but be safe)
    funcs.sort(key=lambda f: f.ir, reverse=True)

    if filter_str:
        funcs = [f for f in funcs
                 if filter_str in f.name or filter_str in f.src or filter_str in f.crate]

    return total_ir, funcs[:top_n]


# ---------------------------------------------------------------------------
# Colour assignment
# ---------------------------------------------------------------------------

_CRATE_COLOR = {
    "preflate":     GRN,
    "preflate_rs":  GRN,
    "container":    GRN,
    "preflate_container": GRN,
    "lepton_jpeg":  CYN,
    "zstd":         YEL,
    "zstd_sys":     YEL,
    "libwebp_sys":  MAG,
    "core":         DIM,
    "std":          DIM,
    "alloc":        DIM,
    "rust_stdlib":  DIM,
    "[system]":     DIM,
}


def _color(crate: str) -> str:
    for prefix, col in _CRATE_COLOR.items():
        if crate.startswith(prefix):
            return col
    return ""


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(total_ir: int, funcs: list[Func]) -> None:
    W_N   = 4
    W_IR  = 16
    W_PCT = 7
    W_SRC = 30
    W_NAME = 55

    sep = "-" * (W_N + W_IR + W_PCT + W_SRC + W_NAME + 12)

    print()
    print(f"{BOLD}{'='*80}{RESET}")
    print(f"{BOLD}  CALLGRIND HOTSPOT REPORT — preflate container compression{RESET}")
    print(f"{BOLD}{'='*80}{RESET}")
    print(f"  Total instructions : {total_ir:,}")
    print(f"  Functions shown    : {len(funcs)}  (by self Ir, highest first)")
    print()

    hdr = (f"{'#':>{W_N}}  {'Self Ir':>{W_IR}}  {'Self%':>{W_PCT}}"
           f"  {'Source file':<{W_SRC}}  {'Function'}")
    print(f"{BOLD}{hdr}{RESET}")
    print(sep)

    for rank, f in enumerate(funcs, 1):
        col   = _color(f.crate)
        bar   = "█" * max(1, round(f.pct / 2))          # 1 block ≈ 2%
        name  = f.name[:W_NAME]
        src   = f.src[-W_SRC:] if len(f.src) > W_SRC else f.src
        row   = (f"{rank:>{W_N}}  {f.ir:>{W_IR},}  {f.pct:>{W_PCT}.2f}%"
                 f"  {src:<{W_SRC}}  {name}")
        print(f"{col}{row}{RESET}  {DIM}{bar}{RESET}")

    # ---- Per-crate breakdown ------------------------------------------------
    crate_totals: dict[str, int] = {}
    for f in funcs:
        crate_totals[f.crate] = crate_totals.get(f.crate, 0) + f.ir

    print()
    print(f"{BOLD}  Cost breakdown (within shown functions, by crate/library){RESET}")
    print()
    shown_total = sum(crate_totals.values())
    for crate, cost in sorted(crate_totals.items(), key=lambda x: -x[1]):
        pct = cost / total_ir * 100 if total_ir else 0
        bar = "█" * max(1, round(pct / 2))
        col = _color(crate)
        print(f"{col}  {crate:<28}  {cost:>16,}  {pct:6.2f}%  {bar}{RESET}")

    unshown = total_ir - shown_total
    if unshown > 0 and total_ir:
        print(f"{DIM}  {'(not in top-N list)':<28}  {unshown:>16,}  "
              f"{unshown/total_ir*100:6.2f}%{RESET}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    root = Path(__file__).resolve().parents[1]

    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--input",    default=str(root / "samples"),
                    help="directory of files to compress (default: samples/)")
    ap.add_argument("--top",      type=int, default=40,
                    help="number of hottest functions to show (default: 40)")
    ap.add_argument("--output",   default="/tmp/callgrind_preflate.out",
                    help="callgrind output file path")
    ap.add_argument("--no-build", action="store_true",
                    help="skip cargo build")
    ap.add_argument("--keep",     action="store_true",
                    help="keep callgrind data file after finishing")
    ap.add_argument("--filter",   default=None,
                    help="only show functions matching this substring")
    args = ap.parse_args()

    input_dir = Path(args.input).resolve()
    out_file  = Path(args.output)

    if not input_dir.exists():
        sys.exit(f"Input directory not found: {input_dir}")

    print(f"{BOLD}==> Checking tools{RESET}")
    _require("valgrind",
             "sudo apt install valgrind")
    _require("callgrind_annotate",
             "Usually bundled with valgrind; try reinstalling it.")
    _require("cargo",
             "Install from https://rustup.rs/")
    v = subprocess.check_output(["valgrind", "--version"],
                                stderr=subprocess.DEVNULL, text=True).strip()
    print(f"  {v}")

    if args.no_build:
        binary = root / "target" / "release" / "preflate_util"
        if not binary.exists():
            sys.exit(f"Binary not found at {binary}; remove --no-build to build.")
        print(f"  Using existing binary: {binary}")
    else:
        binary = build_binary(root)

    run_callgrind(binary, input_dir, out_file)

    if not out_file.exists():
        sys.exit(f"callgrind output not found at {out_file} — did valgrind fail?")

    print(f"{BOLD}==> Parsing callgrind output{RESET}")
    total_ir, funcs = parse_annotate(out_file, args.top, args.filter)

    if not funcs:
        print("  No functions found — try without --filter, or inspect the raw file:")
        print(f"  callgrind_annotate {out_file}")
    else:
        print_report(total_ir, funcs)

    if not args.keep:
        for p in out_file.parent.glob(out_file.name + "*"):
            try:
                p.unlink()
            except OSError:
                pass
    else:
        print(f"  Raw data kept at : {out_file}")
        print(f"  Text report      : callgrind_annotate --auto=yes {out_file}")
        print(f"  GUI (kcachegrind): kcachegrind {out_file}")


if __name__ == "__main__":
    main()
