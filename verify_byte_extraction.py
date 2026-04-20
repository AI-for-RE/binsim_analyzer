#!/usr/bin/env python3
"""
Verification script for analyze.py's byte extraction.

For a sample of functions, compares the bytes that analyze.py would pull out
of the Ghidra project (via FileBytes.getOriginalBytes) against the bytes
read directly from the original .o file inside the corresponding .a archive,
at the byte ranges recorded in the function map.

Run from the project root so paths match those produced by the pipeline:

    python3 verify_byte_extraction.py --library libpng --samples 5
"""

import argparse
import os
import sys
import subprocess
import tempfile

import msgpack
import yaml

# Make `src/` imports resolvable the same way main.py arranges them.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from bindiff_types import ByteRange, Library, QualifiedName  # noqa: E402
import pyghidra  # noqa: E402
from pyghidra import HeadlessPyGhidraLauncher  # noqa: E402


def load_function_map(map_file: str) -> dict[str, list[tuple[str, list[ByteRange]]]]:
    with open(map_file, "rb") as f:
        raw = msgpack.unpackb(f.read(), raw=False)
    return {
        name: [(v[0], [ByteRange(r[0], r[1]) for r in v[1]]) for v in variants]
        for name, variants in raw.items()
    }


def archive_path_for(library: Library, archive_name: str) -> str | None:
    """Reverse the archive_id = archive_path.replace('/', '_') mapping from extract.py."""
    for arch in library.archives:
        if arch.replace("/", "_") == archive_name:
            return arch
    return None


def extract_object_from_archive(archive_path: str, object_name: str, dest_dir: str) -> str | None:
    """Extract `object_name` from .a archive into dest_dir. Returns the extracted path or None."""
    result = subprocess.run(
        ["ar", "x", archive_path, object_name],
        cwd=dest_dir,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"    ar failed: {result.stderr.strip()}")
        return None
    out_path = os.path.join(dest_dir, object_name)
    return out_path if os.path.exists(out_path) else None


def read_direct_bytes(object_file: str, byte_ranges: list[ByteRange]) -> bytes:
    with open(object_file, "rb") as f:
        raw = f.read()
    return b"".join(raw[br.begin_addr:br.end_addr] for br in byte_ranges)


def read_ghidra_bytes(
    project_base_dir: str,
    variant_id: str,
    archive_name: str,
    object_name: str,
    byte_ranges: list[ByteRange],
    JByteArray: object,
) -> bytes:
    project_path = "/" + os.path.join(archive_name, object_name)
    with pyghidra.open_project(project_base_dir, variant_id, create=False) as project:
        with pyghidra.program_context(project, project_path) as program:
            (file_bytes,) = program.getMemory().getAllFileBytes()
            out = bytes()
            for br in byte_ranges:
                length = br.size()
                buf = JByteArray(length)  # type: ignore[operator]
                n = file_bytes.getOriginalBytes(br.begin_addr, buf)
                out += bytes(buf[:n])
            return out


def pick_samples(
    function_map: dict[str, list[tuple[str, list[ByteRange]]]],
    library: Library,
    build_dir_root: str,
    n: int,
) -> list[tuple[str, str, list[ByteRange], str]]:
    """Pick `n` (function_key, variant_id, byte_ranges, archive_path) tuples whose build artifacts exist."""
    picks = []
    for key, variants in function_map.items():
        if len(picks) >= n:
            break
        qn = QualifiedName.from_string(key)
        arch_rel = archive_path_for(library, qn.archive_name)
        if arch_rel is None:
            continue
        for (variant_id, byte_ranges) in variants:
            if not byte_ranges or byte_ranges[0].size() < 4:
                continue
            archive_path = os.path.join(build_dir_root, variant_id, arch_rel)
            if not os.path.exists(archive_path):
                continue
            picks.append((key, variant_id, byte_ranges, archive_path))
            break
    return picks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", required=True, help="Library name as defined in config.yaml")
    parser.add_argument("--samples", type=int, default=5, help="Number of functions to verify")
    parser.add_argument("--out_dir", default="out", help="Pipeline output directory")
    parser.add_argument("--config", default="config.yaml", help="Config file")
    args = parser.parse_args()

    with open(args.config, "r") as f:
        config = yaml.safe_load(f)
    libraries = [Library(**entry) for entry in config["libraries"]]
    ghidra_projects_dir = os.path.abspath(os.path.expanduser(config["ghidra_projects_dir"]))

    library = next((lib for lib in libraries if lib.name == args.library), None)
    if library is None:
        print(f"Library '{args.library}' not found in config. Available: {[lib.name for lib in libraries]}")
        sys.exit(1)

    out_dir = os.path.abspath(args.out_dir)
    map_file = os.path.join(out_dir, "map", library.name, "function_map.msgpack")
    build_dir_root = os.path.join(out_dir, "build")
    project_base_dir = os.path.join(ghidra_projects_dir, library.name)

    if not os.path.exists(map_file):
        print(f"Function map not found at {map_file}. Run the map stage first.")
        sys.exit(1)

    print(f"Loading function map from {map_file}...")
    function_map = load_function_map(map_file)
    print(f"  {len(function_map)} functions in map.")

    samples = pick_samples(function_map, library, build_dir_root, args.samples)
    if not samples:
        print("No samples with existing build artifacts found; cannot verify.")
        sys.exit(1)
    print(f"Selected {len(samples)} samples for verification.")

    print("Starting Ghidra JVM...")
    HeadlessPyGhidraLauncher(verbose=False).start()

    import jpype
    JByteArray = jpype.JArray(jpype.JByte)

    matches = 0
    mismatches = 0
    errors = 0
    for (key, variant_id, byte_ranges, archive_path) in samples:
        qn = QualifiedName.from_string(key)
        total_len = sum(br.size() for br in byte_ranges)
        print(f"\n[{key}] variant={variant_id}, {len(byte_ranges)} range(s), {total_len} bytes")
        print(f"  archive={archive_path}")

        with tempfile.TemporaryDirectory() as tmp:
            object_file = extract_object_from_archive(archive_path, qn.object_name, tmp)
            if object_file is None:
                print(f"  ERROR: could not extract {qn.object_name} from archive.")
                errors += 1
                continue
            direct = read_direct_bytes(object_file, byte_ranges)

        try:
            ghidra = read_ghidra_bytes(
                project_base_dir, variant_id, qn.archive_name, qn.object_name, byte_ranges, JByteArray
            )
        except Exception as e:
            print(f"  ERROR: Ghidra read failed: {e}")
            errors += 1
            continue

        if direct == ghidra:
            print(f"  OK ({len(direct)} bytes match).")
            matches += 1
        else:
            mismatches += 1
            print(f"  MISMATCH: direct_len={len(direct)}, ghidra_len={len(ghidra)}")
            limit = min(len(direct), len(ghidra))
            first_diff = next((i for i in range(limit) if direct[i] != ghidra[i]), None)
            if first_diff is not None:
                print(f"    First differing offset: {first_diff} (direct=0x{direct[first_diff]:02x}, ghidra=0x{ghidra[first_diff]:02x})")
            print(f"    direct head: {direct[:16].hex()}")
            print(f"    ghidra head: {ghidra[:16].hex()}")

    print(f"\n=== Verification summary: {matches} match, {mismatches} mismatch, {errors} error ===")
    sys.exit(0 if (mismatches == 0 and errors == 0) else 2)


if __name__ == "__main__":
    main()
