#!/usr/bin/env python3
"""Freeze and verify the MDBX2 UniFFI ABI used by MDBX3 drop-in builds."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


PROFILE = "mdbx2-uniffi-bindings-v1"
EXTERNAL_FUNCTION_PATTERN = re.compile(r"\bexternal\s+fun\s+([A-Za-z0-9_]+)\s*\(")
CHECKSUM_PATTERN = re.compile(
    r"if\s*\(lib\.(uniffi_[A-Za-z0-9_]+_checksum_[A-Za-z0-9_]+)\(\)\s*!=\s*"
    r"(\d+)\.toShort\(\)\)"
)
CONTRACT_VERSION_PATTERN = re.compile(r"val\s+bindings_contract_version\s*=\s*(\d+)")
COMPONENT_NAME_PATTERN = re.compile(r'componentName\s*=\s*"([^"]+)"')


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_kotlin_bindings(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    required_symbols = sorted(set(EXTERNAL_FUNCTION_PATTERN.findall(text)))
    checksum_pairs = CHECKSUM_PATTERN.findall(text)
    checksums = {name: int(value) for name, value in checksum_pairs}

    contract_match = CONTRACT_VERSION_PATTERN.search(text)
    component_match = COMPONENT_NAME_PATTERN.search(text)
    if contract_match is None:
        raise ValueError("Kotlin bindings do not declare a UniFFI contract version")
    if component_match is None:
        raise ValueError("Kotlin bindings do not declare a component name")
    if not required_symbols:
        raise ValueError("Kotlin bindings contain no external native functions")
    if not checksums:
        raise ValueError("Kotlin bindings contain no API checksum checks")

    missing_checksum_symbols = sorted(set(checksums) - set(required_symbols))
    if missing_checksum_symbols:
        raise ValueError(
            "checksum functions are absent from native declarations: "
            + ", ".join(missing_checksum_symbols)
        )

    return {
        "profile": PROFILE,
        "component_name": component_match.group(1),
        "uniffi_contract_version": int(contract_match.group(1)),
        "generated_bindings_sha256": sha256_file(path),
        "required_symbols": required_symbols,
        "checksums": dict(sorted(checksums.items())),
    }


def write_snapshot(args: argparse.Namespace) -> int:
    bindings_path = Path(args.bindings).resolve()
    output_path = Path(args.output).resolve()
    snapshot = parse_kotlin_bindings(bindings_path)
    snapshot["source_commit"] = args.source_commit
    snapshot["source_library_name"] = args.source_library_name

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "profile": snapshot["profile"],
                "symbols": len(snapshot["required_symbols"]),
                "checksums": len(snapshot["checksums"]),
                "output": str(output_path),
            },
            sort_keys=True,
        )
    )
    return 0


def load_baseline(path: Path) -> dict[str, Any]:
    baseline = json.loads(path.read_text(encoding="utf-8"))
    if baseline.get("profile") != PROFILE:
        raise ValueError(f"unsupported ABI baseline profile: {baseline.get('profile')!r}")
    if baseline.get("component_name") != "mdbx_ffi":
        raise ValueError("ABI baseline does not describe the mdbx_ffi component")
    if not isinstance(baseline.get("required_symbols"), list):
        raise ValueError("ABI baseline required_symbols must be a list")
    if not isinstance(baseline.get("checksums"), dict):
        raise ValueError("ABI baseline checksums must be an object")
    return baseline


def require_symbol(library: ctypes.CDLL, name: str) -> Any:
    try:
        return getattr(library, name)
    except AttributeError as error:
        raise RuntimeError(f"required MDBX2 UniFFI symbol is missing: {name}") from error


def verify_library(args: argparse.Namespace) -> int:
    baseline_path = Path(args.baseline).resolve()
    library_path = Path(args.library).resolve()
    baseline = load_baseline(baseline_path)
    library = ctypes.CDLL(str(library_path))

    missing_symbols: list[str] = []
    for name in baseline["required_symbols"]:
        try:
            require_symbol(library, name)
        except RuntimeError:
            missing_symbols.append(name)

    contract_name = "ffi_mdbx_ffi_uniffi_contract_version"
    contract_function = require_symbol(library, contract_name)
    contract_function.argtypes = []
    contract_function.restype = ctypes.c_int32
    actual_contract = int(contract_function())
    expected_contract = int(baseline["uniffi_contract_version"])

    checksum_mismatches: list[dict[str, Any]] = []
    for name, expected_value in baseline["checksums"].items():
        function = require_symbol(library, name)
        function.argtypes = []
        function.restype = ctypes.c_uint16
        actual_value = int(function())
        if actual_value != int(expected_value):
            checksum_mismatches.append(
                {"symbol": name, "expected": int(expected_value), "actual": actual_value}
            )

    if missing_symbols or actual_contract != expected_contract or checksum_mismatches:
        report = {
            "profile": baseline["profile"],
            "library": str(library_path),
            "missing_symbols": missing_symbols,
            "contract_version": {
                "expected": expected_contract,
                "actual": actual_contract,
            },
            "checksum_mismatches": checksum_mismatches,
        }
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "profile": baseline["profile"],
                "library": str(library_path),
                "verified_symbols": len(baseline["required_symbols"]),
                "verified_checksums": len(baseline["checksums"]),
                "uniffi_contract_version": actual_contract,
                "status": "compatible",
            },
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser(
        "snapshot", help="create an ABI baseline from generated Kotlin bindings"
    )
    snapshot.add_argument("--bindings", required=True)
    snapshot.add_argument("--output", required=True)
    snapshot.add_argument("--source-commit", required=True)
    snapshot.add_argument("--source-library-name", default="libmdbx_ffi.so")
    snapshot.set_defaults(handler=write_snapshot)

    verify = subparsers.add_parser(
        "verify", help="verify a current dynamic library against an ABI baseline"
    )
    verify.add_argument("--baseline", required=True)
    verify.add_argument("--library", required=True)
    verify.set_defaults(handler=verify_library)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.handler(args))
    except (OSError, ValueError, RuntimeError) as error:
        print(f"MDBX FFI ABI verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
