"""BYTEMATCH command-line interface.

Verifies that deployed EVM bytecode matches a build artifact, detecting
tampering. Metadata-aware (Sourcify-style exact / partial verdicts).

Examples
--------
  # Compare deployed bytecode against a Solidity build artifact JSON
  bytematch verify --deployed 0x6080... --artifact build/Token.json

  # Compare two raw hex blobs (files or literals), JSON output for CI
  bytematch verify --deployed deployed.hex --artifact-hex expected.hex --format json

  # Read deployed code from stdin
  cast code 0xADDR | bytematch verify --deployed - --artifact build/Token.json

Exit codes: 0 = match (exact/runtime/partial), 1 = MISMATCH (tampering), 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Verdict,
    MatchResult,
    verify,
    load_artifact_runtime_bytecode,
)


# Maximum number of bytes read from a file or stdin (4 MB - contract
# bytecode is never this large; guards against accidental huge file reads).
_MAX_INPUT_BYTES = 4 * 1024 * 1024


def _read_source(value: str) -> str:
    """Resolve an input that may be a literal hex string, a file path, or '-'.

    Heuristic: if it looks like hex (optionally 0x) and is not an existing
    path, treat it as a literal. '-' means stdin.

    Raises OSError on read failure, ValueError if the file is binary or
    exceeds the 4 MB sanity limit.
    """
    if value == "-":
        raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
        if len(raw) > _MAX_INPUT_BYTES:
            raise ValueError(f"stdin input exceeds {_MAX_INPUT_BYTES} byte limit")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"stdin contains non-UTF-8 / binary data: {exc}") from exc
    if os.path.isfile(value):
        size = os.path.getsize(value)
        if size > _MAX_INPUT_BYTES:
            raise ValueError(
                f"file {value!r} is {size} bytes (limit {_MAX_INPUT_BYTES}); "
                "is this the right file?"
            )
        with open(value, "rb") as fh:
            raw = fh.read()
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"file {value!r} appears to be binary (not a hex or JSON file): {exc}"
            ) from exc
    return value


def _verdict_symbol(v: Verdict) -> str:
    return {
        Verdict.EXACT_MATCH: "OK   ",
        Verdict.RUNTIME_MATCH: "OK   ",
        Verdict.PARTIAL_MATCH: "OK~  ",
        Verdict.MISMATCH: "FAIL ",
    }[v]


def _render_table(res: MatchResult) -> str:
    lines = []
    lines.append("BYTEMATCH verification report")
    lines.append("=" * 46)
    lines.append(f"  verdict            : [{_verdict_symbol(res.verdict)}] {res.verdict.value}")
    lines.append(f"  matched            : {res.matched}")
    lines.append(f"  deployed bytes     : {res.deployed_len}")
    lines.append(f"  artifact bytes     : {res.artifact_len}")
    lines.append(f"  code bytes (dep)   : {res.code_len_deployed}")
    lines.append(f"  code bytes (art)   : {res.code_len_artifact}")
    lines.append(f"  deployed keccak    : {res.deployed_keccak}")
    lines.append(f"  artifact keccak    : {res.artifact_keccak}")
    lines.append(f"  code keccak (dep)  : {res.deployed_code_keccak}")
    lines.append(f"  code keccak (art)  : {res.artifact_code_keccak}")
    if res.first_diff_offset is not None:
        lines.append(f"  first diff offset  : {res.first_diff_offset} (byte)")
        lines.append(f"  differing bytes    : {res.diff_byte_count}")
    md = res.metadata_deployed
    ma = res.metadata_artifact
    lines.append(f"  metadata (dep)     : present={md.present} "
                 f"len={md.length} solc={md.solc_version} hash={md.ipfs_or_bzzr}")
    lines.append(f"  metadata (art)     : present={ma.present} "
                 f"len={ma.length} solc={ma.solc_version} hash={ma.ipfs_or_bzzr}")
    if res.notes:
        lines.append("  notes:")
        for n in res.notes:
            lines.append(f"    - {n}")
    return "\n".join(lines)


def _cmd_verify(args: argparse.Namespace) -> int:
    # Resolve deployed bytecode.
    try:
        deployed_text = _read_source(args.deployed)
    except (OSError, ValueError) as exc:
        print(f"error: reading --deployed: {exc}", file=sys.stderr)
        return 2

    # Resolve expected bytecode either from an artifact JSON or raw hex.
    if args.artifact and args.artifact_hex:
        print("error: use either --artifact or --artifact-hex, not both",
              file=sys.stderr)
        return 2
    if not args.artifact and not args.artifact_hex:
        print("error: one of --artifact or --artifact-hex is required",
              file=sys.stderr)
        return 2

    try:
        if args.artifact:
            artifact_text = _read_source(args.artifact)
            expected_hex = load_artifact_runtime_bytecode(artifact_text)
        else:
            expected_hex = _read_source(args.artifact_hex)
    except OSError as exc:
        print(f"error: reading artifact: {exc}", file=sys.stderr)
        return 2
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: artifact: {exc}", file=sys.stderr)
        return 2

    try:
        res = verify(deployed_text, expected_hex)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print(_render_table(res))

    # Exit non-zero on mismatch so CI gates fail. --strict also fails on
    # non-exact (partial/runtime) matches.
    if not res.matched:
        return 1
    if args.strict and res.verdict != Verdict.EXACT_MATCH:
        if args.format != "json":
            print("strict: verdict is not exact_match", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Verify deployed EVM bytecode matches a build artifact "
                    "(detects tampering). Metadata-aware, Sourcify-style.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("--format", choices=["table", "json"], default="table",
                        help="output format (default: table)")

    sub = parser.add_subparsers(dest="command")

    v = sub.add_parser(
        "verify",
        help="compare deployed bytecode against an artifact",
        description="Compare deployed (on-chain) bytecode against the runtime "
                    "bytecode of a build artifact and emit a match verdict.",
    )
    v.add_argument("--deployed", required=True, metavar="HEX|FILE|-",
                   help="deployed bytecode: literal hex, a file, or '-' for stdin")
    v.add_argument("--artifact", metavar="FILE|JSON",
                   help="build artifact JSON (Hardhat/Foundry/Truffle/solc)")
    v.add_argument("--artifact-hex", metavar="HEX|FILE|-",
                   help="expected runtime bytecode as raw hex (file/literal/-)")
    v.add_argument("--strict", action="store_true",
                   help="require an exact_match (fail on partial/runtime match)")
    v.add_argument("--format", choices=["table", "json"], default="table",
                   help="output format (default: table)")
    v.set_defaults(func=_cmd_verify)
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - unexpected path
        print(f"internal error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
