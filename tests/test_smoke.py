"""Smoke tests for BYTEMATCH. Imports the core engine, runs it on the demo
artifact, and asserts real verification behavior. No network access.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bytematch import (  # noqa: E402
    verify,
    verify_artifact,
    keccak256,
    strip_metadata,
    extract_metadata,
    normalize_bytecode,
    load_artifact_runtime_bytecode,
    Verdict,
    TOOL_NAME,
    TOOL_VERSION,
)
from bytematch.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "Counter.json")


def _artifact_text():
    with open(DEMO, "r", encoding="utf-8") as fh:
        return fh.read()


def _runtime_hex():
    return load_artifact_runtime_bytecode(_artifact_text())


# --- keccak correctness (known answer test) -------------------------------

def test_keccak_empty_known_answer():
    # keccak256("") is a well-known Ethereum constant.
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


def test_keccak_abc_known_answer():
    assert keccak256(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    )


# --- metadata handling ----------------------------------------------------

def test_metadata_is_detected_and_stripped():
    full = normalize_bytecode(_runtime_hex())
    info = extract_metadata(full)
    assert info.present is True
    assert info.length > 0
    assert info.ipfs_or_bzzr == "ipfs"
    assert info.solc_version is not None
    stripped = strip_metadata(full)
    assert len(stripped) < len(full)


# --- the three core verdicts ---------------------------------------------

def test_exact_match_against_self():
    rt = _runtime_hex()
    res = verify(rt, rt)
    assert res.verdict == Verdict.EXACT_MATCH
    assert res.matched is True
    assert res.first_diff_offset is None


def test_verify_artifact_helper_matches_self():
    rt = _runtime_hex()
    res = verify_artifact(rt, _artifact_text())
    assert res.matched is True
    assert res.verdict in (Verdict.EXACT_MATCH, Verdict.RUNTIME_MATCH)


def test_runtime_match_when_only_metadata_differs():
    full = normalize_bytecode(_runtime_hex())
    code = strip_metadata(full)
    # Build a variant with a *different* metadata blob but identical code.
    other_meta = bytes.fromhex("a2646970667358220000000000000000000000000000"
                               "000000000000000000000000000000000000000000")
    other_meta = other_meta + (len(other_meta)).to_bytes(2, "big")
    variant = code + other_meta
    res = verify("0x" + full.hex(), "0x" + variant.hex())
    assert res.verdict == Verdict.RUNTIME_MATCH
    assert res.matched is True


def test_mismatch_when_code_tampered():
    full = normalize_bytecode(_runtime_hex())
    tampered = bytearray(full)
    # Flip an opcode byte well inside the executable region.
    tampered[10] ^= 0xFF
    res = verify("0x" + full.hex(), "0x" + bytes(tampered).hex())
    assert res.verdict == Verdict.MISMATCH
    assert res.matched is False
    assert res.first_diff_offset is not None
    assert res.diff_byte_count >= 1


def test_empty_deployed_is_not_a_match():
    rt = _runtime_hex()
    res = verify("0x", rt)
    assert res.verdict == Verdict.MISMATCH
    assert res.matched is False


# --- input parsing --------------------------------------------------------

def test_normalize_rejects_odd_length():
    with pytest.raises(ValueError):
        normalize_bytecode("0xabc")


def test_normalize_rejects_non_hex():
    with pytest.raises(ValueError):
        normalize_bytecode("0xzz")


def test_normalize_accepts_bare_and_prefixed():
    assert normalize_bytecode("0x6080") == normalize_bytecode("6080")
    assert normalize_bytecode("  60 80  ") == b"\x60\x80"


# --- artifact loader shapes ----------------------------------------------

def test_loader_handles_string_form():
    art = json.dumps({"deployedBytecode": "0x6080"})
    assert load_artifact_runtime_bytecode(art) == "0x6080"


def test_loader_handles_combined_json():
    art = json.dumps({"contracts": {"A.sol:A": {"bin-runtime": "6080"}}})
    assert load_artifact_runtime_bytecode(art) == "6080"


def test_loader_raises_when_missing():
    with pytest.raises(ValueError):
        load_artifact_runtime_bytecode(json.dumps({"abi": []}))


# --- CLI end-to-end -------------------------------------------------------

def test_cli_exact_match_exit_zero(capsys):
    rt = _runtime_hex()
    rc = main(["verify", "--deployed", rt, "--artifact-hex", rt, "--format", "json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "exact_match"
    assert out["matched"] is True


def test_cli_mismatch_exit_one(capsys):
    rt = normalize_bytecode(_runtime_hex())
    tampered = bytearray(rt)
    tampered[10] ^= 0xFF
    rc = main(["verify", "--deployed", "0x" + rt.hex(),
               "--artifact-hex", "0x" + bytes(tampered).hex(),
               "--format", "json"])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "mismatch"


def test_cli_against_artifact_file(capsys):
    rt = _runtime_hex()
    rc = main(["verify", "--deployed", rt, "--artifact", DEMO, "--format", "json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["matched"] is True


def test_cli_strict_fails_on_runtime_match(capsys):
    full = normalize_bytecode(_runtime_hex())
    code = strip_metadata(full)
    other_meta = bytes.fromhex("a26469706673582200" + "00" * 20)
    other_meta = other_meta + len(other_meta).to_bytes(2, "big")
    variant = code + other_meta
    rc = main(["verify", "--deployed", "0x" + full.hex(),
               "--artifact-hex", "0x" + variant.hex(), "--strict"])
    assert rc == 1  # strict rejects non-exact match


def test_version_constants():
    assert TOOL_NAME == "bytematch"
    assert isinstance(TOOL_VERSION, str) and TOOL_VERSION


# ---------------------------------------------------------------------------
# Hardening tests: error paths, edge cases, and input validation
# ---------------------------------------------------------------------------

def test_verify_rejects_non_string_deployed():
    """verify() with a non-string/non-bytes deployed raises ValueError."""
    import pytest
    with pytest.raises(ValueError, match="deployed must be"):
        verify(12345, "0x6080")


def test_verify_rejects_non_string_artifact():
    import pytest
    with pytest.raises(ValueError, match="artifact must be"):
        verify("0x6080", None)


def test_loader_rejects_empty_json():
    """load_artifact_runtime_bytecode raises ValueError on empty input."""
    import pytest
    with pytest.raises(ValueError, match="empty"):
        load_artifact_runtime_bytecode("")


def test_loader_rejects_invalid_json():
    """load_artifact_runtime_bytecode raises ValueError (not JSONDecodeError) on bad JSON."""
    import pytest
    with pytest.raises(ValueError, match="not valid JSON"):
        load_artifact_runtime_bytecode("{not json}")


def test_cli_missing_artifact_flag_returns_2(capsys):
    """CLI returns exit 2 when neither --artifact nor --artifact-hex given."""
    rc = main(["verify", "--deployed", "0x6080"])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "required" in err.lower() or "artifact" in err.lower()


def test_cli_both_artifact_flags_returns_2(capsys):
    """CLI returns exit 2 when both --artifact and --artifact-hex are given."""
    rt = _runtime_hex()
    rc = main(["verify", "--deployed", rt, "--artifact", DEMO, "--artifact-hex", rt])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "not both" in err or "artifact" in err.lower()


def test_cli_nonexistent_artifact_file_returns_2(capsys):
    """CLI returns exit 2 when the artifact file does not exist."""
    rt = _runtime_hex()
    rc = main(["verify", "--deployed", rt, "--artifact", "/nonexistent/path/Token.json"])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "error" in err.lower() or "artifact" in err.lower()


def test_cli_malformed_artifact_json_returns_2(capsys, tmp_path):
    """CLI returns exit 2 when the artifact file contains malformed JSON."""
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not valid json}", encoding="utf-8")
    rt = _runtime_hex()
    rc = main(["verify", "--deployed", rt, "--artifact", str(bad_json)])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "error" in err.lower()


def test_cli_binary_artifact_file_returns_2(capsys, tmp_path):
    """CLI returns exit 2 when the artifact file is binary (not text)."""
    binary_file = tmp_path / "binary.json"
    binary_file.write_bytes(bytes(range(256)))
    rt = _runtime_hex()
    rc = main(["verify", "--deployed", rt, "--artifact", str(binary_file)])
    assert rc == 2
    _, err = capsys.readouterr()
    assert "error" in err.lower()


def test_both_empty_bytecode_is_mismatch():
    """Two empty bytecode inputs should yield MISMATCH (nothing to verify)."""
    res = verify("0x", "0x")
    assert res.verdict == Verdict.MISMATCH
    assert res.matched is False


def test_verify_accepts_bytes_input():
    """verify() accepts raw bytes in addition to hex strings."""
    rt_bytes = normalize_bytecode(_runtime_hex())
    res = verify(rt_bytes, rt_bytes)
    assert res.verdict == Verdict.EXACT_MATCH
