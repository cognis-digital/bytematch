"""Core engine for BYTEMATCH.

Standard library only. Implements:
  * keccak256 (pure-python, for hashing bytecode without dependencies)
  * CBOR metadata splitting (the trailing Solidity metadata appended by solc)
  * immutable-reference / library-placeholder normalization
  * a verdict engine: EXACT_MATCH / RUNTIME_MATCH / PARTIAL_MATCH / MISMATCH

The core question this answers: "is the deployed contract the same code its
repo/build artifact claims, or has it been tampered with?"
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Tuple, List, Dict, Any


# ---------------------------------------------------------------------------
# keccak-256 (Ethereum's hash). Pure-python, stdlib only.
# Based on the Keccak reference permutation. Used to fingerprint bytecode and
# to hash the embedded metadata for comparison.
# ---------------------------------------------------------------------------

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_KECCAK_ROTC = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
]

_KECCAK_PILN = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
]

_MASK64 = (1 << 64) - 1


def _rotl64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f(state: List[int]) -> None:
    for rnd in range(24):
        # Theta
        bc = [0] * 5
        for i in range(5):
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20]
        for i in range(5):
            t = bc[(i + 4) % 5] ^ _rotl64(bc[(i + 1) % 5], 1)
            for j in range(0, 25, 5):
                state[j + i] ^= t
        # Rho + Pi
        t = state[1]
        for i in range(24):
            j = _KECCAK_PILN[i]
            bc[0] = state[j]
            state[j] = _rotl64(t, _KECCAK_ROTC[i])
            t = bc[0]
        # Chi
        for j in range(0, 25, 5):
            row = state[j:j + 5]
            for i in range(5):
                state[j + i] = row[i] ^ ((~row[(i + 1) % 5]) & row[(i + 2) % 5])
        # Iota
        state[0] ^= _KECCAK_RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Compute the keccak-256 digest of ``data`` (32 bytes), stdlib-only."""
    rate = 136  # 1088 bits for keccak-256
    state = [0] * 25
    # Absorb
    padded = bytearray(data)
    padded.append(0x01)  # keccak padding (NOT SHA3's 0x06)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            state[i] ^= lane
        _keccak_f(state)
    # Squeeze
    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out += state[i].to_bytes(8, "little")
            if len(out) >= 32:
                break
        if len(out) < 32:
            _keccak_f(state)
    return bytes(out[:32])


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    EXACT_MATCH = "exact_match"        # identical including metadata hash
    RUNTIME_MATCH = "runtime_match"    # identical after stripping metadata (Sourcify "partial")
    PARTIAL_MATCH = "partial_match"    # identical after normalizing immutables/libraries
    MISMATCH = "mismatch"              # code differs -> possible tampering


# Verdicts that should be treated as a verification FAILURE for CI gating.
_FAILING_VERDICTS = {Verdict.MISMATCH}


@dataclass
class MetadataInfo:
    present: bool
    length: int = 0
    metadata_hex: str = ""
    ipfs_or_bzzr: Optional[str] = None  # decoded hash hint if recognizable
    solc_version: Optional[str] = None


@dataclass
class MatchResult:
    verdict: Verdict
    matched: bool                      # True for any non-MISMATCH verdict
    deployed_len: int
    artifact_len: int
    code_len_deployed: int             # length after metadata strip (bytes)
    code_len_artifact: int
    deployed_keccak: str
    artifact_keccak: str
    deployed_code_keccak: str          # keccak of metadata-stripped code
    artifact_code_keccak: str
    normalized_match: bool
    first_diff_offset: Optional[int]   # byte offset of first divergence (stripped code)
    diff_byte_count: int
    metadata_deployed: MetadataInfo
    metadata_artifact: MetadataInfo
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


# ---------------------------------------------------------------------------
# Bytecode parsing helpers
# ---------------------------------------------------------------------------

def normalize_bytecode(value: str) -> bytes:
    """Accept a 0x-prefixed or bare hex string (any case/whitespace) -> bytes.

    Raises ValueError on invalid hex or odd length.
    """
    if value is None:
        raise ValueError("bytecode is None")
    s = value.strip()
    # drop surrounding quotes if a JSON string slipped through
    s = s.strip('"')
    s = re.sub(r"\s+", "", s)
    if s.lower().startswith("0x"):
        s = s[2:]
    if s == "":
        return b""
    if len(s) % 2 != 0:
        raise ValueError(f"hex string has odd length ({len(s)} nibbles)")
    if not re.fullmatch(r"[0-9a-fA-F]*", s):
        raise ValueError("bytecode contains non-hex characters")
    return bytes.fromhex(s)


def split_metadata(code: bytes) -> Tuple[bytes, bytes]:
    """Split runtime ``code`` into (executable, metadata).

    Solidity appends a CBOR-encoded metadata blob followed by a 2-byte
    big-endian length suffix. e.g. ``...a264<cbor>0033`` where 0x0033 == 51 is
    the length of the preceding CBOR. We validate the length suffix points to a
    plausible CBOR map (starts with 0xa1/0xa2/0xa3...) before trusting it.
    """
    if len(code) < 4:
        return code, b""
    suffix_len = int.from_bytes(code[-2:], "big")
    # CBOR blob length + its own 2-byte length marker
    total = suffix_len + 2
    if suffix_len <= 0 or total > len(code) or suffix_len > 4096:
        return code, b""
    meta_start = len(code) - total
    cbor = code[meta_start:len(code) - 2]
    # CBOR map of small size begins with major type 5 (0xa0-0xb7).
    if not cbor or not (0xA0 <= cbor[0] <= 0xB7):
        return code, b""
    metadata = code[meta_start:]
    return code[:meta_start], metadata


def strip_metadata(code: bytes) -> bytes:
    """Return ``code`` with any trailing Solidity metadata removed."""
    return split_metadata(code)[0]


def _decode_solc_version(cbor: bytes) -> Optional[str]:
    """Best-effort extraction of the solc version triple from CBOR metadata.

    solc encodes ``\"solc\"`` -> a 3-byte byte string (major.minor.patch).
    We scan for the ASCII key 'solc' followed by a CBOR byte-string of len 3.
    """
    idx = cbor.find(b"solc")
    if idx == -1:
        return None
    j = idx + 4
    if j < len(cbor) and cbor[j] == 0x43 and j + 3 < len(cbor):  # 0x43 = bytes(3)
        a, b, c = cbor[j + 1], cbor[j + 2], cbor[j + 3]
        return f"{a}.{b}.{c}"
    return None


def _decode_hash_hint(cbor: bytes) -> Optional[str]:
    """Identify whether metadata carries an ipfs or bzzr0/bzzr1 hash key."""
    for key in (b"ipfs", b"bzzr1", b"bzzr0"):
        if key in cbor:
            return key.decode()
    return None


def extract_metadata(code: bytes) -> MetadataInfo:
    """Return structured info about the trailing metadata, if present."""
    _, metadata = split_metadata(code)
    if not metadata:
        return MetadataInfo(present=False)
    cbor = metadata[:-2]
    return MetadataInfo(
        present=True,
        length=len(metadata),
        metadata_hex="0x" + metadata.hex(),
        ipfs_or_bzzr=_decode_hash_hint(cbor),
        solc_version=_decode_solc_version(cbor),
    )


# A 32-byte immutable reference / library placeholder, once zeroed for
# normalization, looks like a run of NUL bytes. Solidity also leaves a
# placeholder __$<keccak>$__ in *unlinked* artifacts; deployed code will have
# real addresses there. We normalize 32-byte aligned all-zero / all-equal runs
# only where the two codes diverge, to support Sourcify-style PARTIAL matches.

def _normalize_immutables(a: bytes, b: bytes) -> Tuple[bytes, bytes, int]:
    """Zero out positions that look like immutable/library address slots.

    A slot is recognized when one side already contains all-zero bytes (the
    unlinked artifact placeholder) and the other contains real data (the
    deployed contract with a linked address). Only 20-byte (address) or 32-byte
    (bytes32/immutable) runs where the *artifact* side (b) is all-zero qualify.
    This avoids false PARTIAL_MATCH when code has been genuinely tampered.

    We require both codes to be the same length to even attempt this; differing
    lengths after metadata strip is a structural mismatch.
    """
    if len(a) != len(b):
        return a, b, 0
    na = bytearray(a)
    nb = bytearray(b)
    normalized = 0
    i = 0
    n = len(a)
    while i < n:
        if na[i] != nb[i]:
            # Check whether this looks like a library/immutable slot: the
            # artifact side (nb) must be all-zero for a standard slot length
            # (20 bytes for an address, 32 bytes for a bytes32 immutable).
            slot_found = False
            for slot_size in (32, 20):
                end = i + slot_size
                if end > n:
                    continue
                # The artifact's region must be entirely zero.
                if all(nb[k] == 0 for k in range(i, end)):
                    for k in range(i, end):
                        na[k] = 0
                        nb[k] = 0
                        normalized += 1
                    i = end
                    slot_found = True
                    break
            if not slot_found:
                # Not a recognized placeholder pattern — do not normalize.
                i += 1
        else:
            i += 1
    return bytes(na), bytes(nb), normalized


def _first_diff(a: bytes, b: bytes) -> Tuple[Optional[int], int]:
    """Return (offset of first differing byte, total differing byte count)."""
    first = None
    count = 0
    for i in range(max(len(a), len(b))):
        ba = a[i] if i < len(a) else None
        bb = b[i] if i < len(b) else None
        if ba != bb:
            if first is None:
                first = i
            count += 1
    return first, count


# ---------------------------------------------------------------------------
# Public verification API
# ---------------------------------------------------------------------------

def verify(deployed: str, artifact: str) -> MatchResult:
    """Compare deployed bytecode against an artifact's runtime bytecode.

    Both inputs are hex strings (0x-prefixed or bare). Returns a MatchResult
    with a Sourcify-style verdict.
    """
    dep = normalize_bytecode(deployed)
    art = normalize_bytecode(artifact)

    meta_dep = extract_metadata(dep)
    meta_art = extract_metadata(art)

    dep_code = strip_metadata(dep)
    art_code = strip_metadata(art)

    notes: List[str] = []

    dep_kc = keccak256(dep).hex()
    art_kc = keccak256(art).hex()
    dep_code_kc = keccak256(dep_code).hex()
    art_code_kc = keccak256(art_code).hex()

    if not dep:
        notes.append("deployed bytecode is empty (no contract at address?)")
    if not art:
        notes.append("artifact bytecode is empty")

    # 1. Exact match including metadata.
    if dep == art and dep != b"":
        verdict = Verdict.EXACT_MATCH
        notes.append("byte-for-byte identical including metadata hash")
        first_diff, diff_count, normalized_match = None, 0, True
    # 2. Runtime match (Sourcify \"partial\"): code equal, metadata differs.
    elif dep_code == art_code and dep_code != b"":
        verdict = Verdict.RUNTIME_MATCH
        normalized_match = True
        first_diff, diff_count = None, 0
        if meta_dep.metadata_hex != meta_art.metadata_hex:
            notes.append("executable code identical; metadata hash differs "
                         "(recompiled with different source path/settings)")
        else:
            notes.append("executable code identical")
    else:
        # 3. Attempt immutable/library normalization.
        na, nb, normalized = _normalize_immutables(dep_code, art_code)
        if normalized and na == nb:
            verdict = Verdict.PARTIAL_MATCH
            normalized_match = True
            first_diff, diff_count = None, normalized
            notes.append(
                f"code matches after normalizing {normalized} byte(s) of "
                "immutables/library addresses")
        else:
            verdict = Verdict.MISMATCH
            normalized_match = False
            first_diff, diff_count = _first_diff(dep_code, art_code)
            if len(dep_code) != len(art_code):
                notes.append(
                    f"code length differs: deployed={len(dep_code)} "
                    f"artifact={len(art_code)} bytes")
            notes.append("BYTECODE MISMATCH — deployed code does not match "
                         "the build artifact (possible tampering)")

    return MatchResult(
        verdict=verdict,
        matched=verdict not in _FAILING_VERDICTS,
        deployed_len=len(dep),
        artifact_len=len(art),
        code_len_deployed=len(dep_code),
        code_len_artifact=len(art_code),
        deployed_keccak="0x" + dep_kc,
        artifact_keccak="0x" + art_kc,
        deployed_code_keccak="0x" + dep_code_kc,
        artifact_code_keccak="0x" + art_code_kc,
        normalized_match=normalized_match,
        first_diff_offset=first_diff,
        diff_byte_count=diff_count,
        metadata_deployed=meta_dep,
        metadata_artifact=meta_art,
        notes=notes,
    )


def load_artifact_runtime_bytecode(text: str) -> str:
    """Extract runtime (deployed) bytecode hex from a build artifact JSON.

    Supports common shapes:
      * Hardhat/standard solc:  {\"deployedBytecode\": {\"object\": \"0x..\"}}
      * Hardhat (string form):  {\"deployedBytecode\": \"0x..\"}
      * Truffle:                {\"deployedBytecode\": \"0x..\"}
      * solc combined-json:     {\"contracts\": {\"<file>:<name>\": {\"bin-runtime\": \"..\"}}}
      * Foundry:                {\"deployedBytecode\": {\"object\": \"0x..\"}}
    Falls back to creation \"bytecode\" only if no runtime form exists.
    Raises ValueError if nothing usable is found.
    """
    data = json.loads(text)

    def _obj(v: Any) -> Optional[str]:
        if isinstance(v, str):
            return v
        if isinstance(v, dict):
            o = v.get("object")
            if isinstance(o, str):
                return o
        return None

    if isinstance(data, dict):
        for key in ("deployedBytecode", "runtimeBytecode", "bin-runtime"):
            if key in data:
                got = _obj(data[key])
                if got:
                    return got
        # solc combined-json: pick the first contract with bin-runtime
        contracts = data.get("contracts")
        if isinstance(contracts, dict):
            for _, cdef in contracts.items():
                if isinstance(cdef, dict):
                    for key in ("bin-runtime", "runtimeBytecode", "deployedBytecode"):
                        if key in cdef:
                            got = _obj(cdef[key])
                            if got:
                                return got
        # last resort: creation bytecode
        for key in ("bytecode", "bin"):
            if key in data:
                got = _obj(data[key])
                if got:
                    return got
    raise ValueError("could not locate runtime bytecode in artifact JSON "
                     "(looked for deployedBytecode/bin-runtime/bytecode)")


def verify_artifact(deployed: str, artifact_json_text: str) -> MatchResult:
    """Verify ``deployed`` hex against the runtime bytecode in an artifact JSON."""
    art_hex = load_artifact_runtime_bytecode(artifact_json_text)
    return verify(deployed, art_hex)
