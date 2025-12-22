# Demo 01 - Basic bytecode verification

This demo shows BYTEMATCH verifying deployed EVM bytecode against a build
artifact, and catching a tampered deployment.

## Files

- `Counter.json` - a Hardhat/Foundry-style build artifact. Its
  `deployedBytecode.object` field is the runtime bytecode the repo *claims*
  was compiled. It ends with a real Solidity CBOR metadata blob
  (`...a26469706673...0033`, i.e. an `ipfs` hash + 2-byte length suffix).

## What to run

### 1. Honest deployment (matches the artifact)

The artifact's own runtime bytecode obviously matches itself:

```bash
python -m bytematch verify \
  --deployed 0x6080604052348015600e575f80fd5b50600436106030575f3560e01c8063a26469706673 \
  --artifact demos/01-basic/Counter.json
```

For an end-to-end honest check, extract the runtime hex from the artifact and
feed it back as the deployed code -> verdict **`exact_match`**, exit code `0`.

### 2. Recompiled (same code, different metadata) -> `runtime_match`

If the on-chain code is the same logic but compiled from a different source
path/commit, only the trailing metadata hash differs. BYTEMATCH strips the
CBOR metadata and still reports a match (Sourcify "partial"): verdict
**`runtime_match`**, exit code `0`.

### 3. Tampered deployment -> `mismatch`

If even one opcode in the executable region is changed (e.g. an attacker swaps
a `SLOAD`/`SSTORE` or redirects a `JUMP`), BYTEMATCH reports verdict
**`mismatch`**, prints the first differing byte offset, and exits `1` so a CI
pipeline fails.

## Expected result

| scenario              | verdict        | exit |
|-----------------------|----------------|------|
| identical bytecode    | `exact_match`  | 0    |
| same code, new metadata | `runtime_match` | 0 |
| one byte changed      | `mismatch`     | 1    |

The smoke tests in `tests/test_smoke.py` assert all three behaviors against
`Counter.json`.
