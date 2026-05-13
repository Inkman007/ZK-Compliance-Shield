# Circuit Specification

## Overview

The ZK circuit proves two statements simultaneously:

1. **Merkle membership:** The prover knows a `user_hash` that is a leaf in the
   Merkle tree whose root is `merkle_root` (stored on-chain).

2. **Nullifier preimage:** The prover knows a `user_secret` such that
   `nullifier = Poseidon(user_secret ‖ merkle_root)`.

The circuit has **one public input**: `nullifier`.  
All other values (`user_hash`, `user_secret`, Merkle path) are private witnesses.

## Proof system

| Property | Value |
|----------|-------|
| Proof system | Groth16 |
| Curve | BN254 (alt_bn128) |
| Hash function | Poseidon (BN254-native) |
| Public inputs | 1 (nullifier) |
| Trusted setup | Per-circuit (snarkjs `groth16 setup` or Noir) |

## Verification key format

The VK produced by the trusted setup must be encoded as big-endian uncompressed
BN254 points and placed in `src/lib.rs`:

```
VK_ALPHA_G1  [u8; 64]   G1: x‖y
VK_BETA_G2   [u8; 128]  G2: x0‖x1‖y0‖y1
VK_GAMMA_G2  [u8; 128]  G2: x0‖x1‖y0‖y1
VK_DELTA_G2  [u8; 128]  G2: x0‖x1‖y0‖y1
VK_IC_0_G1   [u8; 64]   G1: constant term
VK_IC_1_G1   [u8; 64]   G1: nullifier coefficient
```

## Groth16 verification equation

```
e(π_A, π_B) · e(−vk_α, vk_β) · e(−vk_x, vk_γ) · e(−π_C, vk_δ) == 1
```

Public input accumulator (single input):
```
vk_x = IC[0] + nullifier * IC[1]
```

## Proof format (on-chain submission)

All values are big-endian hex, no `0x` prefix:

| Field | Bytes | Description |
|-------|-------|-------------|
| `proof_a` | 64 | G1 point π_A |
| `proof_b` | 128 | G2 point π_B |
| `proof_c` | 64 | G1 point π_C |
| `nullifier` | 32 | Poseidon(user_secret ‖ merkle_root) |

## Nullifier design

```
nullifier = Poseidon(user_secret ‖ merkle_root)
```

Binding the nullifier to `merkle_root` means:
- A nullifier from one KYC epoch cannot be replayed in a different epoch
  (different root = different nullifier).
- If periodic re-verification is required, add an `epoch` field:
  `nullifier = Poseidon(user_secret ‖ merkle_root ‖ epoch)`

## Trusted setup

Use one of:

```bash
# snarkjs (Groth16)
snarkjs groth16 setup circuit.r1cs pot_final.ptau circuit_final.zkey
snarkjs zkey export verificationkey circuit_final.zkey verification_key.json

# Noir (Barretenberg backend)
nargo prove
nargo verify
```

Extract the VK fields from `verification_key.json` and update `src/lib.rs`
before deploying to mainnet.

## Security notes

- The trusted setup produces toxic waste (τ, α, β, γ, δ scalars). These must
  be destroyed after the ceremony. Use a multi-party computation (MPC) ceremony
  for production to distribute trust.
- The circuit must be audited before the trusted setup. Any bug in the circuit
  invalidates the security of all proofs generated against it.
- The Poseidon parameters (round constants, MDS matrix) must match between the
  circuit and any off-chain nullifier computation.
