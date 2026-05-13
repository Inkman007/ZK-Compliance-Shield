# ZK-Compliance-Shield

[![CI](https://github.com/Inkman007/ZK-Compliance-Shield/actions/workflows/ci.yml/badge.svg)](https://github.com/Inkman007/ZK-Compliance-Shield/actions/workflows/ci.yml)

A **privacy-preserving KYC compliance layer** built on Stellar Protocol 25 (X-Ray).  
Institutions verify that a user is KYC-approved **without storing any PII on-chain**.

Built with Soroban SDK v26 and the native BN254 host functions introduced in Protocol 25.

---

## How it works

```
Off-chain (Institution / KYC Provider)          On-chain (Soroban)
─────────────────────────────────────           ──────────────────────────────
1. Hash each verified user:                     Authority stores:
   user_hash = Poseidon(KYC_data)                 merkle_root  ← root of all user_hashes

2. Build a Merkle tree of user_hashes

3. For a user who wants to prove membership:
   a. Compute nullifier = Poseidon(user_secret ‖ merkle_root)
   b. Generate Groth16 proof π that:
      "I know a user_hash in the tree AND
       I know the pre-image of this nullifier"

4. Submit (π_A, π_B, π_C, nullifier) → verify_identity()
                                                Contract:
                                                  • checks nullifier not reused
                                                  • computes vk_x = IC[0] + nullifier·IC[1]
                                                  • calls bn254.pairing_check()
                                                  • records nullifier + bumps TTL
```

No address, no name, no document number ever touches the chain.

---

## Contract API

| Function | Who calls | Description |
|---|---|---|
| `initialize(authority, merkle_root)` | Deployer (once) | Set trusted authority and initial root |
| `update_root(new_root)` | Authority | Rotate root after a new KYC batch |
| `verify_identity(proof_a, proof_b, proof_c, nullifier)` | Any user | Verify Groth16 proof; records nullifier |
| `merkle_root()` | Anyone | Read current root |

### Error codes

| Code | Meaning |
|---|---|
| 1 | Unauthorized (wrong caller or already initialized) |
| 2 | Contract not initialized |
| 3 | Invalid ZK proof (pairing check failed) |
| 4 | Nullifier already used (replay attack) |

---

## Proof format

All values are **big-endian hex, no `0x` prefix**.

| Field | Size | Description |
|---|---|---|
| `proof_a` | 64 bytes | G1 point π_A (x‖y) |
| `proof_b` | 128 bytes | G2 point π_B (x₀‖x₁‖y₀‖y₁) |
| `proof_c` | 64 bytes | G1 point π_C (x‖y) |
| `nullifier` | 32 bytes | Poseidon(user\_secret ‖ merkle\_root) as big-endian scalar |

---

## Groth16 verification equation

```
e(π_A, π_B) · e(−vk_α, vk_β) · e(−vk_x, vk_γ) · e(−π_C, vk_δ) == 1
```

where the **public input accumulator** is:

```
vk_x = IC[0] + nullifier · IC[1]
```

This binds the proof to the specific nullifier value submitted on-chain.  
G1 negation uses the SDK's `Neg` trait — no manual field arithmetic.

---

## Verification key

The VK (`vk_α`, `vk_β`, `vk_γ`, `vk_δ`, `IC[0]`, `IC[1]`) is hard-coded as
compile-time constants in `src/lib.rs`.  The current values are BN254 generator
points used as structural placeholders.

**Before mainnet:** replace all `VK_*` constants with the output of your
trusted-setup ceremony (`snarkjs groth16 setup` or equivalent).

---

## Storage & TTL

| Key | Type | Storage | Notes |
|---|---|---|---|
| `DataKey::Authority` | `Address` | Instance | Set once at init |
| `DataKey::MerkleRoot` | `BytesN<32>` | Instance | Updated by authority |
| `DataKey::Nullifier(n)` | `bool` | Persistent | TTL extended to ~1 year on write |

Nullifiers use `persistent` storage and have their TTL bumped to **~1 year
(6,307,200 ledgers)** on every successful verification.  This prevents
expiry-based replay attacks.

---

## Quick start

### 1. Build

```bash
cargo build --workspace --target wasm32v1-none --release
```

### 2. Deploy (Futurenet / Testnet)

```bash
stellar contract deploy \
  --wasm target/wasm32v1-none/release/compliance_shield.wasm \
  --source <YOUR_KEY> \
  --network futurenet
```

### 3. Initialize

```bash
stellar contract invoke --id <CONTRACT_ID> --source <AUTHORITY_KEY> \
  --network futurenet -- initialize \
  --authority <AUTHORITY_ADDRESS> \
  --merkle_root <32_BYTE_HEX_ROOT>
```

### 4. Generate a mock proof

```bash
python3 scripts/mock_proof_generator.py
```

### 5. Verify identity

```bash
stellar contract invoke --id <CONTRACT_ID> --source <USER_KEY> \
  --network futurenet -- verify_identity \
  --proof_a   <64_BYTE_HEX> \
  --proof_b   <128_BYTE_HEX> \
  --proof_c   <64_BYTE_HEX> \
  --nullifier <32_BYTE_HEX>
```

---

## Production checklist

- [ ] Replace `VK_*` constants with real trusted-setup output (`snarkjs groth16 setup`)
- [ ] Replace `mock_proof_generator.py` with a real Groth16 prover (Noir / Risc0)
- [ ] Use `env.crypto().bn254().poseidon()` for the nullifier to match the ZK circuit
- [ ] Consider storing the VK in contract storage (updatable by authority) for key rotation
- [ ] Add an epoch to nullifiers if periodic re-verification is required

---

## Security properties

| Property | Mechanism |
|---|---|
| **Privacy** | ZK proof reveals nothing about the user's identity |
| **Soundness** | BN254 pairing check — forgery requires breaking the discrete-log assumption |
| **Input binding** | Public input accumulator ties the proof to the submitted nullifier |
| **Replay prevention** | Nullifier stored persistently with ~1-year TTL; second use panics with error 4 |
| **Authority control** | Only the designated authority can rotate the Merkle root |

---

## References

- [Stellar Protocol 25 (X-Ray) announcement](https://stellar.org/blog/developers/announcing-stellar-x-ray-protocol-25)
- [ZK Proofs on Stellar — official docs](https://developers.stellar.org/docs/build/apps/zk)
- [Soroban SDK v26 BN254 API](https://docs.rs/soroban-sdk/latest/soroban_sdk/_migrating/v25_bn254/index.html)
- [CAP-74: BN254 host functions](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0074.md)
- [Noir Ultrahonk Soroban Verifier](https://github.com/indextree/ultrahonk_soroban_contract)
