# ZK-Compliance-Shield

A **privacy-preserving KYC compliance layer** built on Stellar's Soroban smart-contract platform.  
Institutions can verify that a user is KYC-approved **without storing any PII on-chain**.

---

## How it works

```
Off-chain (Institution / KYC Provider)          On-chain (Soroban)
─────────────────────────────────────           ──────────────────────────────
1. Hash each verified user:                     Authority stores:
   user_hash = Poseidon(KYC_data)                 merkle_root  ← root of all user_hashes

2. Build a Merkle tree of user_hashes

3. For a user who wants to prove membership:
   a. Compute nullifier = SHA-256(user_secret ‖ merkle_root)
   b. Generate Groth16 proof π that:
      "I know a user_hash in the tree AND
       I know the pre-image of this nullifier"

4. Submit (π_A, π_B, π_C, nullifier) → verify_identity()
                                                Contract:
                                                  • checks nullifier not reused
                                                  • calls bn254_pairing_check()
                                                  • records nullifier on success
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
| 3 | Invalid ZK proof |
| 4 | Nullifier already used (replay attack) |

---

## Proof format

All values are **big-endian hex, no `0x` prefix**.

| Field | Size | Curve point |
|---|---|---|
| `proof_a` | 64 bytes | G1 (x ‖ y) |
| `proof_b` | 128 bytes | G2 (x₀ ‖ x₁ ‖ y₀ ‖ y₁) |
| `proof_c` | 64 bytes | G1 |
| `nullifier` | 32 bytes | SHA-256(user\_secret ‖ merkle\_root) |

The verification key (α, β, γ, δ) is **hard-coded** in the contract at deployment time from the trusted-setup ceremony output.

---

## Pairing equation

The contract verifies the standard Groth16 equation using `env.crypto().bn254_pairing_check()`:

```
e(π_A, π_B) · e(−π_C, vk_δ) · e(−vk_α, vk_β) == 1
```

Point negation on G1 is computed as `(x, P − y)` where `P` is the BN254 field prime.

---

## Quick start

### 1. Build the contract

```bash
cargo build --target wasm32-unknown-unknown --release -p compliance-shield
```

### 2. Deploy (Testnet)

```bash
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/compliance_shield.wasm \
  --source <YOUR_KEY> \
  --network testnet
```

### 3. Initialize

```bash
stellar contract invoke --id <CONTRACT_ID> --source <AUTHORITY_KEY> \
  --network testnet -- initialize \
  --authority <AUTHORITY_ADDRESS> \
  --merkle_root <32_BYTE_HEX_ROOT>
```

### 4. Generate a mock proof

```bash
python3 scripts/mock_proof_generator.py
```

The script prints the proof fields and a ready-to-paste `stellar contract invoke` command.

### 5. Verify identity

```bash
stellar contract invoke --id <CONTRACT_ID> --source <USER_KEY> \
  --network testnet -- verify_identity \
  --proof_a  <64_BYTE_HEX> \
  --proof_b  <128_BYTE_HEX> \
  --proof_c  <64_BYTE_HEX> \
  --nullifier <32_BYTE_HEX>
```

---

## Production checklist

- [ ] Replace mock VK constants with real trusted-setup output (e.g. from `snarkjs groth16 setup`)
- [ ] Replace `mock_proof_generator.py` with a real Groth16 prover circuit
- [ ] Use Poseidon hash (not SHA-256) for the nullifier to match the ZK circuit
- [ ] Store the VK in contract storage (updatable by authority) instead of hard-coding
- [ ] Add an expiry / epoch to nullifiers if periodic re-verification is required

---

## Security properties

| Property | Mechanism |
|---|---|
| **Privacy** | ZK proof reveals nothing about the user's identity |
| **Soundness** | BN254 pairing check — forgery requires breaking the discrete-log assumption |
| **Replay prevention** | Nullifier stored persistently; second use panics with error 4 |
| **Authority control** | Only the designated authority can rotate the Merkle root |
