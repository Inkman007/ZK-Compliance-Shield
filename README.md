# ZK-Compliance-Shield

[![CI](https://github.com/Inkman007/ZK-Compliance-Shield/actions/workflows/ci.yml/badge.svg)](https://github.com/Inkman007/ZK-Compliance-Shield/actions/workflows/ci.yml)

A **privacy-preserving KYC compliance layer** built on Stellar Protocol 25 (X-Ray).  
Institutions verify that a user is KYC-approved **without storing any PII on-chain**.

Built with **Soroban SDK v26** and the native BN254 host functions introduced in Protocol 25.

---

## Table of contents

- [How it works](#how-it-works)
- [Project structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Contract API](#contract-api)
- [Proof format](#proof-format)
- [Groth16 verification equation](#groth16-verification-equation)
- [Verification key](#verification-key)
- [Storage & TTL](#storage--ttl)
- [Events](#events)
- [Security properties](#security-properties)
- [Production checklist](#production-checklist)
- [References](#references)

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
                                                  • emits identity_verified event
```

No address, no name, no document number ever touches the chain.

---

## Project structure

```
ZK-Compliance-Shield/
├── contracts/
│   └── compliance-shield/
│       ├── Cargo.toml
│       └── src/
│           └── lib.rs          # Soroban contract (Groth16 verifier)
├── docs/
│   ├── architecture.md         # Component diagram, storage layout, event schema
│   └── circuit-spec.md         # Groth16 circuit spec, VK format, trusted setup guide
├── scripts/
│   ├── deploy.sh               # Build → deploy → initialize in one command
│   ├── mock_proof_generator.py # Outputs EIP-197 test vector proof for ABI testing
│   └── requirements.txt        # Python dependency manifest
├── .cargo/
│   └── config.toml             # Default build target: wasm32v1-none
├── .github/
│   ├── workflows/ci.yml        # CI: fmt + clippy + test + wasm build
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── Cargo.toml                  # Workspace root
├── rust-toolchain.toml         # Pinned: Rust 1.82.0 + wasm32v1-none
├── CHANGELOG.md
└── SECURITY.md
```

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | 1.82.0 (pinned) | `rustup toolchain install 1.82.0` |
| wasm32v1-none target | — | `rustup target add wasm32v1-none` |
| Stellar CLI | latest | [docs.stellar.org/tools/cli](https://developers.stellar.org/docs/tools/cli) |
| Python | 3.9+ | For `scripts/mock_proof_generator.py` |

The `rust-toolchain.toml` file pins the toolchain automatically — `cargo` will install it on first use.

---

## Quick start

### 1. Clone and build

```bash
git clone https://github.com/Inkman007/ZK-Compliance-Shield.git
cd ZK-Compliance-Shield
cargo build --workspace --target wasm32v1-none --release
```

### 2. Run tests

```bash
cargo test --workspace
```

### 3. Deploy with one command

```bash
# Usage: ./scripts/deploy.sh <network> <authority_address> <merkle_root_hex>
STELLAR_SOURCE_KEY=my-key ./scripts/deploy.sh testnet GAUTH... 1a2b3c4d...
```

Or step by step:

**Deploy:**
```bash
stellar contract deploy \
  --wasm target/wasm32v1-none/release/compliance_shield.wasm \
  --source <YOUR_KEY> \
  --network testnet
```

**Initialize:**
```bash
stellar contract invoke --id <CONTRACT_ID> --source <AUTHORITY_KEY> \
  --network testnet -- initialize \
  --authority <AUTHORITY_ADDRESS> \
  --merkle_root <32_BYTE_HEX_ROOT>
```

### 4. Generate a test proof

```bash
# Outputs the canonical EIP-197 jeff1 test vector (structural ABI test)
python3 scripts/mock_proof_generator.py test

# Outputs a mock proof with a random nullifier
python3 scripts/mock_proof_generator.py mock
```

### 5. Verify identity

```bash
stellar contract invoke --id <CONTRACT_ID> --source <USER_KEY> \
  --network testnet -- verify_identity \
  --proof_a   <64_BYTE_HEX> \
  --proof_b   <128_BYTE_HEX> \
  --proof_c   <64_BYTE_HEX> \
  --nullifier <32_BYTE_HEX>
```

---

## Contract API

| Function | Caller | Returns | Description |
|---|---|---|---|
| `initialize(authority, merkle_root)` | Deployer (once) | `()` | Set trusted authority and initial root |
| `update_root(new_root)` | Authority | `()` | Rotate root after a new KYC batch |
| `verify_identity(proof_a, proof_b, proof_c, nullifier)` | Any user | `()` | Verify Groth16 proof; records nullifier; emits event |
| `merkle_root()` | Anyone | `BytesN<32>` | Read current Merkle root |

All state-changing functions return `()` and panic with a typed error code on failure.

### Error codes

| Code | Constant | Meaning |
|---|---|---|
| 1 | `Unauthorized` | Wrong caller, or contract already initialized |
| 2 | `NotInitialized` | Contract has not been initialized |
| 3 | `InvalidProof` | Groth16 pairing check failed |
| 4 | `NullifierReused` | Nullifier already used — replay attack blocked |

---

## Proof format

All values are **big-endian hex, no `0x` prefix**.

| Field | Bytes | Curve element | Description |
|---|---|---|---|
| `proof_a` | 64 | G1 (x‖y) | Groth16 π_A |
| `proof_b` | 128 | G2 (x₀‖x₁‖y₀‖y₁) | Groth16 π_B |
| `proof_c` | 64 | G1 (x‖y) | Groth16 π_C |
| `nullifier` | 32 | Fr scalar | Poseidon(user\_secret ‖ merkle\_root) |

---

## Groth16 verification equation

The contract calls `env.crypto().bn254().pairing_check()` with four pairs:

```
e(π_A, π_B) · e(−vk_α, vk_β) · e(−vk_x, vk_γ) · e(−π_C, vk_δ) == 1
```

The **public input accumulator** binds the proof to the submitted nullifier:

```
vk_x = IC[0] + nullifier · IC[1]
```

G1 negation uses the Soroban SDK's `Neg` trait — no manual field arithmetic.

---

## Verification key

The VK (`vk_α`, `vk_β`, `vk_γ`, `vk_δ`, `IC[0]`, `IC[1]`) is hard-coded as
compile-time `const` arrays in `src/lib.rs`, decoded at compile time with zero
runtime cost.

**Current values:** Real, curve-valid BN254 points sourced from the
[Ethereum EIP-197 canonical test vectors](https://github.com/ethereum/go-ethereum/blob/master/core/vm/testdata/precompiles/bn256Pairing.json)
(`jeff1` test case). These are structurally correct — the contract will not
panic on point decoding — but they are **not a real circuit VK**.

**Before mainnet:** replace all `VK_*` constants with the output of your
trusted-setup ceremony. See [`docs/circuit-spec.md`](docs/circuit-spec.md) for
the exact format and tooling (`snarkjs groth16 setup` / Noir / bellman).

---

## Storage & TTL

| Key | Type | Storage | TTL policy |
|---|---|---|---|
| `DataKey::Authority` | `Address` | Instance | Bumped to ~1 year on every write |
| `DataKey::MerkleRoot` | `BytesN<32>` | Instance | Bumped to ~1 year on every write |
| `DataKey::Nullifier(n)` | `bool` | Persistent | Bumped to ~1 year on every successful verification |

Nullifiers use `persistent` storage with TTL bumped to **~1 year (6,307,200 ledgers)**
on every successful verification. This prevents expiry-based replay attacks.
Instance storage is also bumped on every write to prevent contract expiry.

---

## Events

All events contain zero PII. Subscribe to these for compliance dashboards and monitoring.

| Topics | Data | Emitted by |
|---|---|---|
| `("init", "shield")` | `merkle_root: BytesN<32>` | `initialize` |
| `("root", "updated")` | `new_root: BytesN<32>` | `update_root` |
| `("identity", "verified")` | `nullifier: BytesN<32>` | `verify_identity` |

---

## Security properties

| Property | Mechanism |
|---|---|
| **Privacy** | ZK proof reveals nothing about the user's identity |
| **Soundness** | BN254 pairing check — forgery requires breaking the discrete-log assumption |
| **Input binding** | Public input accumulator ties the proof to the submitted nullifier |
| **Replay prevention** | Nullifier stored persistently with ~1-year TTL; second use panics with error 4 |
| **Authority control** | Only the designated authority can rotate the Merkle root |
| **Contract liveness** | Instance storage TTL bumped on every write — contract cannot silently expire |

---

## Production checklist

- [ ] Write the KYC membership circuit (Noir / circom / bellman)
- [ ] Run a trusted-setup ceremony (`snarkjs groth16 setup` or MPC ceremony)
- [ ] Replace all `VK_*` constants in `src/lib.rs` with ceremony output
- [ ] Replace `mock_proof_generator.py` with a real Groth16 prover
- [ ] Use `env.crypto().bn254().poseidon()` for the nullifier (matches ZK circuit)
- [ ] Audit the contract and circuit before mainnet deployment
- [ ] Add an epoch to nullifiers if periodic re-verification is required
- [ ] Consider storing the VK in contract storage for key rotation without redeployment

---

## References

- [Stellar Protocol 25 (X-Ray) announcement](https://stellar.org/blog/developers/announcing-stellar-x-ray-protocol-25)
- [ZK Proofs on Stellar — official docs](https://developers.stellar.org/docs/build/apps/zk)
- [Soroban SDK v26 BN254 API](https://docs.rs/soroban-sdk/latest/soroban_sdk/_migrating/v25_bn254/index.html)
- [CAP-74: BN254 host functions](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0074.md)
- [CAP-75: Poseidon host functions](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0075.md)
- [Noir Ultrahonk Soroban Verifier](https://github.com/indextree/ultrahonk_soroban_contract)
- [EIP-197: BN254 pairing precompile](https://eips.ethereum.org/EIPS/eip-197)
- [Ethereum bn256Pairing test vectors](https://github.com/ethereum/go-ethereum/blob/master/core/vm/testdata/precompiles/bn256Pairing.json)
