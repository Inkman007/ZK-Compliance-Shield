# Architecture

## Overview

ZK-Compliance-Shield is a Soroban smart contract that enables privacy-preserving
KYC verification on Stellar Protocol 25 (X-Ray). It uses Groth16 zero-knowledge
proofs over the BN254 curve to prove Merkle tree membership without revealing
any user identity.

## Component diagram

```
┌─────────────────────────────────────────────────────────────────┐
│  Off-chain                                                       │
│                                                                  │
│  KYC Provider                    User (Prover)                  │
│  ┌──────────────┐                ┌──────────────────────────┐   │
│  │ 1. Hash PII  │                │ 3. Generate Groth16 proof│   │
│  │    Poseidon  │                │    π = prove(            │   │
│  │    (KYC_data)│                │      user_hash ∈ tree,   │   │
│  │              │                │      nullifier preimage  │   │
│  │ 2. Build     │                │    )                     │   │
│  │    Merkle    │                │                          │   │
│  │    tree      │                │ 4. nullifier =           │   │
│  │              │                │    Poseidon(secret‖root) │   │
│  └──────┬───────┘                └──────────┬───────────────┘   │
│         │ merkle_root                        │ (π_A,π_B,π_C,    │
│         │                                    │  nullifier)       │
└─────────┼────────────────────────────────────┼───────────────────┘
          │                                    │
          ▼                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│  On-chain (Soroban / Stellar Protocol 25)                        │
│                                                                  │
│  ComplianceShield Contract                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                                                           │  │
│  │  initialize(authority, merkle_root)                       │  │
│  │    └─ stores Authority + MerkleRoot in instance storage   │  │
│  │                                                           │  │
│  │  update_root(new_root)          [authority only]          │  │
│  │    └─ rotates MerkleRoot, emits root_updated event        │  │
│  │                                                           │  │
│  │  verify_identity(π_A, π_B, π_C, nullifier)               │  │
│  │    ├─ check nullifier not in persistent storage           │  │
│  │    ├─ compute vk_x = IC[0] + nullifier * IC[1]           │  │
│  │    ├─ bn254.pairing_check(                                │  │
│  │    │    [π_A, -vk_α, -vk_x, -π_C],                       │  │
│  │    │    [π_B,  vk_β,  vk_γ,  vk_δ]                       │  │
│  │    │  ) == true                                           │  │
│  │    ├─ store nullifier in persistent storage + bump TTL    │  │
│  │    └─ emit identity_verified event                        │  │
│  │                                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Storage layout

| Key | Storage type | TTL policy | Description |
|-----|-------------|------------|-------------|
| `DataKey::Authority` | Instance | Bumped on every write | Trusted authority address |
| `DataKey::MerkleRoot` | Instance | Bumped on every write | Current KYC Merkle root |
| `DataKey::Nullifier(n)` | Persistent | ~1 year, bumped on write | Spent nullifier (replay guard) |

## Verification key lifecycle

```
Trusted Setup Ceremony (off-chain)
  └─ snarkjs groth16 setup / bellman / Noir
       └─ outputs: vk_alpha, vk_beta, vk_gamma, vk_delta, IC[0], IC[1]
            └─ hard-coded as const [u8; N] in src/lib.rs
                 └─ compiled into WASM at build time (zero runtime cost)
```

For key rotation, the VK must be embedded in a new contract deployment.
An alternative is to store the VK in instance storage (updatable by authority),
at the cost of additional storage reads on every verification call.

## Event schema

| Event | Topics | Data | Emitted by |
|-------|--------|------|------------|
| `init / shield` | `("init", "shield")` | `merkle_root: BytesN<32>` | `initialize` |
| `root / updated` | `("root", "updated")` | `new_root: BytesN<32>` | `update_root` |
| `identity / verified` | `("identity", "verified")` | `nullifier: BytesN<32>` | `verify_identity` |

Events contain no PII. The nullifier is a one-way hash of the user secret.
