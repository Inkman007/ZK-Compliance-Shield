#!/usr/bin/env python3
"""
Mock Groth16 proof generator for ZK-Compliance-Shield.

Produces structurally valid BN254-encoded byte strings that match the
contract's `verify_identity` ABI.  The points are NOT on the curve and
will NOT pass the real pairing check — this is intentional for local
development and integration testing.

Replace with a real Groth16 prover (snarkjs / bellman / Noir) for production.

Contract interface:
  verify_identity(proof_a: BytesN<64>, proof_b: BytesN<128>,
                  proof_c: BytesN<64>, nullifier: BytesN<32>) -> bool

All values are big-endian hex, no 0x prefix.
"""

import hashlib
import json
import secrets

# BN254 field prime
P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47


def _fake_g1(seed: bytes) -> str:
    """Deterministic fake G1 point (64 bytes = x‖y, 32 bytes each)."""
    h = int.from_bytes(hashlib.sha256(seed).digest(), "big") % P
    x = h.to_bytes(32, "big")
    y = ((h + 1) % P).to_bytes(32, "big")
    return (x + y).hex()


def _fake_g2(seed: bytes) -> str:
    """Deterministic fake G2 point (128 bytes = x0‖x1‖y0‖y1)."""
    h = int.from_bytes(hashlib.sha256(seed).digest(), "big") % P
    coords = [(h + i) % P for i in range(4)]
    return b"".join(c.to_bytes(32, "big") for c in coords).hex()


def generate_proof(user_secret: bytes, merkle_root: bytes) -> dict:
    """
    Generate a mock proof for the given user secret and Merkle root.

    The nullifier is SHA-256(user_secret ‖ merkle_root).
    In production use Poseidon(user_secret ‖ merkle_root) to match the circuit.
    """
    nullifier = hashlib.sha256(user_secret + merkle_root).digest()
    return {
        "proof_a":   _fake_g1(b"proof_a" + user_secret),
        "proof_b":   _fake_g2(b"proof_b" + user_secret),
        "proof_c":   _fake_g1(b"proof_c" + user_secret),
        "nullifier": nullifier.hex(),
    }


if __name__ == "__main__":
    user_secret = secrets.token_bytes(32)
    merkle_root = bytes.fromhex("1a2b3c4d" * 8)  # replace with real root

    proof = generate_proof(user_secret, merkle_root)

    print(json.dumps(proof, indent=2))
    print(
        "\n# Invoke the contract:\n"
        "stellar contract invoke --id <CONTRACT_ID> --source <KEY> "
        "--network testnet -- verify_identity \\\n"
        f"  --proof_a   {proof['proof_a']} \\\n"
        f"  --proof_b   {proof['proof_b']} \\\n"
        f"  --proof_c   {proof['proof_c']} \\\n"
        f"  --nullifier {proof['nullifier']}"
    )
