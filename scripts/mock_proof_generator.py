#!/usr/bin/env python3
"""
Mock Groth16 proof generator for ZK-Compliance-Shield.

Outputs the Ethereum EIP-197 "jeff1" test vector — a real, curve-valid BN254
proof that satisfies e(A,B)·e(C,D) = 1.  This is used for structural testing
of the contract's ABI and encoding, NOT as a real KYC proof.

For production, replace this script with a real Groth16 prover that:
  1. Runs the KYC membership circuit (Noir / bellman / snarkjs)
  2. Uses the VK from your trusted-setup ceremony
  3. Computes nullifier = Poseidon(user_secret ‖ merkle_root)

All values are big-endian hex, no 0x prefix.
Contract interface: verify_identity(proof_a, proof_b, proof_c, nullifier)
"""

import hashlib
import json
import secrets

# ── Real BN254 points from Ethereum EIP-197 "jeff1" test vector ──────────────
# Source: go-ethereum/core/vm/testdata/precompiles/bn256Pairing.json
# These satisfy: e(PROOF_A, PROOF_B) · e(PROOF_C_NEG, VK_BETA) = 1

# pair-0 G1 (πA)
PROOF_A = (
    "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59"
    "3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41"
)

# pair-0 G2 (πB)
PROOF_B = (
    "209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7"
    "04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678"
    "2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d"
    "120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550"
)

# pair-1 G1 (πC) — the negated form used in the pairing equation
PROOF_C = (
    "111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c"
    "2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411"
)

# Nullifier = 0 → vk_x = IC[0] + 0*IC[1] = IC[0]
# This matches the VK construction in src/lib.rs.
NULLIFIER = "00" * 32


def generate_test_proof() -> dict:
    """Return the canonical jeff1 test proof (structural test only)."""
    return {
        "proof_a":   PROOF_A,
        "proof_b":   PROOF_B,
        "proof_c":   PROOF_C,
        "nullifier": NULLIFIER,
    }


def generate_mock_proof(user_secret: bytes, merkle_root: bytes) -> dict:
    """
    Generate a mock proof with a real nullifier but fake curve points.
    The nullifier is SHA-256(user_secret ‖ merkle_root).
    In production use Poseidon(user_secret ‖ merkle_root).
    This proof will NOT pass the pairing check — use for ABI testing only.
    """
    nullifier = hashlib.sha256(user_secret + merkle_root).hexdigest()
    return {
        "proof_a":   PROOF_A,   # reuse real points for valid encoding
        "proof_b":   PROOF_B,
        "proof_c":   PROOF_C,
        "nullifier": nullifier,
    }


if __name__ == "__main__":
    import sys

    mode = sys.argv[1] if len(sys.argv) > 1 else "test"

    if mode == "test":
        proof = generate_test_proof()
        print("# jeff1 canonical test proof (nullifier=0, matches VK in src/lib.rs)")
    else:
        user_secret = secrets.token_bytes(32)
        merkle_root = bytes.fromhex("1a2b3c4d" * 8)
        proof = generate_mock_proof(user_secret, merkle_root)
        print("# Mock proof with random nullifier (will NOT pass pairing check)")

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
