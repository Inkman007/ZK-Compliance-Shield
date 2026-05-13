#!/usr/bin/env python3
"""
Mock Groth16 proof generator for ZK-Compliance-Shield.

Produces deterministic fake BN254 curve points that satisfy the
bn254_pairing_check ABI expected by the Soroban contract.
In production, replace with a real Groth16 prover (e.g. snarkjs / bellman).

Output format (all values are big-endian hex, no 0x prefix):
  proof_a  : 64 bytes  (G1 point: x‖y, 32 bytes each)
  proof_b  : 128 bytes (G2 point: x0‖x1‖y0‖y1, 32 bytes each)
  proof_c  : 64 bytes  (G1 point)
  vk_alpha : 64 bytes  (G1)
  vk_beta  : 128 bytes (G2)
  vk_gamma : 128 bytes (G2)
  vk_delta : 128 bytes (G2)
  nullifier: 32 bytes  (Poseidon hash of user_secret ‖ merkle_root)
"""

import hashlib
import json
import secrets
import sys

# BN254 field modulus
P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47

def _fake_g1(seed: bytes) -> tuple[int, int]:
    """Return a deterministic fake G1 point (not on curve – mock only)."""
    h = int.from_bytes(hashlib.sha256(seed).digest(), "big") % P
    return h, (h + 1) % P

def _fake_g2(seed: bytes) -> tuple[int, int, int, int]:
    """Return a deterministic fake G2 point (mock only)."""
    h = int.from_bytes(hashlib.sha256(seed).digest(), "big") % P
    return h, (h+1)%P, (h+2)%P, (h+3)%P

def _enc32(n: int) -> str:
    return n.to_bytes(32, "big").hex()

def generate_proof(user_secret: bytes, merkle_root: bytes) -> dict:
    nullifier_preimage = user_secret + merkle_root
    nullifier = hashlib.sha256(nullifier_preimage).digest()

    a  = _fake_g1(b"proof_a"  + user_secret)
    b  = _fake_g2(b"proof_b"  + user_secret)
    c  = _fake_g1(b"proof_c"  + user_secret)
    va = _fake_g1(b"vk_alpha" + merkle_root)
    vb = _fake_g2(b"vk_beta"  + merkle_root)
    vg = _fake_g2(b"vk_gamma" + merkle_root)
    vd = _fake_g2(b"vk_delta" + merkle_root)

    return {
        "proof_a":   _enc32(a[0]) + _enc32(a[1]),
        "proof_b":   _enc32(b[0]) + _enc32(b[1]) + _enc32(b[2]) + _enc32(b[3]),
        "proof_c":   _enc32(c[0]) + _enc32(c[1]),
        "vk_alpha":  _enc32(va[0]) + _enc32(va[1]),
        "vk_beta":   _enc32(vb[0]) + _enc32(vb[1]) + _enc32(vb[2]) + _enc32(vb[3]),
        "vk_gamma":  _enc32(vg[0]) + _enc32(vg[1]) + _enc32(vg[2]) + _enc32(vg[3]),
        "vk_delta":  _enc32(vd[0]) + _enc32(vd[1]) + _enc32(vd[2]) + _enc32(vd[3]),
        "nullifier": nullifier.hex(),
    }

if __name__ == "__main__":
    # Demo: random user secret, fixed mock merkle root
    user_secret  = secrets.token_bytes(32)
    merkle_root  = bytes.fromhex(
        "1a2b3c4d" * 8  # 32-byte placeholder; replace with real root
    )
    proof = generate_proof(user_secret, merkle_root)
    print(json.dumps(proof, indent=2))
    print(f"\n# Pass to contract:\n"
          f"stellar contract invoke ... -- \\\n"
          f"  --proof_a {proof['proof_a']} \\\n"
          f"  --proof_b {proof['proof_b']} \\\n"
          f"  --proof_c {proof['proof_c']} \\\n"
          f"  --vk_alpha {proof['vk_alpha']} \\\n"
          f"  --vk_beta {proof['vk_beta']} \\\n"
          f"  --vk_gamma {proof['vk_gamma']} \\\n"
          f"  --vk_delta {proof['vk_delta']} \\\n"
          f"  --nullifier {proof['nullifier']}")
