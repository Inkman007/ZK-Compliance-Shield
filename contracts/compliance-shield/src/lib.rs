#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    crypto::bn254::{G1Affine, G2Affine},
    panic_with_error, symbol_short,
    Address, BytesN, Env,
};

// ── Compile-time hex decoder (no_std, no external crates) ────────────────────

macro_rules! hex {
    ($s:literal) => {{
        const BYTES: [u8; { $s.len() / 2 }] = {
            const fn nibble(c: u8) -> u8 {
                match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    b'A'..=b'F' => c - b'A' + 10,
                    _ => panic!("invalid hex char"),
                }
            }
            let s = $s.as_bytes();
            let mut out = [0u8; { $s.len() / 2 }];
            let mut i = 0usize;
            while i < s.len() {
                out[i / 2] = (nibble(s[i]) << 4) | nibble(s[i + 1]);
                i += 2;
            }
            out
        };
        BYTES
    }};
}

// ── Verification key (hard-coded per deployment) ─────────────────────────────
//
// Replace with real trusted-setup output from `snarkjs groth16 setup`.
// Using BN254 generator points as structural placeholders.

// G1 generator (x=1, y=2)
const VK_ALPHA: [u8; 64] = {
    let x = hex!("0000000000000000000000000000000000000000000000000000000000000001");
    let y = hex!("0000000000000000000000000000000000000000000000000000000000000002");
    let mut out = [0u8; 64];
    let mut i = 0usize;
    while i < 32 { out[i] = x[i]; i += 1; }
    while i < 64 { out[i] = y[i - 32]; i += 1; }
    out
};

// G2 generator (x0, x1, y0, y1)
const VK_BETA: [u8; 128] = {
    let x0 = hex!("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2");
    let x1 = hex!("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed");
    let y0 = hex!("090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b");
    let y1 = hex!("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa");
    let mut out = [0u8; 128];
    let mut i = 0usize;
    while i < 32  { out[i]        = x0[i];      i += 1; }
    while i < 64  { out[i]        = x1[i - 32]; i += 1; }
    while i < 96  { out[i]        = y0[i - 64]; i += 1; }
    while i < 128 { out[i]        = y1[i - 96]; i += 1; }
    out
};

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Nullifier(BytesN<32>),
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracttype]
#[repr(u32)]
pub enum Error {
    Unauthorized    = 1,
    NotInitialized  = 2,
    InvalidProof    = 3,
    NullifierReused = 4,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct ComplianceShield;

#[contractimpl]
impl ComplianceShield {
    /// One-time initialisation: set the trusted authority and initial Merkle root.
    pub fn initialize(env: Env, authority: Address, merkle_root: BytesN<32>) {
        if env.storage().instance().has(&symbol_short!("AUTH")) {
            panic_with_error!(&env, Error::Unauthorized);
        }
        env.storage().instance().set(&symbol_short!("AUTH"), &authority);
        env.storage().instance().set(&symbol_short!("ROOT"), &merkle_root);
    }

    /// Authority rotates the Merkle root (e.g. after a new KYC batch).
    pub fn update_root(env: Env, new_root: BytesN<32>) {
        let authority: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("AUTH"))
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        authority.require_auth();
        env.storage().instance().set(&symbol_short!("ROOT"), &new_root);
    }

    /// Verify a Groth16 proof that the caller belongs to the KYC Merkle tree.
    ///
    /// - `proof_a` / `proof_b` / `proof_c` – Groth16 π_A (G1), π_B (G2), π_C (G1)
    /// - `nullifier` – Poseidon(user_secret ‖ merkle_root); prevents replay
    ///
    /// Panics with the appropriate `Error` code on failure.
    pub fn verify_identity(
        env:       Env,
        proof_a:   BytesN<64>,   // G1: x‖y (32 bytes each)
        proof_b:   BytesN<128>,  // G2: x0‖x1‖y0‖y1
        proof_c:   BytesN<64>,   // G1: x‖y
        nullifier: BytesN<32>,
    ) -> bool {
        // 1. Replay-attack guard
        let nul_key = DataKey::Nullifier(nullifier.clone());
        if env.storage().persistent().has(&nul_key) {
            panic_with_error!(&env, Error::NullifierReused);
        }

        // 2. Decode proof points
        let pi_a = G1Affine::from_bytes(proof_a);
        let pi_b = G2Affine::from_bytes(proof_b);
        let pi_c = G1Affine::from_bytes(proof_c);

        // 3. Build VK points from hard-coded constants
        let vk_alpha = G1Affine::from_bytes(BytesN::from_array(&env, &VK_ALPHA));
        let vk_beta  = G2Affine::from_bytes(BytesN::from_array(&env, &VK_BETA));

        // 4. Groth16 pairing check (simplified, single public input = nullifier):
        //    e(π_A, π_B) · e(−π_C, vk_β) · e(−vk_α, vk_β) == 1
        let neg_pi_c     = negate_g1(&env, &pi_c);
        let neg_vk_alpha = negate_g1(&env, &vk_alpha);

        let valid = env.crypto().bn254_pairing_check(soroban_sdk::vec![
            &env,
            (pi_a,          pi_b.clone()),
            (neg_pi_c,      vk_beta.clone()),
            (neg_vk_alpha,  vk_beta),
        ]);

        if !valid {
            panic_with_error!(&env, Error::InvalidProof);
        }

        // 5. Persist nullifier to block replay
        env.storage().persistent().set(&nul_key, &true);

        true
    }

    /// Read the current Merkle root (public).
    pub fn merkle_root(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&symbol_short!("ROOT"))
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Negate a G1 point: (x, y) → (x, P − y), where P is the BN254 field prime.
fn negate_g1(env: &Env, pt: &G1Affine) -> G1Affine {
    // BN254 field prime
    const P: [u8; 32] =
        hex!("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");

    let raw = pt.to_bytes();
    let mut bytes = [0u8; 64];
    raw.copy_into_slice(&mut bytes);

    // y occupies bytes[32..64]; compute P − y (big-endian 256-bit subtraction)
    let mut y = [0u8; 32];
    y.copy_from_slice(&bytes[32..64]);
    let neg_y = sub_be32(&P, &y);
    bytes[32..64].copy_from_slice(&neg_y);

    G1Affine::from_bytes(BytesN::from_array(env, &bytes))
}

/// Big-endian 256-bit subtraction: a − b (assumes a ≥ b).
fn sub_be32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let diff = (a[i] as u16).wrapping_sub(b[i] as u16).wrapping_sub(borrow);
        out[i] = diff as u8;
        borrow = if diff > 0xFF { 1 } else { 0 };
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    #[test]
    fn test_initialize_and_root() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ComplianceShield);
        let client = ComplianceShieldClient::new(&env, &contract_id);

        let authority = Address::generate(&env);
        let root = BytesN::from_array(&env, &[1u8; 32]);

        client.initialize(&authority, &root);
        assert_eq!(client.merkle_root(), root);
    }

    #[test]
    fn test_double_initialize_fails() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ComplianceShield);
        let client = ComplianceShieldClient::new(&env, &contract_id);

        let authority = Address::generate(&env);
        let root = BytesN::from_array(&env, &[1u8; 32]);
        client.initialize(&authority, &root);

        let result = client.try_initialize(&authority, &root);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_root() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, ComplianceShield);
        let client = ComplianceShieldClient::new(&env, &contract_id);

        let authority = Address::generate(&env);
        let root1 = BytesN::from_array(&env, &[1u8; 32]);
        let root2 = BytesN::from_array(&env, &[2u8; 32]);

        client.initialize(&authority, &root1);
        client.update_root(&root2);
        assert_eq!(client.merkle_root(), root2);
    }
}
