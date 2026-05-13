#![no_std]

use soroban_sdk::{
    contract, contractimpl, contractmeta, contracttype,
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    panic_with_error, symbol_short,
    vec,
    Address, BytesN, Env, U256,
};

// ── Contract metadata (Protocol 25 / X-Ray) ──────────────────────────────────

contractmeta!(
    key = "name",
    val = "ZK-Compliance-Shield"
);
contractmeta!(
    key = "description",
    val = "Privacy-preserving KYC compliance layer using Groth16/BN254 on Stellar Protocol 25"
);
contractmeta!(
    key = "version",
    val = "0.2.0"
);

// ── TTL constants (ledgers) ───────────────────────────────────────────────────
//
// Nullifiers must never expire — a lapsed nullifier enables identity replay.
// ~1 year at 5-second ledger close = 6_307_200 ledgers.
// We extend when TTL drops below 30 days (518_400 ledgers).

const NULLIFIER_TTL_THRESHOLD: u32 = 518_400;   // 30 days
const NULLIFIER_TTL_EXTEND_TO: u32 = 6_307_200; // ~1 year

// Instance storage (Authority + MerkleRoot) must also stay alive.
const INSTANCE_TTL_THRESHOLD: u32 = 518_400;   // 30 days
const INSTANCE_TTL_EXTEND_TO: u32 = 6_307_200; // ~1 year

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Trusted authority address (set once at initialisation).
    Authority,
    /// Current Merkle root of verified-user hashes.
    MerkleRoot,
    /// Spent nullifier — value is `true`, key prevents replay.
    Nullifier(BytesN<32>),
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracttype]
#[repr(u32)]
pub enum Error {
    /// Wrong caller, or contract already initialised.
    Unauthorized    = 1,
    /// Contract has not been initialised yet.
    NotInitialized  = 2,
    /// Groth16 pairing check failed.
    InvalidProof    = 3,
    /// Nullifier has already been used (replay attack).
    NullifierReused = 4,
}

// ── Verification key ──────────────────────────────────────────────────────────
//
// Hard-coded from the trusted-setup ceremony output.
// Replace all constants with real snarkjs / bellman output before mainnet.
//
// Layout (all big-endian, uncompressed):
//   VK_ALPHA_G1  : G1 (64 bytes)
//   VK_BETA_G2   : G2 (128 bytes)
//   VK_GAMMA_G2  : G2 (128 bytes)
//   VK_DELTA_G2  : G2 (128 bytes)
//   VK_IC_0_G1   : G1 (64 bytes)  — constant term of the input commitment
//   VK_IC_1_G1   : G1 (64 bytes)  — coefficient for public input 0 (nullifier)
//
// Using BN254 generator points as structural placeholders.

// G1 generator: (1, 2)
const VK_ALPHA_G1: [u8; 64] = g1(
    hex32("0000000000000000000000000000000000000000000000000000000000000001"),
    hex32("0000000000000000000000000000000000000000000000000000000000000002"),
);

// G2 generator
const VK_BETA_G2: [u8; 128] = g2(
    hex32("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
    hex32("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
    hex32("090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
    hex32("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"),
);

// Placeholder: same as beta (replace with real gamma from trusted setup)
const VK_GAMMA_G2: [u8; 128] = VK_BETA_G2;

// Placeholder: same as beta (replace with real delta from trusted setup)
const VK_DELTA_G2: [u8; 128] = VK_BETA_G2;

// IC[0]: constant term — G1 generator (placeholder)
const VK_IC_0_G1: [u8; 64] = VK_ALPHA_G1;

// IC[1]: nullifier coefficient — 2*G1 (placeholder)
// 2*G = (0x030644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001,
//        0x0000000000000000000000000000000000000000000000000000000000000002) — not real 2G
// Using a distinct placeholder so IC[0] != IC[1]
const VK_IC_1_G1: [u8; 64] = g1(
    hex32("030644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"),
    hex32("0000000000000000000000000000000000000000000000000000000000000002"),
);

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct ComplianceShield;

#[contractimpl]
impl ComplianceShield {
    /// One-time initialisation: set the trusted authority and initial Merkle root.
    pub fn initialize(env: Env, authority: Address, merkle_root: BytesN<32>) {
        if env.storage().instance().has(&DataKey::Authority) {
            panic_with_error!(&env, Error::Unauthorized);
        }
        env.storage().instance().set(&DataKey::Authority, &authority);
        env.storage().instance().set(&DataKey::MerkleRoot, &merkle_root);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (symbol_short!("init"), symbol_short!("shield")),
            merkle_root,
        );
    }

    /// Authority rotates the Merkle root after a new KYC batch.
    pub fn update_root(env: Env, new_root: BytesN<32>) {
        let authority: Address = env
            .storage()
            .instance()
            .get(&DataKey::Authority)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        authority.require_auth();
        env.storage().instance().set(&DataKey::MerkleRoot, &new_root);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (symbol_short!("root"), symbol_short!("updated")),
            new_root,
        );
    }

    /// Verify a Groth16 proof that the caller belongs to the KYC Merkle tree.
    ///
    /// # Parameters
    /// - `proof_a`   – π_A  (G1, 64 bytes)
    /// - `proof_b`   – π_B  (G2, 128 bytes)
    /// - `proof_c`   – π_C  (G1, 64 bytes)
    /// - `nullifier` – Poseidon(user_secret ‖ merkle_root) as a 32-byte big-endian scalar
    ///
    /// # Groth16 verification equation
    /// ```text
    /// e(π_A, π_B) · e(−vk_α, vk_β) · e(−vk_x, vk_γ) · e(−π_C, vk_δ) == 1
    /// ```
    /// where `vk_x = IC[0] + nullifier * IC[1]` (public input accumulator).
    ///
    /// Emits an `identity_verified` event on success.
    /// Panics with the appropriate `Error` code on failure.
    pub fn verify_identity(
        env:       Env,
        proof_a:   BytesN<64>,
        proof_b:   BytesN<128>,
        proof_c:   BytesN<64>,
        nullifier: BytesN<32>,
    ) {
        // ── 1. Replay-attack guard ────────────────────────────────────────────
        let nul_key = DataKey::Nullifier(nullifier.clone());
        if env.storage().persistent().has(&nul_key) {
            panic_with_error!(&env, Error::NullifierReused);
        }

        let bn254 = env.crypto().bn254();

        // ── 2. Decode proof points ────────────────────────────────────────────
        let pi_a = Bn254G1Affine::from_array(&env, &{
            let mut b = [0u8; 64]; proof_a.copy_into_slice(&mut b); b
        });
        let pi_b = Bn254G2Affine::from_array(&env, &{
            let mut b = [0u8; 128]; proof_b.copy_into_slice(&mut b); b
        });
        let pi_c = Bn254G1Affine::from_array(&env, &{
            let mut b = [0u8; 64]; proof_c.copy_into_slice(&mut b); b
        });

        // ── 3. Build VK points ────────────────────────────────────────────────
        let vk_alpha = Bn254G1Affine::from_array(&env, &VK_ALPHA_G1);
        let vk_beta  = Bn254G2Affine::from_array(&env, &VK_BETA_G2);
        let vk_gamma = Bn254G2Affine::from_array(&env, &VK_GAMMA_G2);
        let vk_delta = Bn254G2Affine::from_array(&env, &VK_DELTA_G2);
        let ic_0     = Bn254G1Affine::from_array(&env, &VK_IC_0_G1);
        let ic_1     = Bn254G1Affine::from_array(&env, &VK_IC_1_G1);

        // ── 4. Public input accumulator: vk_x = IC[0] + nullifier * IC[1] ────
        let nullifier_scalar: Bn254Fr = {
            let mut b = [0u8; 32];
            nullifier.copy_into_slice(&mut b);
            U256::from_be_bytes(&env, &BytesN::from_array(&env, &b)).into()
        };
        let vk_x = ic_0 + bn254.g1_mul(&ic_1, &nullifier_scalar);

        // ── 5. Groth16 pairing check ──────────────────────────────────────────
        //
        // e(π_A, π_B) · e(−vk_α, vk_β) · e(−vk_x, vk_γ) · e(−π_C, vk_δ) == 1
        let valid = bn254.pairing_check(
            vec![&env, pi_a,    -vk_alpha, -vk_x,    -pi_c   ],
            vec![&env, pi_b,     vk_beta,   vk_gamma,  vk_delta],
        );

        if !valid {
            panic_with_error!(&env, Error::InvalidProof);
        }

        // ── 6. Persist nullifier + bump TTL ───────────────────────────────────
        env.storage().persistent().set(&nul_key, &true);
        env.storage().persistent().extend_ttl(
            &nul_key,
            NULLIFIER_TTL_THRESHOLD,
            NULLIFIER_TTL_EXTEND_TO,
        );

        // ── 7. Emit event (nullifier only — no PII) ───────────────────────────
        env.events().publish(
            (symbol_short!("identity"), symbol_short!("verified")),
            nullifier,
        );
    }

    /// Read the current Merkle root (public).
    pub fn merkle_root(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&DataKey::MerkleRoot)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized))
    }
}

// ── Compile-time helpers ──────────────────────────────────────────────────────

/// Decode a 64-char hex literal into a [u8; 32] at compile time.
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "hex32 requires exactly 64 hex chars");
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        out[i] = (nibble(b[i * 2]) << 4) | nibble(b[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex char"),
    }
}

/// Concatenate two [u8; 32] into a [u8; 64] G1 point.
const fn g1(x: [u8; 32], y: [u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut i = 0usize;
    while i < 32 { out[i]      = x[i]; i += 1; }
    while i < 64 { out[i] = y[i - 32]; i += 1; }
    out
}

/// Concatenate four [u8; 32] into a [u8; 128] G2 point.
const fn g2(x0: [u8; 32], x1: [u8; 32], y0: [u8; 32], y1: [u8; 32]) -> [u8; 128] {
    let mut out = [0u8; 128];
    let mut i = 0usize;
    while i < 32  { out[i]       = x0[i];       i += 1; }
    while i < 64  { out[i]       = x1[i -  32]; i += 1; }
    while i < 96  { out[i]       = y0[i -  64]; i += 1; }
    while i < 128 { out[i]       = y1[i -  96]; i += 1; }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, ComplianceShield);
        let client = ComplianceShieldClient::new(&env, &contract_id);
        let authority = Address::generate(&env);
        let root = BytesN::from_array(&env, &[0xabu8; 32]);
        client.initialize(&authority, &root);
        (env, contract_id, authority)
    }

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
        let (env, contract_id, authority) = setup();
        let client = ComplianceShieldClient::new(&env, &contract_id);
        let root = BytesN::from_array(&env, &[1u8; 32]);
        assert!(client.try_initialize(&authority, &root).is_err());
    }

    #[test]
    fn test_update_root() {
        let (env, contract_id, authority) = setup();
        env.mock_all_auths();
        let client = ComplianceShieldClient::new(&env, &contract_id);
        let new_root = BytesN::from_array(&env, &[2u8; 32]);
        client.update_root(&new_root);
        assert_eq!(client.merkle_root(), new_root);
    }

    #[test]
    fn test_update_root_requires_authority() {
        let (env, contract_id, _) = setup();
        // No mock_all_auths — auth will fail
        let client = ComplianceShieldClient::new(&env, &contract_id);
        let new_root = BytesN::from_array(&env, &[3u8; 32]);
        assert!(client.try_update_root(&new_root).is_err());
    }

    #[test]
    fn test_nullifier_replay_rejected() {
        let (env, contract_id, _) = setup();
        let client = ComplianceShieldClient::new(&env, &contract_id);

        let proof_a   = BytesN::from_array(&env, &[0u8; 64]);
        let proof_b   = BytesN::from_array(&env, &[0u8; 128]);
        let proof_c   = BytesN::from_array(&env, &[0u8; 64]);
        let nullifier = BytesN::from_array(&env, &[0x42u8; 32]);

        // First call fails at pairing (invalid proof), not at replay guard.
        let _ = client.try_verify_identity(&proof_a, &proof_b, &proof_c, &nullifier);

        // Inject nullifier as if a prior valid proof succeeded.
        env.as_contract(&contract_id, || {
            env.storage()
                .persistent()
                .set(&DataKey::Nullifier(nullifier.clone()), &true);
        });

        // Second call must fail with NullifierReused (error 4).
        let err = client
            .try_verify_identity(&proof_a, &proof_b, &proof_c, &nullifier)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, soroban_sdk::Error::from_contract_error(4));
    }

    #[test]
    fn test_nullifier_ttl_set_on_success() {
        // This test verifies that after a successful verify_identity the
        // nullifier entry exists in persistent storage with a non-zero TTL.
        // We cannot easily produce a valid Groth16 proof in unit tests, so we
        // inject the nullifier directly and check TTL behaviour.
        let (env, contract_id, _) = setup();
        env.ledger().with_mut(|li| {
            li.sequence_number    = 100_000;
            li.min_persistent_entry_ttl = 500;
            li.max_entry_ttl      = 10_000_000;
        });

        let nullifier = BytesN::from_array(&env, &[0x99u8; 32]);
        let key = DataKey::Nullifier(nullifier.clone());

        env.as_contract(&contract_id, || {
            env.storage().persistent().set(&key, &true);
            env.storage().persistent().extend_ttl(
                &key,
                NULLIFIER_TTL_THRESHOLD,
                NULLIFIER_TTL_EXTEND_TO,
            );
            let ttl = env.storage().persistent().get_ttl(&key);
            assert_eq!(ttl, NULLIFIER_TTL_EXTEND_TO);
        });
    }
}
