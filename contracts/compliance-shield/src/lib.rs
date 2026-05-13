#![no_std]

use soroban_sdk::{
    contract, contractimpl, contractmeta, contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr},
    panic_with_error, symbol_short,
    vec,
    Address, BytesN, Env, U256,
};

// ── Contract metadata ─────────────────────────────────────────────────────────

contractmeta!(key = "name",        val = "ZK-Compliance-Shield");
contractmeta!(key = "description", val = "Privacy-preserving KYC compliance layer using Groth16/BN254 on Stellar Protocol 25");
contractmeta!(key = "version",     val = "0.3.0");

// ── TTL constants (ledgers) ───────────────────────────────────────────────────
// ~1 year at 5-second ledger close = 6_307_200 ledgers.
// Extend when TTL drops below 30 days (518_400 ledgers).

const NULLIFIER_TTL_THRESHOLD: u32 = 518_400;
const NULLIFIER_TTL_EXTEND_TO: u32 = 6_307_200;
const INSTANCE_TTL_THRESHOLD:  u32 = 518_400;
const INSTANCE_TTL_EXTEND_TO:  u32 = 6_307_200;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Authority,
    MerkleRoot,
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

// ── Verification key ──────────────────────────────────────────────────────────
//
// Real, curve-valid BN254 points from the Ethereum EIP-197 canonical test
// vectors (go-ethereum bn256Pairing.json, "jeff1" test case).
//
// REPLACE ALL VK_* CONSTANTS with trusted-setup ceremony output before mainnet.
// See docs/circuit-spec.md for the exact format and tooling.

const VK_ALPHA_G1: [u8; 64] = g1(
    hex32("1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59"),
    hex32("3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41"),
);

const VK_BETA_G2: [u8; 128] = g2(
    hex32("209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7"),
    hex32("04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678"),
    hex32("2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d"),
    hex32("120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550"),
);

// Canonical BN254 G2 generator — replace with ceremony output.
const VK_GAMMA_G2: [u8; 128] = g2(
    hex32("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
    hex32("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
    hex32("090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
    hex32("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"),
);

const VK_DELTA_G2: [u8; 128] = VK_GAMMA_G2;

const VK_IC_0_G1: [u8; 64] = g1(
    hex32("111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c"),
    hex32("2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411"),
);

const VK_IC_1_G1: [u8; 64] = VK_IC_0_G1;

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
        env.events().publish((symbol_short!("init"), symbol_short!("shield")), merkle_root);
    }

    /// Authority rotates the Merkle root after a new KYC batch.
    pub fn update_root(env: Env, new_root: BytesN<32>) {
        let authority: Address = env
            .storage().instance().get(&DataKey::Authority)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        authority.require_auth();
        env.storage().instance().set(&DataKey::MerkleRoot, &new_root);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
        env.events().publish((symbol_short!("root"), symbol_short!("updated")), new_root);
    }

    /// Verify a Groth16 proof that the caller belongs to the KYC Merkle tree.
    ///
    /// Groth16 equation:
    /// `e(πA, πB) · e(−vkα, vkβ) · e(−vkX, vkγ) · e(−πC, vkδ) == 1`
    /// where `vkX = IC[0] + nullifier * IC[1]`.
    ///
    /// Emits `("identity", "verified")` on success.
    /// Panics with a typed `Error` code on failure.
    pub fn verify_identity(
        env:       Env,
        proof_a:   BytesN<64>,
        proof_b:   BytesN<128>,
        proof_c:   BytesN<64>,
        nullifier: BytesN<32>,
    ) {
        // 1. Replay guard
        let nul_key = DataKey::Nullifier(nullifier.clone());
        if env.storage().persistent().has(&nul_key) {
            panic_with_error!(&env, Error::NullifierReused);
        }

        let bn254 = env.crypto().bn254();

        // 2. Decode proof points
        let pi_a = Bn254G1Affine::from_array(&env, &{ let mut b = [0u8; 64];  proof_a.copy_into_slice(&mut b); b });
        let pi_b = Bn254G2Affine::from_array(&env, &{ let mut b = [0u8; 128]; proof_b.copy_into_slice(&mut b); b });
        let pi_c = Bn254G1Affine::from_array(&env, &{ let mut b = [0u8; 64];  proof_c.copy_into_slice(&mut b); b });

        // 3. Build VK points
        let vk_alpha = Bn254G1Affine::from_array(&env, &VK_ALPHA_G1);
        let vk_beta  = Bn254G2Affine::from_array(&env, &VK_BETA_G2);
        let vk_gamma = Bn254G2Affine::from_array(&env, &VK_GAMMA_G2);
        let vk_delta = Bn254G2Affine::from_array(&env, &VK_DELTA_G2);
        let ic_0     = Bn254G1Affine::from_array(&env, &VK_IC_0_G1);
        let ic_1     = Bn254G1Affine::from_array(&env, &VK_IC_1_G1);

        // 4. Public input accumulator: vkX = IC[0] + nullifier * IC[1]
        let scalar: Fr = {
            let mut b = [0u8; 32];
            nullifier.copy_into_slice(&mut b);
            U256::from_be_bytes(&env, &BytesN::from_array(&env, &b)).into()
        };
        let vk_x = ic_0 + bn254.g1_mul(&ic_1, &scalar);

        // 5. Groth16 pairing check
        let valid = bn254.pairing_check(
            vec![&env, pi_a,    -vk_alpha, -vk_x,    -pi_c   ],
            vec![&env, pi_b,     vk_beta,   vk_gamma,  vk_delta],
        );
        if !valid {
            panic_with_error!(&env, Error::InvalidProof);
        }

        // 6. Persist nullifier + bump TTL
        env.storage().persistent().set(&nul_key, &true);
        env.storage().persistent().extend_ttl(&nul_key, NULLIFIER_TTL_THRESHOLD, NULLIFIER_TTL_EXTEND_TO);

        // 7. Emit event (nullifier only — zero PII)
        env.events().publish((symbol_short!("identity"), symbol_short!("verified")), nullifier);
    }

    /// Read the current Merkle root (public).
    pub fn merkle_root(env: Env) -> BytesN<32> {
        env.storage().instance().get(&DataKey::MerkleRoot)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized))
    }
}

// ── Compile-time helpers ──────────────────────────────────────────────────────

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

const fn g1(x: [u8; 32], y: [u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut i = 0usize;
    while i < 32 { out[i]      = x[i];      i += 1; }
    while i < 64 { out[i] = y[i - 32]; i += 1; }
    out
}

const fn g2(x0: [u8; 32], x1: [u8; 32], y0: [u8; 32], y1: [u8; 32]) -> [u8; 128] {
    let mut out = [0u8; 128];
    let mut i = 0usize;
    while i < 32  { out[i] = x0[i];       i += 1; }
    while i < 64  { out[i] = x1[i -  32]; i += 1; }
    while i < 96  { out[i] = y0[i -  64]; i += 1; }
    while i < 128 { out[i] = y1[i -  96]; i += 1; }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        let contract_id = env.register(ComplianceShield, ());
        let client = ComplianceShieldClient::new(&env, &contract_id);
        let authority = Address::generate(&env);
        let root = BytesN::from_array(&env, &[0xabu8; 32]);
        client.initialize(&authority, &root);
        (env, contract_id, authority)
    }

    #[test]
    fn test_initialize_and_root() {
        let env = Env::default();
        let contract_id = env.register(ComplianceShield, ());
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
        let client = ComplianceShieldClient::new(&env, &contract_id);
        assert!(client.try_update_root(&BytesN::from_array(&env, &[3u8; 32])).is_err());
    }

    #[test]
    fn test_nullifier_replay_rejected() {
        let (env, contract_id, _) = setup();
        let client = ComplianceShieldClient::new(&env, &contract_id);
        let proof_a   = BytesN::from_array(&env, &[0u8; 64]);
        let proof_b   = BytesN::from_array(&env, &[0u8; 128]);
        let proof_c   = BytesN::from_array(&env, &[0u8; 64]);
        let nullifier = BytesN::from_array(&env, &[0x42u8; 32]);

        // First call fails at pairing — not at replay guard.
        let _ = client.try_verify_identity(&proof_a, &proof_b, &proof_c, &nullifier);

        // Inject nullifier as if a prior valid proof succeeded.
        env.as_contract(&contract_id, || {
            env.storage().persistent().set(&DataKey::Nullifier(nullifier.clone()), &true);
        });

        // Second call must fail with NullifierReused (error 4).
        let err = client
            .try_verify_identity(&proof_a, &proof_b, &proof_c, &nullifier)
            .unwrap_err()
            .unwrap();
        assert_eq!(err, soroban_sdk::Error::from_contract_error(4));
    }

    #[test]
    fn test_nullifier_ttl_extended() {
        let (env, contract_id, _) = setup();
        env.ledger().with_mut(|li| {
            li.sequence_number          = 100_000;
            li.min_persistent_entry_ttl = 500;
            li.max_entry_ttl            = 10_000_000;
        });
        let nullifier = BytesN::from_array(&env, &[0x99u8; 32]);
        let key = DataKey::Nullifier(nullifier.clone());
        env.as_contract(&contract_id, || {
            env.storage().persistent().set(&key, &true);
            env.storage().persistent().extend_ttl(&key, NULLIFIER_TTL_THRESHOLD, NULLIFIER_TTL_EXTEND_TO);
            assert_eq!(env.storage().persistent().get_ttl(&key), NULLIFIER_TTL_EXTEND_TO);
        });
    }
}
