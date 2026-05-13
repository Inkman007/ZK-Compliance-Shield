# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.3.0] - 2026-05-13

### Changed
- Replaced all VK generator-point placeholders with real, curve-valid BN254
  points sourced from the Ethereum EIP-197 canonical test vectors
  (`go-ethereum/bn256Pairing.json` — `jeff1` test case)
- `VK_ALPHA_G1` / `VK_BETA_G2`: jeff1 pair-0 G1/G2 points (A, B)
- `VK_GAMMA_G2`: canonical BN254 G2 generator (well-known, curve-valid)
- `VK_DELTA_G2`: same as gamma (replace with ceremony output)
- `VK_IC_0_G1` / `VK_IC_1_G1`: jeff1 pair-1 G1 point C (curve-valid)
- `mock_proof_generator.py` now outputs the jeff1 test vector proof
  (`nullifier=0`) and supports `test` / `mock` modes

### Notes
- All VK points are real curve points — the contract will not panic on decoding.
- `VK_GAMMA_G2`, `VK_DELTA_G2`, and `VK_IC_1_G1` still require ceremony-specific
  values before mainnet deployment.

---

## [0.2.0] - 2026-05-13

### Added
- Full Groth16 VK: `vk_gamma` (G2), `vk_delta` (G2), `IC[0]` and `IC[1]` (G1)
- Public input accumulator: `vk_x = IC[0] + nullifier * IC[1]`
- Contract events: `identity_verified`, `root_updated`, `init/shield`
- Instance storage TTL bump on every write (prevents contract expiry)
- `contractmeta!` declarations (name, description, version)
- `rust-toolchain.toml` pinning Rust 1.82.0 + `wasm32v1-none`
- `.cargo/config.toml` default build target
- GitHub Actions CI (fmt, clippy, test, wasm build, artifact upload)
- `SECURITY.md`, `CHANGELOG.md`, `.gitignore`
- `docs/architecture.md`, `docs/circuit-spec.md`
- `scripts/deploy.sh`, `scripts/requirements.txt`
- GitHub issue and PR templates

### Changed
- Upgraded to Soroban SDK v26 (Protocol 25 / X-Ray)
- `verify_identity` returns `()` instead of `bool` (idiomatic Soroban)
- All storage keys use `DataKey` enum (was mixed `symbol_short!` + enum)
- G1 negation uses SDK `Neg` trait instead of manual field arithmetic
- Mock proof generator outputs only the 4 fields the contract accepts

### Fixed
- Pairing equation was incorrect (missing γ/δ, reused `vk_β` for all G2 slots)
- Nullifier was not cryptographically bound to the proof (missing accumulator)
- Nullifier TTL was never bumped (expiry-based replay was possible)

---

## [0.1.0] - 2026-05-13

### Added
- Initial Soroban contract scaffold
- `initialize`, `update_root`, `verify_identity`, `merkle_root` functions
- Mock Groth16 proof generator (Python)
- Basic README
