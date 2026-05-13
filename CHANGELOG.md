# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.2.0] - 2026-05-13

### Added
- Full Groth16 VK: `vk_gamma` (G2), `vk_delta` (G2), `IC[0]` and `IC[1]` (G1)
- Public input accumulator: `vk_x = IC[0] + nullifier * IC[1]`
- Contract events: `identity_verified`, `root_updated`, `init`
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
- `verify_identity` now returns `()` instead of `bool` (idiomatic Soroban)
- All storage keys use `DataKey` enum (was mixed `symbol_short!` + enum)
- G1 negation uses SDK `Neg` trait instead of manual field arithmetic
- Mock proof generator outputs only the 4 fields the contract accepts

### Fixed
- Pairing equation was incorrect (missing γ/δ, reused vk_β for all G2 slots)
- Nullifier was not cryptographically bound to the proof (missing accumulator)
- Nullifier TTL was never bumped (expiry-based replay was possible)

## [0.1.0] - 2026-05-13

### Added
- Initial Soroban contract scaffold
- `initialize`, `update_root`, `verify_identity`, `merkle_root` functions
- Mock Groth16 proof generator (Python)
- Basic README
