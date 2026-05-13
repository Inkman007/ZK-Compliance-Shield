## Summary
<!-- One sentence describing what this PR does. -->

## Changes
<!-- Bullet list of what changed and why. -->

## Testing
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo build --target wasm32v1-none --release` succeeds
- [ ] New tests added for new behaviour

## Security checklist (for contract changes)
- [ ] No new storage keys that could collide with existing ones
- [ ] TTL is bumped for any new persistent entries
- [ ] Auth checks are present on all privileged functions
- [ ] Events are emitted for all state changes
- [ ] VK placeholder comment updated if constants changed
