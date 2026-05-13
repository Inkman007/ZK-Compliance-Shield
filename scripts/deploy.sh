#!/usr/bin/env bash
# deploy.sh — Build, deploy, and initialize the ComplianceShield contract.
#
# Usage:
#   ./scripts/deploy.sh [testnet|futurenet|mainnet] <AUTHORITY_ADDRESS> <MERKLE_ROOT_HEX>
#
# Prerequisites:
#   - stellar CLI installed and configured
#   - STELLAR_SOURCE_KEY env var set (or pass --source manually)
#   - Rust toolchain with wasm32v1-none target

set -euo pipefail

NETWORK="${1:-testnet}"
AUTHORITY="${2:?Usage: deploy.sh <network> <authority_address> <merkle_root_hex>}"
MERKLE_ROOT="${3:?Usage: deploy.sh <network> <authority_address> <merkle_root_hex>}"

WASM="target/wasm32v1-none/release/compliance_shield.wasm"

echo "==> Building WASM..."
cargo build --workspace --target wasm32v1-none --release

echo "==> Deploying to $NETWORK..."
CONTRACT_ID=$(stellar contract deploy \
  --wasm "$WASM" \
  --source "${STELLAR_SOURCE_KEY:-default}" \
  --network "$NETWORK" \
  --fee 1000000 \
  2>&1 | tail -1)

echo "    Contract ID: $CONTRACT_ID"

echo "==> Initializing contract..."
stellar contract invoke \
  --id "$CONTRACT_ID" \
  --source "${STELLAR_SOURCE_KEY:-default}" \
  --network "$NETWORK" \
  --send=yes \
  -- initialize \
  --authority "$AUTHORITY" \
  --merkle_root "$MERKLE_ROOT"

echo ""
echo "✅ Deployed and initialized."
echo "   Network:     $NETWORK"
echo "   Contract ID: $CONTRACT_ID"
echo "   Authority:   $AUTHORITY"
echo "   Merkle root: $MERKLE_ROOT"
