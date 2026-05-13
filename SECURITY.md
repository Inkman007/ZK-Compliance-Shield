# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ Yes    |
| 0.1.x   | ❌ No     |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing the maintainer directly or opening a
[GitHub Security Advisory](https://github.com/Inkman007/ZK-Compliance-Shield/security/advisories/new).

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

You will receive a response within 72 hours. We follow responsible disclosure
and will coordinate a fix and public disclosure timeline with you.

## Security Considerations

This contract handles cryptographic proof verification for KYC compliance.
The following areas are particularly sensitive:

- **Verification key (VK):** The `VK_*` constants in `src/lib.rs` must come
  from a trusted-setup ceremony. Placeholder values ship with the repo and
  **must be replaced before mainnet deployment**.

- **Nullifier TTL:** Nullifiers use `persistent` storage with a ~1-year TTL.
  If the TTL is not periodically refreshed, expired nullifiers could be reused.
  The contract bumps TTL on every successful verification.

- **Authority key:** The authority address controls the Merkle root. Compromise
  of this key allows an attacker to add arbitrary users to the KYC set.

- **Poseidon vs SHA-256:** The mock proof generator uses SHA-256 for the
  nullifier. Production circuits must use Poseidon to match the ZK circuit.
