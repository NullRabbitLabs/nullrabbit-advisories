# NR-2026-030 — Sui passkey (WebAuthn) authenticator: spec-compliance and multisig defense-in-depth gaps (SUI_H03)

**NullRabbit Operator Advisory** · Published 2026-07-08

> **Why we publish publicly:** this is an out-of-scope-for-bounty authentication-hardening finding on the Sui node, source-traced only — the gaps are code-level defense-in-depth properties with no network-observable wire signature, so like NR-2026-028 it ships no detection bundle. See [Why we publish these findings publicly](../WHY-WE-PUBLISH.md).

## Summary

`SUI_H03` is a set of five authentication defense-in-depth gaps in Sui's passkey (WebAuthn) authenticator and its multisig branch. `PasskeyAuthenticator::verify_claims` verifies the secp256r1 signature but skips four WebAuthn spec-mandated relying-party checks — User-Presence flag, RP-ID-hash, `signCount` clone-detection, and an unused hardening hook — and the passkey branch of `MultiSig::verify_claims` omits the scheme-consistency check that its five sibling signature branches all apply. None is a standalone exploit: each either requires prior private-key compromise / authenticator cloning, or is caught by a downstream address check. Composite severity **Low-Medium** (most-impactful sub-item CVSS 3.1 base 1.4). The value is bringing passkey handling to WebAuthn-compliant parity with Sui's other authenticators.

## Mechanism (source-cited, `MystenLabs/sui`, tested sui 1.70.1 @ `a7e7b45a4cee`)

- **H03a — User-Presence flag not checked.** `verify_claims` (`crates/sui-types/src/passkey_authenticator.rs:225-274`) uses `authenticator_data` verbatim inside the signed message but never parses the flags byte at offset 32, so a signature carrying `UP=0` ("user not present") is accepted where a WebAuthn-compliant relying party (§7.2.11) would reject it.
- **H03b — RP-ID-hash not verified.** `authenticator_data[0..32]` (the RP-ID hash, WebAuthn §7.2.11) is never examined. The authenticator-level RP-ID binding is the primary defence; verifying it relying-party-side is the missing defense-in-depth layer that would catch a coerced or custom-firmware cross-RP-ID signature.
- **H03c — no signCount tracking.** Sui does not track the authenticator `signCount` (WebAuthn §7.2.21) across transactions, so a cloned authenticator replaying a stale counter is indistinguishable from the genuine one — clone detection is impossible.
- **H03d — hardening hook explicitly ignored.** The passkey path takes its `VerifyParams` argument unused (`:239`) where every other authenticator consumes it; future hardening fields added to `VerifyParams` (e.g. an accepted-authenticator allowlist) would be silently bypassed on the passkey path.
- **H03e — multisig scheme-consistency check missing.** `MultiSig::verify_claims` (`crates/sui-types/src/multisig.rs:162-298`) applies an upfront `additional_multisig_checks` scheme/pubkey-type check in the Ed25519, Secp256k1, Secp256r1 and ZkLogin branches but not in the Passkey branch (`:267-282`). The type mismatch is still caught downstream by the `author != SuiAddress::from(&get_pk())` check, so this is a defense-in-depth asymmetry, not a direct bypass.

Remediation is a single upstream PR touching the two files: parse-and-require the UP flag, verify the RP-ID hash against a canonical Sui RP-ID, track `signCount` per credential, consume `VerifyParams`, and add the missing multisig scheme check to match the five sibling branches. Per-item fixes are in the source trace.

## Scope

Authentication-correctness / defense-in-depth on the Sui validator's signature-verification path; no funds movement, no chain halt, no unauthenticated break — every sub-item requires prior key compromise or authenticator cloning, or is caught downstream. Source-traced only: no turnkey reproducer against live infrastructure, no public IPs or mainnet hostnames. Operator-side mitigation is not available (verification runs inside the node binary); these are upstream-fix concerns.

## Provenance and disclosure

NullRabbit original source-level analysis (`provenance.source_class: original`). `SUI_H03` is a **security-class finding with no detector product** — the gaps are auth-logic properties whose only wire signature is "a passkey-signed transaction," indistinguishable from a legitimate one, so unlike the availability findings in NR-2026-027 it ships no bundle to the public dataset. Best-practice / hardening findings are out of scope on the Sui bug-bounty program (HackenProof), and the direct `security@sui.io` channel is unresponsive, so this is published as a source-traced operator advisory. Vendor: **MystenLabs / `MystenLabs/sui`**. Source trace and per-item evidence in `chains/sui/findings/H03/`.

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.

If you operate Sui validator infrastructure or build Sui wallets using passkey authentication and have applied the remediation above, or have measurements at variance with this, we would like to hear from you.
