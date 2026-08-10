# NR-2026-063 — Attestant Dirk: distributed-wallet slashing protection fails open, and the documented recovery does not restore it

**NullRabbit Operator Advisory** · Published 2026-08-11

## Summary

Attestant **Dirk** is a remote signer whose slashing-protection rules are the last line of defence between a
validator client and a slashable signature. Two defects in the **distributed (DKG) wallet** path were measured
end-to-end against real `attestant/dirk:1.2.0` containers with a genuine 2-of-3 distributed wallet.

**The one that matters: `--import-slashing-protection` is inert for distributed wallets, and fails silently.**
Each replica keys its slashing state on **its own component public key**, and the interchange export is keyed
the same way — so an export taken from replica 1 imports into replica 2 under *replica 1's* key, which
replica 2 never consults. The import returns exit code 0, the data is visibly present in the store, and the
replica will still sign the exact epoch the import was meant to protect. An operator who follows the
documented recovery procedure gets a success code and no protection.

Second, and the reason the first one matters: **an empty slashing store approves anything well-formed**, on
both the proposal and the attestation path. Together these mean a rebuilt replica is unprotected and cannot
be repaired by the documented means.

**Neither is remotely triggerable.** Both require an operational event — a zone rebuild, a PVC deletion, a
node replacement with fresh volumes. There is no attacker in either. Availability is unaffected; the risk is
that honest validators get slashed.

## Findings at a glance

| Finding | Component | Class | Severity |
|---|---|---|---|
| `DIRK_DISTRIBUTED_SLASHING_IMPORT_KEY_MISMATCH` | interchange import/export | `silent-control-failure`, `integrity` | MEDIUM |
| `DIRK_THRESHOLD_STORE_LOSS_EQUIVOCATION` | `rules/standard` empty-store guard | `integrity`, `fail-open` | MEDIUM |

- **Reachability:** not remote. Requires ≥ threshold replicas to lose their slashing store through an
  operational event, plus (for the first finding) an operator attempting the documented recovery.
- **Not affected:** non-distributed wallets, for the import defect — there `account.PublicKey()` *is* the
  validator key, so the interchange file round-trips correctly.

## Affected versions

Present through **`1.2.1`** and current `master` (`9482744`). `rules/standard` has had no functional change
since `2c86968` (2025-01-07), so this is long-standing rather than a recent regression.

## Mechanism (source-cited, `attestantio/dirk`)

### 1. Interchange import is keyed to the wrong public key

For a distributed account, each replica holds a distinct **component** key; the wallet's on-chain identity is
the **composite** key. `fetchSignBeaconAttestationState` / `fetchSignBeaconProposalState` key the slashing
store on `metadata.PubKey`, which resolves to the replica's own component key. `ExportSlashingProtection`
emits entries under those same keys. Nothing on the import path maps a foreign component key onto the local
replica's key, and nothing warns when an imported key matches no local account.

### 2. An absent state defaults to `-1`, and every guard is `>= 0`

- Proposals: `signbeaconproposal.go:121` defaults an absent state to `Slot = -1`; `:88` gates the slot check
  on `state.Slot >= 0`.
- Attestations: `signbeaconattestation.go:107-109` defaults **both** `SourceEpoch` and `TargetEpoch` to `-1`;
  `signbeaconattestations.go:151` and `:163` gate the **double-vote** and **surround-vote** checks
  respectively on `>= 0`.

So an empty store skips one check on the proposal path and *two* on the attestation path, leaving only the
intrinsic well-formedness checks (correct domain, `target > source`). Nothing historical is consulted.

Dirk maintains a peer mesh but never reconciles slashing state at runtime; the only interchange is the manual
`--import/--export-slashing-protection` startup commands, which require the process stopped.

## Measurement (fidelity: explicit)

Measured live on **3× `attestant/dirk:1.2.0`** with a real DKG 2-of-3 wallet (composite `0xa6916c38…`;
component keys `0xb5c978…`, `0x9087226…`, `0xb47acb5…`), driven over the real gRPC signing API. `ethdo`'s
generic `Sign` was **not** used — it carries no anti-slashing rule, so it measures nothing.

**Import defect, in order:**

| Step | Result |
|---|---|
| Export from dirk-1 (intact store) | `{"pubkey":"0xb5c978…","signed_attestations":[{"source_epoch":"10","target_epoch":"11"}]}` |
| Wipe dirk-2's store, import that file | **exit 0, no warning** |
| Export dirk-2 to verify | data **is** present, keyed `0xb5c978…` |
| Ask dirk-2 to sign target epoch 11, different block root | **SIGNED** |
| Export dirk-2 again | **two** keys: `0x9087226…` (its own, written by the signature just produced) and `0xb5c978…` (imported, never read) |

Protection returns only once the replica has signed under its own key — i.e. after the signing it needed
protecting for.

**Empty-store fail-open,** after wiping the stores of two of three replicas:

| Request | Result |
|---|---|
| Conflicting attestation at an already-voted target epoch | both replicas **SUCCEEDED** — slashable double vote |
| Surrounding vote `5→25` over a signed `10→20` | both replicas **SUCCEEDED** — slashable surround vote |
| Conflicting block at an already-signed slot | both replicas **SUCCEEDED** — slashable equivocation |
| Control: replica with its store intact | **DENIED** throughout |

**Correctly bounded, and stated so operators don't over-read this.** Wiping **one** of three is still
refused — the surviving member of every quorum remembers, so it takes `>= threshold` replicas losing state.
A clean network partition **cannot** produce this: quorum intersection holds, and the 2-of-3 design is sound
on that point. The batch path (`OnSignBeaconAttestations`) is also fine — the duplicate-key guard at
`services/ruler/golang/runner.go:64-80` rejects the aliasing the rules layer would otherwise permit.

## Scope

Slashing safety only. No remote attacker, no availability impact, no funds movement by a third party, no
authentication break. The loss mode is the validator's own stake via slashing penalty and forced exit.

## Mitigation

- **Do not rely on `--import-slashing-protection` to restore a rebuilt distributed-wallet replica.** Verify
  after any import by exporting the target replica and confirming the entries are keyed to *that replica's*
  component key.
- Treat the slashing store as durable state: back up the per-replica volume, or rebuild replicas one at a
  time and allow each to re-establish its own state before rebuilding the next, so fewer than `threshold`
  replicas are ever without memory.
- Where the deployment spreads replicas across failure domains, confirm no single domain holds
  `>= threshold` of them.

**Suggested upstream fixes,** as sent to the vendor: map to the local replica's component key on import (or
key the interchange by the composite key), and at minimum warn when an imported public key matches no local
account; and refuse to sign for an account with no slashing record unless an explicit override is passed.

## Context: fail-open on an empty store is a class, not one vendor's mistake

Stated so this advisory is not read as singling Attestant out. **Fail-open on an empty slashing store is the
common default across remote signers and validator clients, and Dirk is in the majority here, not the
exception.** The underlying problem is general: an empty database is indistinguishable from a validator with
no signing history, and the prevailing resolution is to sign. At least one implementation gets it right —
SSV's `eth2-key-manager` errors on a missing highest-record rather than approving.

We have a cross-implementation review of this class in progress. It is **deliberately not published here**,
because those vendors have not been contacted and it would be inconsistent to give them less notice than we
gave Attestant. It will be published separately, after they have.

What **is** specific to Dirk, and is the novel part of this advisory, is the **import-key mismatch** — the
documented recovery path silently failing to restore protection on a distributed wallet.

## Vendor channel and scope

Vendor **Attestant (`attestantio/dirk`)**. No published security channel: no `SECURITY.md` in the repo or the
org, GitHub private vulnerability reporting disabled, no `security@` address, no bug bounty. Reported to
`info@attestant.io` on **2026-07-28** with a stated 14-day disclosure window, published on expiry.

## Provenance

Our own (`source_class: original`) measurement and source trace. No CVE. Non-DoS security class, so no
detector bundle ships with this advisory — the spec+HF gate is category-inapplicable rather than unmet.

Prior-art check at time of reporting: no GitHub security advisory for `attestantio/dirk`, and no public issue
on empty-store fail-open or distributed-wallet import key scoping.

## Contact
research@nullrabbit.ai
