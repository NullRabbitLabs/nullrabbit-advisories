# nullrabbit-advisories

Standing home for NullRabbit operator advisories — public,
operator-facing writeups of validator and RPC infrastructure
findings, with reproducers and source citations.

These advisories are aimed at validator and RPC operators
(staking infrastructure, RPC providers, indexers, custodians)
who need to understand and mitigate exposure ahead of upstream
fixes. They are not vendor triage documents; the canonical
vendor-facing channel for each finding is referenced in the
advisory body.

**Why these are public:** see [Why we publish these findings
publicly](WHY-WE-PUBLISH.md). This class is vendor-declared
out-of-scope for bounty and embargo; no embargo applies, and we
release analysis + reproducer only (no weaponized PoC).

## Layout

```
nullrabbit-advisories/
├── README.md                 ← this file (advisory index)
├── LICENSE                   ← MIT
└── NR-YYYY-NNN/              ← one folder per advisory
    ├── NR-YYYY-NNN-<slug>.md ← operator advisory (the canonical text)
    └── reproducers/          ← self-contained reproducers + populators
        └── README.md         ← reproducer quick-start
```

Each advisory folder is self-contained — a reader who lands on
`NR-YYYY-NNN/` has the advisory text, the reproducers, and the
quick-start needed to verify the finding locally.

## Advisories

All published advisories cover the out-of-scope, no-embargo class described in
[Why we publish these findings publicly](WHY-WE-PUBLISH.md).

| ID | Date | Subject | Status |
|---|---|---|---|
| [NR-2026-001](NR-2026-001/NR-2026-001-agave-rpc-architectural-findings.md) | 2026-05-12 | Three Agave RPC architectural findings (response amplification + runtime-pool saturation) | Published |
| [NR-2026-002](NR-2026-002/NR-2026-002-agave-snapshot-appendvec-datalen-panic.md) | 2026-07-02 | Agave snapshot bootstrap crash via malformed AppendVec account length | Published |
| [NR-2026-003](NR-2026-003/NR-2026-003-iota-grpc-h2-multiplex-oom.md) | 2026-07-02 | IOTA node gRPC OOM via unbounded HTTP/2 concurrent streams | Published |
| [NR-2026-004](NR-2026-004/NR-2026-004-sui-layered-subscription-egress-dos.md) | 2026-07-02 | Sui fullnode takedown — wide-filter subscription memory-pin + multiGetObjects egress amplification | Published |
| [NR-2026-005](NR-2026-005/NR-2026-005-sui-subscription-permit-leak.md) | 2026-07-02 | Sui subscription permit leak + streamer-map orphan + wide-filter memory pin | Published |
| [NR-2026-006](NR-2026-006/NR-2026-006-iota-subscription-filter-cpu-and-reconnect-memory-oom.md) | 2026-07-02 | IOTA node OOM/CPU wedge via deep event-filter + reconnect-runaway subscription leak | Published |
| [NR-2026-007](NR-2026-007/NR-2026-007-cometbft-consensus-channel-floods.md) | 2026-07-03 | CometBFT consensus-channel message floods (Proposal / Vote / BlockSync) | Published |
| [NR-2026-008](NR-2026-008/NR-2026-008-cometbft-secretconnection-preauth-cpu-burn.md) | 2026-07-04 | CometBFT SecretConnection pre-authentication handshake CPU burn | Published |
| [NR-2026-009](NR-2026-009/NR-2026-009-iota-grpc-streamcheckpoints-subscriber-slot-exhaustion.md) | 2026-07-04 | IOTA node gRPC StreamCheckpoints subscriber-slot exhaustion | Published |

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.

## Licence

MIT (see `LICENSE`). Reproducers and advisory text may be
redistributed under those terms. NullRabbit name and marks
are not licensed.
