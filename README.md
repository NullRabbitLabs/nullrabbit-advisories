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

| ID | Date | Subject | Status |
|---|---|---|---|
| [NR-2026-001](NR-2026-001/NR-2026-001-agave-rpc-architectural-findings.md) | 2026-05-12 | Three Agave RPC architectural findings (response amplification + runtime-pool saturation) | Published |

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.

## Licence

MIT (see `LICENSE`). Reproducers and advisory text may be
redistributed under those terms. NullRabbit name and marks
are not licensed.
