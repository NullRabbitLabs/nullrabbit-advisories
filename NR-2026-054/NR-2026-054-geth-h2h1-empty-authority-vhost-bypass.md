# NR-2026-054 — Ethereum (go-ethereum): h2→h1 empty-`:authority` downgrade bypasses geth's `--http.vhosts` Host allowlist

**NullRabbit Operator Advisory** · Published 2026-07-15

## Summary

go-ethereum's `--http.vhosts` is a Host-header allowlist (default `localhost`) that rejects JSON-RPC
requests whose `Host` is not permitted — the standard anti-DNS-rebinding control. geth **accepts an empty
`Host` header** (returns `200`) while rejecting a non-allowlisted Host (`403 "invalid host specified"`).
Independently, when a node is fronted by an **HAProxy** HTTP/2 front, a malformed request with an empty
`:authority` pseudo-header (plus a `host:` header) is downgraded to HTTP/1.1 with an **empty `Host`**,
HAProxy ignoring the supplied host header. Chained, a request whose intended `Host` is **forbidden** by the
allowlist reaches geth with an empty `Host` and is **accepted** — a bypass of geth's Host allowlist. This is
an **availability/access-control-hardening issue** (a defeat of the Host restriction), **not** an
authentication bypass beyond that control — no funds, no consensus break — so it is handled on NullRabbit's
publish-track.

## Findings at a glance

| Finding | Primitive | Surface | Class | Severity |
|---|---|---|---|---|
| `ETH_GETH_H2H1_EMPTY_AUTHORITY_VHOST_BYPASS` | `eth_geth_h2h1_empty_authority_vhost_bypass` | `--http.vhosts` Host allowlist, geth behind an HAProxy h2 front | `auth_bypass` | MEDIUM |

- **Reachability:** a caller able to send **raw/malformed HTTP/2** (empty `:authority`) to an HAProxy front
  that terminates h2 and forwards h1 to geth. Not reachable from a conformant browser (browsers cannot emit
  an empty `:authority`).
- **Edge-specific:** the empty-`:authority`→empty-`Host` downgrade is **HAProxy-specific** — nginx `GOAWAY`s
  and Envoy rejects the empty `:authority`, so those fronts are not affected.
- **Affected:** go-ethereum with `--http.vhosts` set to a restricted allowlist, fronted by HAProxy in h2.

## Affected versions

Observed on go-ethereum 1.17.4 (empty-`Host` acceptance) + HAProxy 3.3.6 (empty-`:authority`→empty-`Host`
downgrade). No specific affected range is established beyond the described component behaviours.

## Mechanism (source-cited)

- **geth** (`node/rpcstack.go`, `virtualHostHandler`): the allowlist check permits requests whose `Host` is
  in `--http.vhosts`, and — as measured — an **empty** `Host` is treated as allowed (`Host: localhost` →
  200, `Host: 127.0.0.1` → 200, `Host:` empty → 200, `Host: evil.example` → 403, no Host → 400).
- **HAProxy** (h2→h1 downgrade): given a malformed HTTP/2 request with `:authority=""` plus a `host:` header,
  HAProxy forwards `host: ` (empty), ignoring the supplied host header. (This is finding #1 of NullRabbit's
  h2→h1 downgrade-disagreement set; nginx and Envoy reject the same input.)
- **Chain:** attacker sends `:authority=""` + `host: <forbidden>` to the HAProxy front → geth receives an
  empty `Host` → 200. The intended forbidden `Host` (which is `403` when sent directly or with a proper
  `:authority`) is thereby smuggled past the allowlist.

## Reproduction (fidelity: lab)

Measured against a self-owned go-ethereum 1.17.4 node (`--http.vhosts localhost`) behind an HAProxy 3.3.6 h2
front:
- **Control** — proper `:authority=evil.example` through HAProxy → geth `403 "invalid host specified"`.
- **Attack** — `:authority=""` + `host: evil.example` through HAProxy → geth **`200`** (`{"result":...}`) —
  allowlist bypassed.
- Direct `Host: evil.example` to geth (no edge) stays `403` — the control holds; only the downgrade route
  defeats it.

The published corpus reproducer (primitive `eth_geth_h2h1_empty_authority_vhost_bypass`, family
`auth_bypass`, `source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures both the control
(`403`) and attack (`200`) traffic, including the cleartext downgraded empty-`Host` request to geth. A
hand-built HTTP/2 client (validation disabled) is required to emit the empty `:authority`.

## Scope

Defeats geth's Host allowlist (`--http.vhosts`) — a DNS-rebinding / Host-access control — turning a forbidden
Host into an accepted empty Host. It is **not** an authentication bypass beyond that control; no funds, no
consensus. Requires the HAProxy-h2-front deployment and a caller able to speak malformed h2; nginx/Envoy
fronts and browser clients are not affected.

## Mitigation

- **Do not rely on `--http.vhosts` alone behind an HAProxy h2 front.** Enforce the Host/authority allowlist
  at the edge as well, and reject empty `:authority` / empty `Host`.
- Prefer an edge (nginx/Envoy) that rejects the malformed `:authority`, or upgrade/patch HAProxy behaviour so
  the downgrade preserves the intended host header.
- Keep the JSON-RPC transport on loopback or behind authentication; the allowlist is a defence-in-depth
  control, not a substitute for network isolation.

## Vendor channel and scope

Vendors: **go-ethereum** (empty-`Host` acceptance in the vhost check) and **HAProxy** (empty-`:authority`
downgrade). Availability/access-control hardening on the public JSON-RPC surface → **out of paid scope →
publish-track**. Not a fund-loss / consensus-safety class.

## Provenance

Our own (`source_class: original`) measurement; composes NullRabbit's h2→h1 downgrade-disagreement research
(`rigs/h2-diff`) with a geth Host-handling behaviour confirmed in lab. No assigned CVE. The corpus primitive
`eth_geth_h2h1_empty_authority_vhost_bypass` is on-spec and on-HF (`NullRabbit/nr-bundles-public`), so this
advisory does not outpace its shipped defensive artefact.

## Contact
research@nullrabbit.ai
