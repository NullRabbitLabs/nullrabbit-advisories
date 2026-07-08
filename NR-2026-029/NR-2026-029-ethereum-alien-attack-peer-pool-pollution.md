# NR-2026-029 — Ethereum devp2p "Alien Attack" peer-pool pollution (ETH_ALIEN_PEER_POOL_POLLUTION)

**NullRabbit Operator Advisory** · Published 2026-07-08

## Summary

The Ethereum devp2p handshake admits peers **before** it knows what chain they are on. The RLPx ECIES
key-agreement and the devp2p `Hello` (capability exchange) are chain-agnostic; the only chain check —
`networkID`, `genesis`, and `forkID` — happens later, in the `eth` subprotocol `Status` message, after
the node has already completed the full cryptographic handshake and allocated a connection. A peer from a
**same-family but different chain** (e.g. a mainnet-identity peer connecting to a private/testnet node,
or cross-connecting sibling chains that share devp2p) therefore forces the target to spend the entire
ECIES + `Hello` handshake on a connection it will only reject at `Status`. Flooding such "alien"
handshakes wastes handshake CPU and occupies inbound connection slots — degrading a node's ability to
form and keep honest peers. This is the class SlowMist first documented as the **Alien Attack**
("peer-pool pollution").

This is a node-availability finding in the class vendors treat as out-of-scope for bounty/embargo. No CVE
is assigned; the mechanism is public. We publish the measured reproduction and the detection signature.

## Mechanism (source-traced, `ethereum/go-ethereum`)

1. Attacker completes the RLPx ECIES handshake and sends devp2p `Hello` advertising `eth`. Both are
   **chain-agnostic** — geth admits the peer to the `eth` handshake regardless of chain.
2. geth sends its `Status` = `[version, networkID, td, bestHash, genesis, forkID]`.
3. Attacker replies with an **alien** `Status` — a different chain identity (Ethereum mainnet
   `networkID=1` + the mainnet genesis hash) than the target.
4. geth detects the `networkID`/`genesis` mismatch and disconnects (`Disconnect` reason `0x02`,
   subprotocol breach) — but only **after** paying for the full ECIES + `Hello` handshake and holding
   the slot for the duration.

The chain check being downstream of the expensive handshake is the defect: an unauthenticated remote
peer controls whether the node performs that work, and repeated alien handshakes pollute the peer pool
(handshake-CPU waste + slot occupation). The discovery-layer variant (alien ENRs poisoning the Kademlia
routing table across same-family chains) is the same class at the UDP layer.

## Scope

- **Affected:** Ethereum `devp2p`/RLPx nodes in default configuration (geth and protocol-compatible
  clients). Measured against `ethereum/client-go` **v1.17.4**: RLPx + `Hello` complete, geth emits its
  `Status`, the alien `Status` is rejected with `Disconnect(0x02)`.
- **Impact:** availability/degradation (peer-pool pollution, handshake-resource waste, connection-slot
  occupation). Not a crash and not fund-loss.
- **Not affected:** the chain's consensus or ledger state; this is a peering-layer resource issue.

## Provenance and disclosure

- **Attack class:** first documented by **SlowMist** — *Blockchain Common Vulnerability List* ("Alien
  Attack" / peer-pool pollution): <https://github.com/slowmist/Cryptocurrency-Security-Audit-Guide/blob/main/Blockchain-Common-Vulnerability-List.md>
- **NullRabbit contribution:** a faithful wire-level reproduction driver (`geth_alien_peer_pool_pollution`)
  and captured attack traffic (4 postures, thousands of completed alien handshakes each) added to the
  open detector corpus `NullRabbit/nr-bundles-public`. `source_class = public-cve-replication`.
- **No embargo** (the class is public). **No weaponized PoC** — analysis + reproducer only.

## Contact

research@nullrabbit.ai · <https://nullrabbit.ai/research>
