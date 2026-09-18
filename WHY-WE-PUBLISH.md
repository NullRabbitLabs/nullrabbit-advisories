# Why we publish these findings publicly

These are node-availability findings — malformed-snapshot / bootstrap crashes, RPC and response
amplification, consensus-channel message floods, pre-authentication handshake CPU burns, and
subscription / connection-slot exhaustion. Where a vendor declares this class **out of scope for
bounty and embargo**, we publish an operator advisory. The impact is real and high for any node in
its default configuration, and it is not
theoretical: each mechanism is measured against the real code path — the deserializer, the request
handler, or the consensus reactor — not asserted. The flagship example is a malformed snapshot that
deterministically crashes a bootstrapping node during snapshot load from untrusted peers, before the
hash gate, measured against the real deserializer and index-generation path.

**Corrected 2026-09-18.** This page used to assert, generally, that "vendor `SECURITY.md` files
explicitly direct out-of-scope findings to public issues". A general claim cannot carry that
weight, because it is true of some vendors and not others, and it was being relied on for vendors
where nobody had checked. The sentence is gone.

What replaces it is a per-advisory test. An advisory goes on the publish track only where the
vendor's own policy is quoted — the words, the URL, and the date it was read — showing the class is
excluded, or where there is no reachable channel at all. Where the vendor says nothing about scope,
silence is not an exclusion, and the answer is to tell them.

Two things that audit confirmed, since the point is evidence rather than assertion. MystenLabs/Sui
lists "Attacks involving DDoS" under "Out of scope" and says all other impacts are "ineligible for
payout". Agave excludes, under its own RPC DoS category, "Those impacting `getProgramAccounts`, et
al. without secondary indexes enabled and/or unfiltered requests" and "Those requiring calls from
multiple clients", and separately excludes "Issues involving maliciously crafted snapshots" — the
class of the flagship example above.

We publish for three reasons:

1. **Public good:** The validator ecosystem has no shared attack substrate. These primitives belong
   in the open corpus so operators, researchers, and tool builders can defend against the actual
   threat surface, not the one vendors prefer to acknowledge.

2. **Transparency:** We train our detectors on real, contract-validated behaviors. Hiding source
   findings would make the models and index unverifiable. The corpus is the ground truth.

3. **Independent research posture:** We are not a vendor SOC or bounty hunter. We surface ignored
   classes so the standard improves. Vendors can fix; the community gets the data immediately.

No embargo applies. No weaponized PoC is released. Analysis + reproducer only. This is how the
reference substrate is built.

---

*Hosted / canonical version: <https://nullrabbit.ai/research> (Publication Policy). This file is the
in-repo copy so each advisory stays self-contained.*
