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
explicitly direct out-of-scope findings to public issues". Audited against the vendors we had
actually published against, that was true of one of them and not the others, so the sentence is
gone. It was doing load-bearing work it could not carry: "the vendor will not pay for this" is a
different statement from "the vendor does not want to be told", and only the second justifies
publishing without notice.

What replaces it is a per-advisory test rather than a general claim. An advisory may go out on the
publish track only where the vendor's own policy is quoted — the words, the URL, and the date it
was read — showing the class is excluded, or where there is no reachable channel at all. Silence in
a security policy is not an exclusion; where a vendor says nothing about scope, the answer is to
tell them. Where we got that wrong, the advisory carries a correction rather than a quiet edit; see
NR-2026-001.

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
