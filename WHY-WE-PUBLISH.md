# Why we publish these findings publicly

These are node-availability findings — malformed-snapshot / bootstrap crashes, RPC and response
amplification, consensus-channel message floods, pre-authentication handshake CPU burns, and
subscription / connection-slot exhaustion — in the class that vendors declare **out-of-scope for
bounty and embargo**. Vendor `SECURITY.md` files explicitly direct out-of-scope findings to public
issues. The impact is real and high for any node in its default configuration, and it is not
theoretical: each mechanism is measured against the real code path — the deserializer, the request
handler, or the consensus reactor — not asserted. The flagship example is a malformed snapshot that
deterministically crashes a bootstrapping node during snapshot load from untrusted peers, before the
hash gate, measured against the real deserializer and index-generation path.

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
