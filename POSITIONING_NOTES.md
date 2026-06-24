# QIHSE Positioning Notes

These notes capture the blunt positioning feedback from the KEYSTONE/QIHSE review conversation.

## Core Point

QIHSE can be ambitious and still credible, but the README needs to separate evidence from aspiration. If the implementation backs the claims, the framing should make that obvious instead of forcing readers to trust maximal language.

The goal is not to make QIHSE smaller. The goal is to make it harder to dismiss.

## What To Keep

- The exactness-first principle: approximation can propose candidates, but exact verification decides truth.
- The native C systems-engineering identity.
- The multi-engine database ambition.
- The AGPL/commercial-license posture.
- The benchmark-driven engineering story.
- The larger ecosystem signal: QIHSE plus KEYSTONE and related repos show sustained capability, not a one-off project.

## What Weakens Trust

- Absolute claims like "any workload, any scale" unless backed by direct evidence.
- Security claims like "zero timing leaks", "CNSA 2.0 compliant", or "mathematically cannot deduce" unless formally tested and documented.
- Language such as "stealth", "silent", "zero trace", and "violently lock down".
- Hidden or covert enforcement mechanisms.
- README language that reads like a manifesto instead of an evidence brief.

Even when the code is real, theatrical wording makes true claims look inflated.

## Recommended README Structure

1. What is stable now.
2. What is experimental now.
3. What is reserved/planned.
4. What has benchmark numbers.
5. What security properties are implemented.
6. What security properties are threat-modeled but not formally verified.
7. How licensing works: AGPL for open use, commercial license for closed/proprietary use.

Every engine should be labeled clearly:

- `stable`
- `experimental`
- `reserved`
- `planned`

## Licensing And Anti-Ripoff Strategy

AGPL gives leverage after discovery; it does not magically reveal who copied the code.

Better non-covert protection:

- Keep the highest-value tuning layer, datasets, or support process private.
- Publish an AGPL core and offer a commercial license.
- Add SPDX headers and clear notices.
- Put copyright/provenance markers in generated benchmark output and docs.
- Use visible, harmless implementation fingerprints that help prove copying.
- Keep dated tags/releases for authorship evidence.
- Make commercial collaboration easier than silent copying.

Avoid hidden phone-home or stealth license enforcement. It creates security-review risk and gives infringers an argument against the project.

## Better Public Framing

Use language like:

- "multi-engine native database research system"
- "exactness-first candidate filtering and reranking"
- "native C data-plane with optional SIMD acceleration"
- "stable/experimental engine matrix"
- "measured benchmark profiles"
- "AGPL core with commercial licensing available"

Avoid language like:

- "endgame"
- "any workload, any scale"
- "military-grade" without formal scope
- "zero trace"
- "silent callout"
- "stealth integrity"

## How To Make People Want To Work With You

The strongest signal is not a trap. It is a trail of evidence:

- multiple serious repos;
- reproducible tests;
- clear benchmark methods;
- honest status labels;
- auditable security design;
- explicit licensing;
- clean commercial path;
- documentation that shows judgment as well as technical force.

The desired impression should be:

> This author can build deep native systems, understands performance and correctness, and is serious enough that working with them is safer than copying them.

## `.DS_Store` Integrity Idea

The instinct behind hiding an integrity marker in a boring file is understandable: attackers often ignore mundane files, and deception can be useful in defensive systems.

But for military contractors or other high-assurance buyers, `.DS_Store` is weak as the primary integrity root. They will care less about cleverness and more about auditability:

- Is the integrity root documented?
- Can it be backed up and rotated?
- Can endpoint cleanup tools accidentally remove it?
- Can SIEM/EDR monitor it?
- Does it behave consistently on Linux, macOS, containers, and restricted hosts?
- What happens once an attacker learns the trick?
- Does it comply with file hygiene and evidence-handling policies?

Recommended framing:

- Use an explicit primary integrity file such as `qihse_integrity.chain`, `qihse_audit.hashlog`, or similar.
- Anchor the hash chain to TPM, HSM, YubiKey, operator-held key material, or signed checkpoints where possible.
- Export signed checkpoints to external storage.
- Define incident behavior clearly: read-only lockdown, preserve evidence, require authorized recovery.
- Treat `.DS_Store` only as an optional documented canary/tamper tripwire, not the primary root of trust.

Good wording:

> QIHSE supports documented tamper-evident canaries in addition to the primary audit hash chain.

Avoid wording:

> stealth integrity
> hidden root of trust
> attacker will never think to look here

The better story is not "we hid it." The better story is "we have an auditable integrity chain, plus optional deception canaries for defense in depth."
