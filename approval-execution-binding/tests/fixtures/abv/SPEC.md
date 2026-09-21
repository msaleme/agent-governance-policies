# Approval Binding Vectors (ABV) v0.1

A protocol-neutral conformance corpus for one question:

> **Does this record prove that what executed is what was approved?**

It is not a protocol. It defines six predicates, a canonical form, a neutral record shape
for expressing test cases, and a vector set in which every negative case fails exactly one
predicate — with positive controls that MUST be accepted.

**ABV v0.1 is a single-use, separate-attester profile.** That is a choice, not a claim about
what every approval must be. A protocol with legitimately reusable approvals, or one that
places authority elsewhere, may decline P5 or P6 without being non-conforming to itself.

## Why this exists

Agent protocols are converging on an approval record, and they are arriving at the same gap
by different routes. Each protocol's own conformance vectors are welded to its own record
shape, so an implementer cannot reuse another's work and a reader cannot compare two
protocols' guarantees. ABV is the part that is common to all of them.

Nothing here is novel cryptography. The contribution is the **predicate decomposition** and
the insistence on positive controls.

## The six predicates

A binding is *sound* for a given execution when all six hold. Each vector in this corpus
negates exactly one.

| ID | Predicate | The failure it excludes |
|---|---|---|
| **P1** | **Action.** The approval's scope commits to the executed action identifier. | Approved tool A, executed tool B. |
| **P2** | **Arguments.** The approval's scope commits to the executed argument bytes. | Approved tool A with args X, executed A with args Y. |
| **P3** | **Dereference.** Where either side names content by reference, the commitment covers the *dereferenced bytes*, and the executor verifies and then consumes **those same bytes**. | Approval commits a URI; the bytes behind it change before execution. Or: the executor hashes, then re-fetches. |
| **P4** | **Freshness.** The approval is valid at the instant of execution. | Approval correctly scoped, granted, and expired before it was used. |
| **P5** | **Separate attester.** An approval attestation exists, its attester is **not** an executing party, its key is one the verifier holds, and the attestation verifies over the approval scope. | A record in which the executor is also the only witness that it was approved. |
| **P6** | **Single use.** An approval authorises at most one execution. **This is a profile choice, not a universal requirement** — a standing budget or allowlist is legitimately reusable. ABV defines a *single-use* profile; a protocol with a different reuse bound is not thereby non-conforming to itself. | One approval replayed for a second execution. |

P1 and P2 are separate on purpose. A joint commitment over `(action, arguments)` satisfies
both, but splitting them lets an operator distinguish *someone approved a different tool*
from *someone approved the same tool with different arguments*, which are different
incidents with different responses.

P5 is the predicate most often absent. A record can satisfy P1–P4 completely and still be a
document its own author wrote about itself.

**P5 does not test authority for the scope.** It establishes that a *separate, authenticated*
party attested the approval. It does **not** establish that that party was entitled to approve
this action — entitlement is a policy question the record cannot answer on its own, and
conflating the two would repeat the error this decomposition exists to avoid. A checker
passing P5 has shown separateness and authentication, nothing more.

### Precedence between P2 and P3

When an argument is carried by reference, a change to that argument **is** a change to the
dereferenced bytes, and the two predicates overlap. The rule: **P3 takes precedence whenever
a reference is involved**, because it is the more specific diagnosis — it tells the operator
the commitment was over the wrong bytes rather than that the caller passed different values.
P2 vectors in this corpus therefore carry no references at all, which is what makes the two
independently testable. This was found by running the corpus, not by designing it; the first
draft's P2 vectors used referenced arguments and were correctly classified P3.

## Canonical form

Digests are SHA-256 over **JCS** ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785))
serialization of the covered object, lowercase hex, unprefixed.

Two rules that RFC 8785 does not settle and that every implementation must state:

1. **Covered members.** A record that carries its own digest must say whether the digest
   member is *removed* before hashing or *substituted* with a fixed placeholder. Both are
   sound; they produce different digests for an identical document. ABV specifies
   **removal**, and a profile that does otherwise must say so.
2. **Referenced content.** A member naming content by reference contributes the digest of
   the **dereferenced bytes**, not the reference string. A profile that commits a URI
   without a sibling digest does not satisfy P3.

**A canonicalization mismatch MUST reject before execution.** An implementation that logs a
mismatch and proceeds has implemented no binding at all, and an implementation that treats a
mismatch as an internal error and retries has implemented a slower one.

## Verdicts

A checker returns `accept` or `reject`. A `reject` carries the predicate it failed.

A conforming checker MUST:
- reject every `NEG-*` vector, **naming the predicate the vector negates**, and
- accept every `CTRL-*` vector.

Naming the predicate matters. A checker that rejects `NEG-P4-01` for the wrong reason has
not demonstrated it implements P4; it has demonstrated it rejects that file.

## Acceptance controls (read this before claiming a pass)

**A checker that rejects everything satisfies every negative vector in this corpus.** That
is why `CTRL-*` exists and why it is not optional. A submitted result that reports
`NEG` passes without `CTRL` passes is not a result.

Two further controls, both learned from real suites:

- **`CTRL-02` is a near-miss.** It differs from a negative vector in one byte that should
  not matter — a re-ordered object, a different but equivalent number form. A checker that
  rejects it has a canonicalization bug that the other controls cannot see.
- **The positive path must be deterministic.** A positive control wired to a real
  side-effecting operation fails for reasons unrelated to the binding, and a test that fails
  for unrelated reasons is one that eventually gets muted. ABV vectors are pure data.

## Neutral record shape

Vectors are expressed in a minimal shape so that the corpus does not privilege any
protocol's field names. A profile (`profiles/`) maps a real protocol onto it.

```json
{
  "abv": "0.1",
  "id": "NEG-P2-01",
  "negates": "P2",
  "request":   { "action": "...", "arguments": { ... } },
  "approval":  { "scope": { "action": "...", "arguments_digest": "..." },
                 "authority": "...", "not_after": "...", "nonce": "..." },
  "execution": { "action": "...", "arguments": { ... }, "at": "...", "status": "..." },
  "attestations": [ { "claim": "approval", "authority": "...", "mac": "..." } ],
  "expect": { "verdict": "reject", "predicate": "P2" }
}
```

`mac` is a keyed digest standing in for a signature. ABV deliberately does **not** specify a
signature algorithm: P5 is about whether the attesting party is distinct from the executing
one, which is a structural property, and requiring a specific curve would make the corpus
harder to adopt without testing anything additional. A profile MAY substitute real
signatures.

## What this corpus does not test

- Whether a proposed action is *harmful*. Binding says the executed action is the approved
  one; it says nothing about whether approving it was wise.
- Whether an enforcement point exists that the executing party cannot bypass. That is an
  architectural property, not a record property, and a sound record checked by the adversary
  proves nothing. ABV tests the record; deployment must supply the boundary.
- Transport, identity proofing, key custody, or revocation.

## Provenance

Each predicate has at least one observed referent in a real specification; see
`profiles/OBSERVED.md`. No predicate here was invented for symmetry.
