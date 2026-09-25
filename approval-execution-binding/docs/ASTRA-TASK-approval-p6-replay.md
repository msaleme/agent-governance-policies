# Astra task — end-to-end validation of P6 single-use replay (and P5 attestation) on a real Flex Gateway

**Owner:** Astra (autonomous agent on a disposable, authorized gateway).
**Why this is handed off:** the reviewer findings #3 (atomic single-use) and #6/#4/#5
(verified-executor + versioned attested payload) are fully unit-tested in-process with the
`pdk_unit` harness, but a small set of behaviours can only be *proven* against a real Flex
Gateway container talking to a real upstream. Those are enumerated below. This machine does
**not** run Docker `pdk_test`, so this brief is the record of what must still be exercised
before we claim end-to-end P5/P6 enforcement, and how.

Do **not** treat this document as evidence the behaviours pass — it is a task list. Monitor
mode is not enforcement; a green unit suite is not a green container run.

---

## Background: what is already proven in-process (do not re-litigate)

The `#[cfg(test)]` suite in `src/test.rs` (driven by the vendored ABV vectors plus
hand-written edge cases) covers, deterministically and offline:

- **#3 single-use (P6):** `DataStorage::store(&nonce, &StoreMode::Absent, &1u8)` — first
  reservation returns `Ok` (allow), a second reservation of the same nonce returns
  `Err(CasMismatch)` (replay → P6 deny), any other `Err` → **fail closed**. Monitor mode does
  **not** reserve. The `pdk_unit` `OSBackend` persists the store across `.request()` calls in
  one test, so the replay is a real second write against the same in-memory store.
- **#6 verified executor:** executor read from `AuthenticationData` (client_id then
  principal); when absent **and P5 required**, fail closed; when absent and P5 not required,
  fall back to the configured header. A test injects `AuthenticationData = X` plus a spoofed
  header `= Y` and proves P5 authenticates against `X`.
- **#4/#5 versioned attested payload:** P5 MAC covers the canonical-JSON `mcp-v1` payload
  `{v, iss, aud, tenant, env, sub, action, arguments_digest, not_after, nonce}`; mutating any
  protected claim flips the verdict to deny; kid rotation works; `expected_*` config is
  required (non-empty) whenever P5 is required.

## What only a real gateway can prove (the actual Astra task)

1. **Cross-request nonce persistence through the real gateway data store.**
   The unit harness uses an in-process `OSBackend` map. A real Flex Gateway backs
   `store_builder.local("approval-nonces")` with its own runtime store. Prove: send a sound,
   P6-required `tools/call` twice (same nonce) through a *running* container; assert the first
   forwards to the upstream and the second is denied with `predicate=P6`, and that the upstream
   is hit exactly once.

2. **Restart / eviction semantics of `local()`.**
   `local()` storage has **no TTL control exposed to the policy** and its durability across a
   gateway **restart** or pod reschedule is runtime-defined, not guaranteed by this policy.
   Prove (or document the observed behaviour): reserve a nonce, restart the gateway, replay the
   same nonce. If the store is in-memory-only, the replay will be *allowed* after restart — that
   is a **known limitation of the demo build**, not a bug in the binding logic. Record the
   result so the limitation is stated honestly in customer conversations.

3. **Cross-replica behaviour (horizontal scale).**
   `local()` is **per-replica**. Two gateway replicas behind a load balancer will *not* share
   nonce reservations, so a replayed approval can slip through on a second replica. Prove this
   with a 2-replica composite, then confirm the **fix path**: swapping `local()` for a
   **shared/remote** store (`store_builder.remote(...)` / Anypoint Shared Storage) makes the
   reservation global. The single-replica demo is honest only if this constraint is stated.

4. **Storage-unavailable → fail-closed, on a real store.**
   The "other `Err` → fail closed" branch is **not unit-triggerable** (the in-process backend
   never errors except `CasMismatch`). Prove it against a real gateway by making the data store
   unreachable (e.g. misconfigure/withdraw the store backend) and asserting a P6-required call
   is **denied**, not allowed-through.

5. **P5 end-to-end with a real upstream identity policy.**
   The two committed `tests/requests.rs` `#[pdk_test]` cases bind **only P1+P2** because P5
   needs a verified `AuthenticationData` subject from an upstream auth policy (OIDC / JWT /
   Client-ID Enforcement) placed before this policy. Add a composite that chains a real
   authentication policy, mints a real `mcp-v1` HMAC with a ≥32-byte key held by the gateway,
   and proves an approval attested by a *different* authority than the verified executor passes
   P5 while a self-attested one fails.

## Baseline to build on

- Fetch `origin/main`; the verified checkpoint is squash commit **`1e46807`** (PR #19, which
  merged reviewer findings #1–#7). Branch fresh off it; confirm `git rev-parse --show-toplevel`
  is this repo before staging. See `../../docs/CODEX-HANDOFF.md` for authorization/handling.
- `approval-execution-binding/tests/requests.rs` already ships **two** `#[pdk_test]` composite
  cases that bind **P1+P2 only** (`sound_approval_reaches_the_real_upstream_end_to_end` allow +
  `action_mismatch_is_denied_end_to_end_and_never_reaches_upstream` P1-deny). Extend that file
  for the P5/P6 cases below — do not rewrite the existing two.

## How to run (disposable, authorized gateway only)

- Use a **disposable, authorized** Flex Gateway — never a shared/customer gateway. Churn is
  expected here.
- `tests/requests.rs` already builds the composite pattern (`TestComposite` + `Flex 1.14.0` +
  `HttpMock`). Extend it; do not run it on this machine (no Docker `pdk_test` runtime here).
- **Never churn a live MCP instance** with repeated API PATCH + Save&Apply — it corrupts
  gateway route state (empty-body 503). If an instance wedges, **delete and recreate** it.
- **API PATCH ≠ enforcement:** config reaches the running gateway only after a **UI Save &
  Apply** (watch `deployment.updatedDate` bump, status Active→Updating→Active). Assert
  enforcement only after that push, never off the PATCH alone.

## Boundaries (load-bearing)

- **Verification only.** Do not change runtime behaviour, the `Predicate` enum, or the GCL
  schema. If a prescribed expectation fails on a real gateway, **file a GitHub issue with the
  captured evidence — do not patch the policy to make it pass.**
- Keep everything inside the explicitly-authorized disposable scope; do not infer shared-API
  or production-mutation authority. **Delete every test resource afterward and confirm it.**
- **Never print, log, or copy identity/credential material** (registration YAML, tokens, the
  ≥32-byte attester key) into evidence, commits, or issues. Never treat headers as trusted
  provenance.

## Evidence artifact (mirror `agent-decoy-policies/docs/evidence/`)

Commit a pair:

1. A human-readable evidence doc (per case: coordinator/policy config, request, **actual**
   wire result, backend hit-count, disposition, and for #2/#3 the observed restart/replica
   behaviour stated honestly).
2. A machine-readable `docs/evidence/approval-p6-connected-<UTC-date>.json` capturing:
   artifact identity, **WASM SHA-256** of the built policy, UTC timestamps, HTTP statuses,
   per-case dispositions, `PolicyViolation` counts, and **resource-deletion status**.

State plainly which cases passed, which are qualified, and which failed — do not present a
partial run as all-green.

## Definition of done

CI (`policies` + GitGuardian) green; a committed, reproducible evidence doc + JSON produced
on a real disposable gateway for cases 1–5 above (or GitHub issues filed for any that don't
hold), with all disposable resources deleted and deletion confirmed; the two publish-time
items either confirmed or recorded as still-pending. Open a PR from a fresh topic branch; do
**not** merge to this public repo without the maintainer's explicit go.

## Publish-time items

- **GCL sensitive-key syntax — FIXED (issue #21), locally verified.** The reviewer's #1
  sensitive-key marker was first written as a bare `characteristics: [security:sensitive]`,
  which PDK's GCL→JSON-Schema compiler rejects (`strict mode: unknown keyword:
  "characteristics"`) and which therefore blocked the whole connected run. It is now the
  doc-supported JSON-LD form on `attesterKeys[].key`:
  ```yaml
  key:
    type: string
    "@context":
      "@characteristics":
        - "security:sensitive"
  ```
  Verified locally with `anypoint-cli-v4 pdk policy-project build-asset-files`:
  `target/definition/schema.json` now generates and preserves the marker (no bare
  `characteristics` leaks). **Re-confirm on a real Exchange publish** — the local check
  proves the same ajv strict-mode step that Exchange runs, but only a live publish proves
  Exchange acceptance end to end.
- **Build/publish targets.** There is no `make package` target (an earlier draft of this brief
  said so — corrected). The real chain is **`make build`** (→ `build-asset-files`, the step
  that generates and validates the schema above) then **`make publish`/`make release`**.
  `cargo-anypoint` is pinned to **1.10.0** in both `Makefile`s; the local check above ran with
  1.9.0 (which reproduces the identical schema behaviour) — run `make build`/`publish` under
  1.10.0 on the real toolchain before publishing.
- **`metadata/capabilities/assetTypes: mcp`** is prescribed by the reviewer but has **no
  in-repo precedent** and the CI gate does not lint it — confirm Exchange/Anypoint accepts it
  when the policy is published.
