# Codex / Astra handoff — connected-mode verification of `approval-execution-binding`

Read this first, then the task brief it points to. This is an **orientation +
authorization** document, not evidence that anything passes.

## Ownership note (this repo differs from `agent-decoy-policies`)

Unlike the decoy-policies repo, **this repository is authored directly on the
maintainer's machine** — it is *not* an Astra-owned autonomous worktree. So:

- Do **not** assume local edits here are disposable/discardable. Treat `origin/main`
  as the source of truth: **fetch `origin/main`, branch fresh, and open a PR** for any
  change. Never force-push or rewrite `main`.
- Before staging anything, confirm `git rev-parse --show-toplevel` resolves to a
  checkout of `github.com/msaleme/agent-governance-policies` (a same-named directory
  elsewhere on the host may be an unrelated repo).

## Working state (verified checkpoint)

- Both Tier-1 policies live here: **`approval-execution-binding/`** and
  **`aggregate-risk-gate/`** (Rust + PDK 1.10.0, `wasm32-wasip1`, toolchain 1.89.0).
- Reviewer findings **#1–#7** on `approval-execution-binding` (Tommaso Bolis, P4A) are
  **code-resolved and merged**: squash commit **`1e46807`** via **PR #19**
  (`fix/approval-binding-1-7-reviewer-findings`, branch deleted). CI **`policies`** gate
  and **GitGuardian** both green on that PR; local `main` == `origin/main`, clean tree.
- There are **no release tags** in this repo. Anchor on the merged commit above; do not
  cut or publish a release as part of this task.
- `aggregate-risk-gate` was untouched by #1–#7 except a `Makefile` `cargo-anypoint`
  version bump; its suite is green (no regression). It has **no open reviewer findings**.

## Your task

**Prove — on a real, disposable, explicitly-authorized Flex/Omni Gateway — the small set
of behaviours that Local Mode cannot,** enumerated in:

> `approval-execution-binding/docs/ASTRA-TASK-approval-p6-replay.md`

In short: cross-request/cross-replica/restart nonce single-use (#3), storage-unavailable
fail-closed (#3), and the P5 attested-payload path with a real upstream auth policy
(#4/#5/#6) — plus the two publish-time GCL/toolchain items. The in-process `pdk_unit`
suite already proves the deterministic parts; **do not re-litigate those** — see the
brief's "already proven in-process" section.

This is a **verification** task. If a prescribed expectation does not hold on a real
gateway, **file a GitHub issue with the captured evidence — do not patch the policy to
make an assertion pass**, and do not change runtime behaviour, enums, or the GCL schema.

## Authorization & handling (load-bearing)

- Use only a **disposable, explicitly-authorized** gateway, upstream, network and
  registration identity. **Never** a shared or customer gateway/org. Churn is expected in
  that disposable scope only — do not infer shared-API or production mutation authority.
- **Delete every test resource afterward** (gateway, API instances, any test Exchange
  versions, upstream, network, registration) and **confirm deletion** in the evidence.
- **Never print, log, or copy identity/credential material** (registration YAML, tokens,
  keys) into evidence, commits, or issues.
- **Never churn a live MCP instance** with repeated API PATCH + Save & Apply — it corrupts
  gateway route state (empty-body 503). If an instance wedges, **delete and recreate** it.
- Remember **API PATCH ≠ enforcement**: a config change reaches the running gateway only
  after a **UI Save & Apply** (watch `deployment.updatedDate` bump, status
  Active→Updating→Active) — assert enforcement only after that.

## Honesty rules (must be reflected in the evidence)

- **Monitor mode is not enforcement**, and a green unit suite is **not** a green container
  run — never present one as the other.
- **`local()` nonce storage is per-replica with no policy-controlled TTL.** A replay can
  slip through on a second replica or after a restart. That is a **known limitation of the
  single-replica demo build**, not a bug in the binding logic — record it honestly and note
  the fix path (a shared/remote store makes the reservation global).
- **Never treat request headers as trusted provenance** or as cross-policy control state.

## Evidence (mirror the decoy repo's discipline)

Record results as a committed pair, mirroring `agent-decoy-policies/docs/evidence/`:

- a human-readable `docs/COORDINATOR-STYLE` evidence doc (per-case: config, request,
  actual wire result, backend hit-count, disposition), and
- a machine-readable `docs/evidence/approval-p6-connected-<UTC-date>.json` capturing:
  artifact identity, **WASM SHA-256**, UTC timestamps, HTTP statuses, per-case
  dispositions, PolicyViolation counts, and **resource-deletion status**.

## Definition of done

Open a PR from a fresh topic branch off `origin/main` with: the evidence doc + JSON on a
real gateway for the brief's cases (or issues filed for any that don't hold), all disposable
resources deleted and confirmed, CI (`policies` + GitGuardian) green, and the publish-time
items (`make build`/`make publish` under cargo-anypoint 1.10.0; GCL `assetTypes: mcp`
acceptance on a real Exchange publish) either confirmed or recorded as still-pending. The GCL
sensitive-key syntax that first blocked the run (issue #21) is **fixed and locally verified** —
`build-asset-files` now generates `schema.json` — but re-confirm it on a live Exchange publish.
Do not merge to this public repo without the maintainer's explicit go.
