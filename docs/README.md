# Verification evidence

This directory records what was checked on **real, disposable Flex Gateway
deployments**: the behavior that the library tests and the local `pdk_test` suites
can't establish on their own. Each run has two files:

- a report (`*.md`) with the setup, each case's config, request, wire result and
  upstream hit count, and its disposition;
- a machine-readable file (`evidence/*.json`) with artifact identity, WASM SHA-256,
  timestamps, statuses, dispositions and resource-deletion status.

Every resource a run created was deleted, and each report records how deletion was
confirmed. Org, environment and client ids, secrets, registration material, digest
keys, hostnames and IPs are not recorded. Where a field needs one, it holds a
placeholder such as `<ANYPOINT_ORG_ID>`.

## Dispositions

| Disposition | Meaning |
| --- | --- |
| **PASS** | The case's stated predicate held on a real gateway. |
| **QUALIFIED** | It held under a stated substitution or limit, which the report gives. |
| **OBSERVED** | The case records behavior rather than asserting it, for example per-worker scope. |
| **FAIL** | The predicate did not hold. None are open. |

## Runs

| Date (UTC) | Policy | Report | Evidence | Result |
| --- | --- | --- | --- | --- |
| 2026-09-25 | Approval-to-Execution Binding | [P5/P6 connected verification](APPROVAL-P6-CONNECTED-2026-09-25.md) | [JSON](evidence/approval-p6-connected-2026-09-25.json) | Qualified partial: P5 with real Client ID Enforcement and same-replica replay rejection proven; cross-replica and restart reopening observed as `local()` limits |
| 2026-09-25 | Approval-to-Execution Binding | [Storage unavailable (case 4)](APPROVAL-STORAGE-UNAVAILABLE-2026-09-25.md) | [JSON](evidence/approval-storage-unavailable-2026-09-25.json) | Qualified: the fail-closed branch is correct by inspection but unreachable on `local()` |
| 2026-10-01 to 10-03 | Cross-Session Aggregate-Risk Gate | [Real-gateway cases 1–9, plus 2c, 2d and 8b](AGGREGATE-RISK-CONNECTED-2026-10-01.md) | [JSON](evidence/aggregate-risk-connected-2026-10-01.json) | 8 pass, including 2c with real Client ID Enforcement on a connected gateway; 3 qualified; 3 observed; none failed |
| 2026-10-02 | Cross-Session Aggregate-Risk Gate | [Pinned-toolchain Exchange publication](AGGREGATE-RISK-PUBLISH-2026-10-02.md) | [JSON](evidence/aggregate-risk-publish-2026-10-02.json) | Pass, as a development publish with cargo-anypoint 1.10.0 |

## Briefs and harnesses

- **Aggregate-risk gate:**
  - brief: [`aggregate-risk-gate/docs/ASTRA-TASK-aggregate-risk-connected.md`](../aggregate-risk-gate/docs/ASTRA-TASK-aggregate-risk-connected.md)
  - harness: `aggregate-risk-gate/tests/connected_e2e.rs`, which CI runs in the `runtime-e2e` job, except the hand-run `case2c`
- **Approval binding:**
  - brief: [`approval-execution-binding/docs/ASTRA-TASK-approval-p6-replay.md`](../approval-execution-binding/docs/ASTRA-TASK-approval-p6-replay.md)
  - runnable extension: [`approval-execution-binding/tests/CONNECTED.md`](../approval-execution-binding/tests/CONNECTED.md)
- **Operator handoff (historical):** [`CODEX-HANDOFF.md`](CODEX-HANDOFF.md) holds the authorization, handling and honesty rules every run followed.

## Rules for adding a run

1. Use only disposable, explicitly authorized resources. Never use a shared or customer gateway or org.
2. Report the wire result as observed. If an expectation doesn't hold, file an issue with the evidence. Don't patch the policy to make an assertion pass.
3. Count a policy change as enforced only after a UI Save & Apply has deployed it. An API PATCH alone is not enforcement.
4. Delete every resource afterwards, and record how you confirmed the deletion.
5. Before committing, run the redaction check in [CONTRIBUTING.md](../CONTRIBUTING.md#redaction).
