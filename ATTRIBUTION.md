# Attribution and license scope

## Project contributions and upstream notices

Agent Governance Policies is maintained by [msaleme](https://github.com/msaleme).
Project-authored contributions are offered under the [MIT License](LICENSE).
Third-party code, templates, dependencies, and documentation retain their own
copyright notices and terms; the root MIT license does not relicense them.

Both policies were scaffolded from the MuleSoft Policy Development Kit (PDK)
project template. The initial scaffold files carry
`Copyright 2026 Salesforce, Inc. All rights reserved.` notices in their headers;
project modifications add a separate MIT notice alongside them. Future changes
must preserve the upstream notices. The precise original scaffold/tool release is
not recorded in Git; the currently pinned SDK version is not proof of that
historical provenance.

The current PDK 1.10.0 crates supply Salesforce Terms of Use in `LICENSE.txt`, not
an MIT or Apache SPDX declaration. A verbatim copy is retained in
[licenses/Salesforce-PDK-1.10.0.txt](licenses/Salesforce-PDK-1.10.0.txt), taken
from the locked `pdk` crate. Its SHA-256 is
`40e41c7b6c998968bc1c26002776215f57055cdb78c3795c61cef0d269d8fd05`.
This records the SDK's supplied terms; it does not establish the license of every
historical template file. Preserve component-specific notices when distributing
source or compiled artifacts.

## Reference corpora

These policies are gateway enforcement boundaries for prior, separately published
research corpora. The corpora define *what a correct check means*; the policies
add the runtime that performs it. The corpora are cited, not relicensed here.

- **Approval-to-Execution Binding** vendors the `approval-binding-vectors` (ABV
  v0.1) conformance corpus into `approval-execution-binding/tests/fixtures/abv/`
  as its test fixtures (12 vectors: 3 positive controls + 9 negative predicate
  cases). The ABV corpus is MIT-licensed and was built for exactly this purpose;
  its `SPEC.md` defines the P1–P6 predicate semantics and the P2/P3 precedence and
  canonicalization rules the policy implements. The corpus tests a *record*; it
  explicitly notes that the enforcement boundary is an architectural property the
  corpus itself cannot observe.
- **Cross-Session Aggregate-Risk Gate** implements the reserve-then-authorize
  model demonstrated by the `authorized-but-composed` reference work
  (`github.com/msaleme/authorized-but-composed`), companion code to the position
  paper *"Authorized but Composed: Cross-Session Risk Composition as an
  Agent-Governance Control"* (Michael K. Saleme), Zenodo concept DOI
  [10.5281/zenodo.21400261](https://doi.org/10.5281/zenodo.21400261); its
  single-action sibling is *"Authorized but Refused"*
  ([10.5281/zenodo.21263262](https://doi.org/10.5281/zenodo.21263262)). The
  corpus's conformance fixtures and verifier are also exercised inside the
  `red-team-blue-team-agent-fabric` security harness
  (`github.com/msaleme/red-team-blue-team-agent-fabric`). The concurrency scenarios
  there are synthetic and simulated; this repository reproduces the
  naive-counter-breaches vs. reserve-then-authorize-holds contrast as executable
  Rust tests, not as a claim of production telemetry or a safety benchmark. The
  corpus `verify` step is a replay/consistency check, not an independently provable
  signed attestation.

## Protocol specifications

These policies inspect and enforce on live agent-protocol traffic; they implement
the wire formats defined by the following specifications (cited as the governed
protocols, not as an endorsement or a conformance claim by their maintainers):

- **Model Context Protocol (MCP)** — the JSON-RPC tool-calling protocol both
  policies admit and gate on MCP instances: [modelcontextprotocol.io](https://modelcontextprotocol.io).
- **Agent2Agent (A2A)** — the agent-to-agent protocol these policies gate on A2A
  instances: [a2a-protocol.org](https://a2a-protocol.org) /
  [github.com/a2aproject/A2A](https://github.com/a2aproject/A2A).
- **JSON-RPC 2.0** — the envelope both protocols share and these policies parse,
  including the `-32008` in-band error rendering on denial:
  [jsonrpc.org/specification](https://www.jsonrpc.org/specification).

## Direct Rust dependencies

Versions and license declarations below were read from the committed per-policy
`Cargo.lock` files. Dependencies are fetched by Cargo; their source is not vendored
here. This is a direct-dependency summary, not an exhaustive transitive license
inventory for a binary release.

| Dependency | Locked version | Used by | Upstream declaration / source |
| --- | --- | --- | --- |
| `pdk` | 1.10.0 | both | Salesforce `LICENSE.txt`; [MuleSoft PDK](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview) |
| `serde` | 1.0.229 | both | MIT OR Apache-2.0; [serde-rs/serde](https://github.com/serde-rs/serde) |
| `serde_json` | 1.0.151 | both | MIT OR Apache-2.0; [serde-rs/json](https://github.com/serde-rs/json) |
| `anyhow` | 1.0.104 | both | MIT OR Apache-2.0; [dtolnay/anyhow](https://github.com/dtolnay/anyhow) |
| `sha2` | 0.10.9 | approval-execution-binding | MIT OR Apache-2.0; [RustCrypto/hashes](https://github.com/RustCrypto/hashes) |
| `hmac` | 0.12.1 | approval-execution-binding | MIT OR Apache-2.0; [RustCrypto/MACs](https://github.com/RustCrypto/MACs) |
| `chrono` | 0.4.45 | approval-execution-binding | MIT OR Apache-2.0; [chronotope/chrono](https://github.com/chronotope/chrono) |
| `pdk-test`, `pdk-unit` (tests) | 1.10.0 | both | Salesforce `LICENSE.txt` in each crate |
| `httpmock` (tests) | 0.6.8 | both | MIT; [alexliesenfeld/httpmock](https://github.com/alexliesenfeld/httpmock) |
| `reqwest` (tests) | 0.11.27 | both | MIT OR Apache-2.0; [seanmonstar/reqwest](https://github.com/seanmonstar/reqwest) |

The PDK also resolves internal crates such as `pdk-classy`; inspect the complete
resolved dependency tree and its notices before distributing WASM bundles. Docker
images and build tools are separate upstream products with their own terms.

## Design references

The policies apply access-governance and resource-governance concepts to gateway
policy enforcement. The identifiers below describe design context, not a
certification, and no single policy decision establishes compliance coverage.

- **NIST:** [SP 800-53 Rev. 5](https://doi.org/10.6028/NIST.SP.800-53r5) supplies
  the control references cited in each policy README (Access Enforcement,
  Information Flow Enforcement, Non-repudiation, Boundary Protection, and Event
  Logging control families). These references are not certification.
- **OWASP:** the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/)
  provides threat context (Excessive Agency; Unbounded Consumption). A policy
  decision alone does not establish exploitation or compliance coverage.
- **MITRE:** [ATLAS](https://atlas.mitre.org/) and
  [Engage](https://engage.mitre.org/) provide adversary-behavior and engagement
  vocabulary used as design context; these policies provide detection and bounded
  enforcement, not a complete adversary-engagement environment.
- **EU AI Act (Regulation (EU) 2024/1689):** Articles 9, 12, 14, and 15 are cited
  as forward-looking supporting-measure context. The high-risk obligations these
  articles carry are phased and do not bind until 2027–2028; nothing here is a
  claim of present AI Act conformity, and conformity assessment attaches to a whole
  high-risk system, not a point gateway policy.
- **AIUC-1:** a private, insurer-backed certification for whole AI agents. These
  policies map to its Security and Accountability domains as *supporting technical
  measures / enabling evidence* for a customer's own evaluations. A PDK policy is
  not a certifiable unit and is not "AIUC-1 certified."
- **MuleSoft / Salesforce:** the [PDK documentation](https://docs.mulesoft.com/pdk/latest/)
  and [public policy examples](https://github.com/mulesoft/pdk-custom-policy-examples)
  provide the gateway development context.

References to organizations, products, and frameworks identify sources and
compatibility targets; they do not imply endorsement or a marketplace listing.
