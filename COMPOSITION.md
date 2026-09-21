# Composition notes

The two policies in this repository are independent WebAssembly filters. They do
not share proxy-WASM state and MUST NOT use request or response headers as
cross-policy control state. A gateway deployment that runs both owns ordering and
the final forwarding decision.

## Running both on one route

Both are inbound authorization checks that admit one JSON-RPC 2.0 envelope, make a
local decision, and either forward unchanged or deny (JSON-RPC `-32008` or empty
`403`). Neither rewrites a forwarded body. They compose additively because they
answer different questions about the same call:

1. **Approval-to-Execution Binding** — *is this the action that was approved?*
   (integrity of a specific mandate).
2. **Cross-Session Aggregate-Risk Gate** — *does this call, added to everything
   already authorized, stay within the shared budget?* (cumulative exposure).

A call must satisfy both to proceed. Recommended order in a chain is
approval-binding first (reject an unauthorized/altered action before it consumes
any budget), then the aggregate-risk gate. Both belong after identity/admission
policies such as `mcp-support` and `mcp-access-control` and before the call
reaches the upstream tool.

## Boundaries

- **No shared state.** Each filter decides from the request in front of it plus
  its own configuration (and, for the aggregate-risk gate, its own per-worker
  ledger). One filter's denial rendering is not an input to the other.
- **Independent budgets and records.** The aggregate-risk gate's ledger is not
  aware of approval records, and approval-binding does not track exposure. Running
  them together does not merge those concerns; it layers two separate checks.
- **Additive to Agent Fabric.** Both deploy as PDK policies on the Flex/Omni
  gateway instances already fronting the fabric's A2A brokers and MCP tools, keyed
  to the identity the fabric already carries. Neither requires a broker, agent, or
  backend change.
