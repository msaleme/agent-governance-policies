// Copyright 2026 msaleme. Licensed under the MIT License.
//
// Cross-Session Aggregate-Risk Gate — a PDK policy that catches "death by a
// thousand authorized cuts": individually valid calls that each clear their own
// per-session cap, but compose across sessions past an aggregate exposure budget
// no per-call control ever sees. A per-call gate, a rate limit, and a per-session
// cap are all structurally blind to the SUM; this policy is a control that sees
// it.
//
// Mechanism: reserve-then-authorize. On each governed call this policy computes
// the call's exposure contribution (a token-cost estimate, a spend amount read
// from the request body, or a fixed per-call weight), atomically reserves that
// contribution against a serialized ledger keyed by budget scope (agent, fabric,
// or tenant) BEFORE authorizing, allows the call only if committed-plus-reserved
// exposure stays within the aggregate budget, commits the reservation once the
// upstream call succeeds, and releases it if the call fails. This order is the
// whole point, and is exhaustively proven correct (including under real
// concurrency) in `ledger.rs`: a naive read-then-write counter breaches the
// budget because concurrent callers can all read the same pre-commit total before
// anyone writes; only serializing the check-and-reserve into one atomic step
// holds it.
//
// This build reproduces the exact scenarios from the companion research
// (github.com/msaleme/authorized-but-composed, MIT/CC BY 4.0): five sessions of
// 800 each clear a 1,000 per-session cap (enforced upstream of this policy, not
// modeled here) but compose to 4,000 against a 3,000 aggregate budget; a naive
// counter authorizes all five under concurrency, while reserve-then-authorize
// admits exactly three (2,400) and refuses the other two.
//
// Honesty boundary (Stage A / Stage B — see also the gcl.yaml field docs and
// README): this build ships Stage A, a real, correct, exhaustively tested
// in-process reserve-then-authorize engine — but it is scoped to a single
// gateway worker's in-memory ledger, not a distributed, multi-region, or
// replay-consistent store, and it makes no cryptographic non-repudiation claim
// about its decisions. A distributed Stage B ledger with signed decision records
// is unshipped roadmap work; the `ledgerEndpoint` config field is reserved for it
// and does nothing in this build.
//
// NIST SP 800-53 Rev 5: AC-6 (Least Privilege / aggregate exposure), SI-4
// (Monitoring), AU-6 (Audit Review — the running-total resultHeader).
mod generated;
mod ledger;

use anyhow::{anyhow, Result};
use pdk::hl::*;
use pdk::logger;
use pdk::policy_violation::PolicyViolations;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::generated::config::Config;
use crate::ledger::{Denial, Ledger, LedgerStore, Reservation};

/// JSON-RPC server-error code used when this policy prevents a call from
/// reaching its upstream tool. Matches the sibling decoy/binding policies in
/// this family so a downstream consumer (SIEM, Kill Switch) can key off one
/// code across the whole gateway.
const MCP_BLOCKED_CODE: i64 = -32008;

/// A body larger than this is not read for pricing/JSON-RPC-echo purposes. This
/// is a latency/inspection admission cap, not a security containment boundary —
/// unlike a tripwire policy, failing to read a body here has an explicit, safe
/// fallback (treat the call as unpriceable, or fall back to the estimate) rather
/// than a risk of missing a hidden secret.
const MAX_INSPECT_BYTES: usize = 64 * 1024;

/// The request body available to this policy for pricing/batch-shape
/// inspection, resolved at the HEADER phase, before any buffering decision.
/// `NoBody` (a genuinely bodyless request) and `Uninspectable` (a body exists
/// but this policy declines to buffer/read it — oversize, non-JSON, or
/// compressed) are kept deliberately distinct: a bodyless call structurally
/// cannot be a hidden batch, but an uninspectable one might be, so only
/// `Uninspectable` is treated as unpriceable — fail-closed in block mode,
/// never silently priced as a single call (see `compute_contribution`).
enum RawBody<'a> {
    NoBody,
    Uninspectable,
    Present(&'a [u8]),
}

impl<'a> RawBody<'a> {
    /// Collapses `NoBody`/`Uninspectable` together for call sites (id-echo on
    /// deny) that only care about having real bytes to parse — both already
    /// fall back to the generic empty-403/202 containment path in
    /// `deny_response`.
    fn as_bytes(&self) -> Option<&'a [u8]> {
        match self {
            RawBody::Present(bytes) => Some(bytes),
            _ => None,
        }
    }
}

/// Whether this request is safe to buffer and inspect at all, checked from
/// headers ALONE, before this filter ever calls `into_headers_body_state()`.
/// Buffering a body only to discover afterward that it was oversized,
/// compressed, or a non-JSON media type would defeat the purpose of gating in
/// the first place. A missing/invalid Content-Length, a declared length over
/// `MAX_INSPECT_BYTES`, a non-JSON Content-Type, or any Content-Encoding
/// (this build never decompresses) all fail this gate. See README.md's
/// "Inspection boundary" section for the SSE/streaming/compressed/non-UTF-8
/// exclusions this enforces.
fn request_is_inspectable(handler: &(impl HeadersHandler + ?Sized)) -> bool {
    let length_ok = handler
        .header("content-length")
        .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|len| len <= MAX_INSPECT_BYTES);
    let json = handler.header("content-type").is_some_and(|value| {
        let media = value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        media == "application/json"
            || (media.starts_with("application/") && media.ends_with("+json"))
    });
    let uncompressed = handler.header("content-encoding").is_none();
    length_ok && json && uncompressed
}

// ---------------------------------------------------------------------------
// JSON-RPC parsing / response shaping. Protocol-generic (not specific to this
// policy's business logic); mirrors the idiom used by the sibling decoy/binding
// policies in this family so a downstream consumer sees the same shape of
// in-band error and the same notification/batch handling everywhere on the
// gateway.
// ---------------------------------------------------------------------------

/// Deserialize JSON while rejecting a duplicate member in any object, so an
/// admission decision (echoing an id, treating a body as a single vs. batch
/// call) can never be based on a differently-parsed view of the same bytes than
/// whatever the upstream tool will eventually see.
struct NoDuplicateMembers;

impl<'de> Deserialize<'de> for NoDuplicateMembers {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;
impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = NoDuplicateMembers;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("JSON with no duplicate object members")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateMembers)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicateMembers>()?.is_some() {}
        Ok(NoDuplicateMembers)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON object member"));
            }
            map.next_value::<NoDuplicateMembers>()?;
        }
        Ok(NoDuplicateMembers)
    }
}

/// The response shape to preserve when denying a parseable JSON-RPC call.
/// Non-JSON-RPC traffic falls back to a generic empty-403 (see `deny_response`).
struct ParsedJsonRpcRequest {
    is_batch: bool,
    response_ids: Vec<Value>,
}

fn parse_jsonrpc_request(body: &[u8]) -> Option<ParsedJsonRpcRequest> {
    if body.len() > MAX_INSPECT_BYTES {
        return None;
    }
    serde_json::from_slice::<NoDuplicateMembers>(body).ok()?;
    let root: Value = serde_json::from_slice(body).ok()?;
    let is_batch = matches!(root, Value::Array(_));
    let items: Vec<&Value> = match &root {
        Value::Array(items) if !items.is_empty() => items.iter().collect(),
        Value::Object(_) => vec![&root],
        _ => return None,
    };

    if items.iter().any(|item| {
        item.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || item.get("method").and_then(Value::as_str).is_none()
            || item
                .get("id")
                .is_some_and(|id| !matches!(id, Value::String(_) | Value::Number(_) | Value::Null))
    }) {
        return None;
    }

    Some(ParsedJsonRpcRequest {
        is_batch,
        response_ids: items
            .iter()
            .filter_map(|item| item.get("id").cloned())
            .collect(),
    })
}

/// Builds the deny response. `raw_body` is used only to decide whether an
/// in-band JSON-RPC error can be safely echoed with the caller's own id;
/// whenever it cannot (not JSON-RPC, a batch this build cannot confidently
/// parse, or `on_deny` is configured for it directly), this always falls back
/// to an empty HTTP 403 — echoing an id this policy cannot trust risks
/// confirming a protected value to the caller.
fn deny_response(
    on_deny: OnDeny,
    raw_body: Option<&[u8]>,
    result_header: &str,
    stamp: &str,
    message: &str,
) -> Response {
    if on_deny == OnDeny::RpcError {
        if let Some(parsed) = raw_body.and_then(parse_jsonrpc_request) {
            if parsed.response_ids.is_empty() {
                // A notification has no id and JSON-RPC forbids a response either way.
                return Response::new(202)
                    .with_headers([(result_header.to_string(), stamp.to_string())]);
            }
            let error = |id: Value| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": MCP_BLOCKED_CODE, "message": message },
                })
            };
            let body = if parsed.is_batch {
                Value::Array(parsed.response_ids.into_iter().map(error).collect()).to_string()
            } else {
                error(
                    parsed
                        .response_ids
                        .into_iter()
                        .next()
                        .expect("response ID exists"),
                )
                .to_string()
            };
            return Response::new(200)
                .with_headers([
                    ("Content-Type".to_string(), "application/json".to_string()),
                    (result_header.to_string(), stamp.to_string()),
                ])
                .with_body(body);
        }
    }
    Response::new(403).with_headers([(result_header.to_string(), stamp.to_string())])
}

// ---------------------------------------------------------------------------
// Configuration surface, validated and compiled once at policy start.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Block,
    Monitor,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OnDeny {
    RpcError,
    EmptyForbidden,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Contribution {
    TokenCost,
    SpendAmount,
    FixedWeight,
}

/// Compiled, validated policy state, built once at configuration time and
/// shared (by reference) across every exchange this instance governs. Owns the
/// Stage A ledger described in the module doc comment.
struct Gate {
    budget_scope: String,
    needs_scope_header: bool,
    scope_header: String,
    aggregate_budget: f64,
    contribution: Contribution,
    fixed_weight: f64,
    spend_amount_field: String,
    estimated_tokens: f64,
    mode: Mode,
    on_deny: OnDeny,
    result_header: String,
    ledger: Ledger,
}

impl Gate {
    fn from_config(config: &Config) -> Result<Self> {
        let budget_scope = match config.budget_scope.as_str() {
            "agent" | "fabric" | "tenant" => config.budget_scope.clone(),
            other => {
                return Err(anyhow!(
                    "budgetScope must be agent, fabric, or tenant, got {other:?}"
                ))
            }
        };
        let contribution = match config.contribution.as_str() {
            "token-cost" => Contribution::TokenCost,
            "spend-amount" => Contribution::SpendAmount,
            "fixed-weight" => Contribution::FixedWeight,
            other => {
                return Err(anyhow!(
                    "contribution must be token-cost, spend-amount, or fixed-weight, got {other:?}"
                ))
            }
        };
        let mode = match config.mode.as_str() {
            "block" => Mode::Block,
            "monitor" => Mode::Monitor,
            other => return Err(anyhow!("mode must be block or monitor, got {other:?}")),
        };
        let on_deny = match config.on_deny.as_str() {
            "rpc-error" => OnDeny::RpcError,
            "empty-403" => OnDeny::EmptyForbidden,
            other => {
                return Err(anyhow!(
                    "onDeny must be rpc-error or empty-403, got {other:?}"
                ))
            }
        };
        match config.window.as_str() {
            "rolling-24h" | "fixed-period" => {}
            other => {
                return Err(anyhow!(
                    "window must be rolling-24h or fixed-period, got {other:?}"
                ))
            }
        };
        if !config.aggregate_budget.is_finite() || config.aggregate_budget < 0.0 {
            return Err(anyhow!(
                "aggregateBudget must be a non-negative finite number"
            ));
        }
        if !config.fixed_weight.is_finite() || config.fixed_weight < 0.0 {
            return Err(anyhow!("fixedWeight must be a non-negative finite number"));
        }
        if !config.estimated_tokens.is_finite() || config.estimated_tokens < 0.0 {
            return Err(anyhow!(
                "estimatedTokens must be a non-negative finite number"
            ));
        }

        let needs_scope_header = budget_scope != "fabric";
        let scope_header = config.scope_header.trim().to_string();
        if needs_scope_header && scope_header.is_empty() {
            return Err(anyhow!(
                "scopeHeader must not be blank when budgetScope is agent or tenant"
            ));
        }

        let spend_amount_field = config.spend_amount_field.trim().to_string();
        if contribution == Contribution::SpendAmount && spend_amount_field.is_empty() {
            return Err(anyhow!(
                "spendAmountField must not be blank when contribution=spend-amount"
            ));
        }

        let result_header = config.result_header.trim().to_string();
        if result_header.is_empty() {
            return Err(anyhow!("resultHeader must not be blank"));
        }

        if !config.ledger_endpoint.trim().is_empty() {
            logger::info!(
                "aggregate-risk-gate: ledgerEndpoint is set but Stage A does not consult an \
                 external ledger; every decision is made by the in-process store. Ignoring {:?}.",
                config.ledger_endpoint
            );
        }

        // `window` (e.g. "rolling-24h") is accepted-but-not-enforced at Stage A: this
        // in-process ledger has no notion of time or expiry, so every scope's
        // exposure accumulates for the life of the gateway worker process, not the
        // configured window. Logged once at startup so this is visible without
        // reading the gcl.yaml field docs.
        logger::info!(
            "aggregate-risk-gate: window={:?} is accepted but not enforced by this Stage A build \
             (no time-boxing or expiry; exposure accumulates for the worker process lifetime).",
            config.window
        );

        Ok(Self {
            budget_scope,
            needs_scope_header,
            scope_header,
            aggregate_budget: config.aggregate_budget,
            contribution,
            fixed_weight: config.fixed_weight,
            spend_amount_field,
            estimated_tokens: config.estimated_tokens,
            mode,
            on_deny,
            result_header,
            ledger: Ledger::new(),
        })
    }

    /// The concrete ledger key for this call: the aggregation dimension plus an
    /// identity value (or a fixed value for "fabric", which has none). Returns
    /// whether the identity header was required-but-missing/blank, so callers
    /// can apply block/monitor semantics to that case.
    fn scope_key(&self, header_value: Option<&str>) -> (String, bool) {
        if !self.needs_scope_header {
            return (format!("{}:*", self.budget_scope), false);
        }
        match header_value.map(str::trim) {
            Some(value) if !value.is_empty() => (format!("{}:{value}", self.budget_scope), false),
            _ => (format!("{}:(missing)", self.budget_scope), true),
        }
    }
}

/// Dot-separated lookup into a parsed JSON body, e.g. "params.amount" reads
/// `body.params.amount`. Only descends through JSON objects; any other shape
/// along the path (array, scalar, missing member) is treated as not found.
fn dot_path_value<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

/// What this call's exposure contribution turned out to be, pre-flight.
enum ContributionOutcome {
    /// The real, known-now contribution (fixed-weight, or a parsed spend
    /// amount).
    Known(f64),
    /// A pre-flight ESTIMATE (token-cost). This build never reads the
    /// response body to learn a real usage figure (see `response_filter`),
    /// so the estimate itself is what ultimately gets committed in
    /// `response_filter` — settled, not reconciled against anything real.
    Estimate(f64),
    /// contribution=spend-amount and the body was missing, unparseable, or
    /// missing/non-numeric at `spendAmountField`.
    Unpriceable,
}

/// How many JSON-RPC calls `body` represents, for contribution accounting. A
/// batch (JSON array) body must never be priced as if it were a single call —
/// that would fail-open the aggregate-risk check by letting a batch of N
/// calls each escape at 1/N of their real weight. `body` is assumed already
/// size-checked (`RawBody::Present` only, never `Uninspectable`).
fn body_item_count(body: &[u8]) -> usize {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Array(items)) if !items.is_empty() => items.len(),
        _ => 1,
    }
}

fn compute_contribution(gate: &Gate, raw_body: RawBody) -> ContributionOutcome {
    let body = match raw_body {
        // An uninspectable-but-present body might be a batch of any size —
        // fail closed rather than guess it is worth exactly one call.
        RawBody::Uninspectable => return ContributionOutcome::Unpriceable,
        RawBody::NoBody => None,
        RawBody::Present(bytes) => Some(bytes),
    };
    match gate.contribution {
        Contribution::FixedWeight => {
            let items = body.map(body_item_count).unwrap_or(1) as f64;
            ContributionOutcome::Known(gate.fixed_weight * items)
        }
        Contribution::TokenCost => {
            let items = body.map(body_item_count).unwrap_or(1) as f64;
            ContributionOutcome::Estimate(gate.estimated_tokens * items)
        }
        Contribution::SpendAmount => {
            let Some(body) = body else {
                return ContributionOutcome::Unpriceable;
            };
            let Ok(value) = serde_json::from_slice::<Value>(body) else {
                return ContributionOutcome::Unpriceable;
            };
            let items: Vec<&Value> = match &value {
                Value::Array(items) if !items.is_empty() => items.iter().collect(),
                _ => vec![&value],
            };
            let mut total = 0.0;
            for item in &items {
                match dot_path_value(item, &gate.spend_amount_field).and_then(Value::as_f64) {
                    Some(amount) if amount.is_finite() && amount >= 0.0 => total += amount,
                    // Fail closed on the WHOLE batch if any one item is
                    // unpriceable — never silently price the batch at only
                    // the items that happened to parse.
                    _ => return ContributionOutcome::Unpriceable,
                }
            }
            ContributionOutcome::Known(total)
        }
    }
}

/// Why a call was denied, carrying only the scope key and numeric totals — never
/// another session's call content — so both the log line and the resultHeader
/// stamp are always safe to forward downstream without a further redaction pass.
enum DenyReason {
    MissingScopeHeader,
    Unpriceable,
    BudgetExceeded(Denial),
}

impl DenyReason {
    fn stamp(&self, scope: &str) -> String {
        match self {
            DenyReason::MissingScopeHeader => {
                format!("denied;scope={scope};reason=missing-scope-header")
            }
            DenyReason::Unpriceable => format!("denied;scope={scope};reason=unpriceable"),
            DenyReason::BudgetExceeded(denial) => format!(
                "denied;scope={scope};would-be-total={:.2};budget={:.2}",
                denial.would_be_total, denial.budget
            ),
        }
    }

    fn message(&self, scope: &str) -> String {
        match self {
            DenyReason::MissingScopeHeader => {
                format!("aggregate risk gate: missing the required scope-identity header for scope \"{scope}\"")
            }
            DenyReason::Unpriceable => {
                format!("aggregate risk gate: call could not be priced for scope \"{scope}\"")
            }
            DenyReason::BudgetExceeded(denial) => format!(
                "aggregate risk gate: call would compose scope \"{scope}\" to {:.2}, over its aggregate budget of {:.2}",
                denial.would_be_total, denial.budget
            ),
        }
    }
}

/// Carries the outcome of the request-phase reservation forward to the
/// response-phase filter. `stamp` is always applied to the CLIENT-facing
/// response header there — it must not be set on the request-phase
/// `HeadersHandler`, since that handler's `set_header` mutates the outbound
/// request to the upstream, not the response the caller sees.
#[derive(Clone, Debug)]
enum Ticket {
    /// Nothing was reserved (a monitor-mode unpriceable call) — the response
    /// filter only needs to stamp the header.
    None(String),
    /// A reservation for a KNOWN contribution (fixed-weight or spend-amount):
    /// commit on a successful response, release otherwise.
    Reserved(String, Reservation),
    /// A reservation made against an ESTIMATE (token-cost): settled at the
    /// pre-flight estimate itself on success (this build never reads the
    /// response body to learn a real usage figure — see `response_filter`),
    /// or released on failure.
    Estimated(String, Reservation),
}

fn is_success(status: u32) -> bool {
    (200..400).contains(&status)
}

/// Reserves (block mode) or force-reserves (monitor mode, which never denies)
/// `contribution` against `scope`, builds the allow/monitor header stamp, and
/// returns the ticket to carry into the response phase — where the stamp is
/// actually applied to the client-facing response. `estimate` selects whether
/// the resulting ticket is `Reserved` (known amount) or `Estimated`
/// (token-cost).
fn admit(
    gate: &Gate,
    scope: &str,
    contribution: f64,
    estimate: bool,
    echo_bytes: Option<&[u8]>,
    violations: &PolicyViolations,
) -> Flow<Ticket> {
    let reservation = match gate.mode {
        Mode::Block => match gate
            .ledger
            .reserve(scope, contribution, gate.aggregate_budget)
        {
            Ok(reservation) => reservation,
            Err(denial) => {
                // This IS the aggregate-risk signal this policy exists to
                // catch: an individually valid call that composes past the
                // budget. Mirrors the sibling decoy/binding policies'
                // PolicyViolations usage so a downstream SIEM/Kill Switch can
                // key off one signal across the whole gateway.
                violations.generate_policy_violation();
                let reason = DenyReason::BudgetExceeded(denial);
                let stamp = reason.stamp(scope);
                let response = deny_response(
                    gate.on_deny,
                    echo_bytes,
                    &gate.result_header,
                    &stamp,
                    &reason.message(scope),
                );
                return Flow::Break(response);
            }
        },
        Mode::Monitor => {
            let (reservation, breached) =
                gate.ledger
                    .force_reserve_checked(scope, contribution, gate.aggregate_budget);
            if breached {
                // The call that would have been refused in block mode is
                // still forwarded (monitor never denies), but the composition
                // breach is real and must be visible as a policy violation,
                // not just a log line.
                violations.generate_policy_violation();
            }
            reservation
        }
    };
    let total_after = gate.ledger.snapshot(scope).total();
    let verb = if gate.mode == Mode::Block {
        "allowed"
    } else {
        "monitor"
    };
    let stamp = format!(
        "{verb};scope={scope};contribution={contribution:.2};total={total_after:.2}/{:.2}",
        gate.aggregate_budget
    );
    Flow::Continue(if estimate {
        Ticket::Estimated(stamp, reservation)
    } else {
        Ticket::Reserved(stamp, reservation)
    })
}

fn decide(
    handler: &(impl HeadersHandler + ?Sized),
    gate: &Gate,
    raw_body: RawBody,
    violations: &PolicyViolations,
) -> Flow<Ticket> {
    let header_value = if gate.needs_scope_header {
        handler.header(&gate.scope_header)
    } else {
        None
    };
    let (scope, missing_header) = gate.scope_key(header_value.as_deref());
    // Captured before `raw_body` is moved into `compute_contribution` below —
    // `as_bytes` only borrows, so this stays valid for every deny path that
    // still needs the original bytes to attempt an in-band id-echo.
    let echo_bytes = raw_body.as_bytes();

    if missing_header && gate.mode == Mode::Block {
        let reason = DenyReason::MissingScopeHeader;
        let stamp = reason.stamp(&scope);
        let response = deny_response(
            gate.on_deny,
            echo_bytes,
            &gate.result_header,
            &stamp,
            &reason.message(&scope),
        );
        return Flow::Break(response);
    }

    match compute_contribution(gate, raw_body) {
        ContributionOutcome::Unpriceable => {
            if gate.mode == Mode::Block {
                let reason = DenyReason::Unpriceable;
                let stamp = reason.stamp(&scope);
                let response = deny_response(
                    gate.on_deny,
                    echo_bytes,
                    &gate.result_header,
                    &stamp,
                    &reason.message(&scope),
                );
                Flow::Break(response)
            } else {
                // Monitor mode: the call still happened, so it is recorded (at a
                // zero contribution — its real exposure is unknown, not zero, but
                // there is nothing safe to guess) so the scope shows up in the
                // ledger and an operator can see the gap; the gap itself is made
                // visible on the header rather than silently inflating or
                // deflating the running total.
                gate.ledger.record(&scope, 0.0);
                let stamp = format!("monitor;scope={scope};reason=unpriceable");
                Flow::Continue(Ticket::None(stamp))
            }
        }
        ContributionOutcome::Known(amount) => {
            admit(gate, &scope, amount, false, echo_bytes, violations)
        }
        ContributionOutcome::Estimate(estimate) => {
            admit(gate, &scope, estimate, true, echo_bytes, violations)
        }
    }
}

async fn request_filter(
    request_state: RequestState,
    gate: &Gate,
    violations: &PolicyViolations,
) -> Flow<Ticket> {
    let headers_state = request_state.into_headers_state().await;
    if !headers_state.contains_body() {
        let handler = headers_state.handler();
        return decide(handler, gate, RawBody::NoBody, violations);
    }
    // Header-phase gate, BEFORE ever calling `into_headers_body_state()`:
    // an oversized, non-JSON, or compressed body is never buffered at all —
    // `decide` still runs (as `Uninspectable`) so this call gets the same
    // fail-closed handling as a body this policy read and found unpriceable.
    if !request_is_inspectable(headers_state.handler()) {
        let handler = headers_state.handler();
        return decide(handler, gate, RawBody::Uninspectable, violations);
    }
    let state = headers_state.into_headers_body_state().await;
    let handler = state.handler();
    let body = handler.body();
    // Defense in depth: a Content-Length that undersold the real body size
    // must not smuggle an oversized body past the header-phase gate above.
    let raw_body = if body.len() <= MAX_INSPECT_BYTES {
        RawBody::Present(body.as_ref())
    } else {
        RawBody::Uninspectable
    };
    decide(handler, gate, raw_body, violations)
}

async fn response_filter(
    response_state: ResponseState,
    request_data: RequestData<Ticket>,
    gate: &Gate,
) {
    let ticket = match request_data {
        RequestData::Continue(ticket) => ticket,
        _ => return,
    };

    // The stamp is always applied to the CLIENT-facing response header here —
    // never to the request-phase handler, whose `set_header` would instead
    // mutate the outbound request to the upstream tool.
    let headers_state = response_state.into_headers_state().await;
    let (stamp, resolution) = match ticket {
        Ticket::None(stamp) => (stamp, None),
        Ticket::Reserved(stamp, reservation) => (stamp, Some((reservation, false))),
        Ticket::Estimated(stamp, reservation) => (stamp, Some((reservation, true))),
    };
    headers_state
        .handler()
        .set_header(&gate.result_header, &stamp);

    let Some((reservation, is_estimate)) = resolution else {
        return;
    };

    if !is_success(headers_state.status_code()) {
        gate.ledger.release(reservation);
        return;
    }

    if !is_estimate {
        gate.ledger.commit(reservation);
        return;
    }

    // Token-cost is estimate-then-SETTLE, not estimate-then-reconcile against
    // a real figure: this filter never calls `into_headers_body_state()` on
    // the response leg (headers-only, by design — buffering a large/streamed
    // upstream reply here would risk a 504 for no gain worth that risk), so
    // there is no real `usage.total_tokens` to read. The reservation's own
    // contribution — the pre-flight estimate — is what gets committed. See
    // the Honesty boundaries section in README.md and the `contribution`
    // field doc in gcl.yaml.
    let estimate = reservation.contribution;
    gate.ledger.reconcile(reservation, estimate);
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    violations: PolicyViolations,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Invalid policy configuration at line {}, column {} ({:?})",
            err.line(),
            err.column(),
            err.classify()
        )
    })?;

    let gate = Gate::from_config(&config)?;
    logger::info!(
        "Aggregate Risk Gate armed: budgetScope={}, aggregateBudget={}, contribution={}, mode={}",
        gate.budget_scope,
        gate.aggregate_budget,
        config.contribution,
        if gate.mode == Mode::Block {
            "block"
        } else {
            "monitor"
        }
    );

    let filter = on_request(|rs| request_filter(rs, &gate, &violations))
        .on_response(|res, data| response_filter(res, data, &gate));
    launcher.launch(filter).await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use pdk_unit::{
        TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder,
    };
    use serde_json::json;
    use std::rc::Rc;

    fn config(overrides: Value) -> String {
        let mut base = json!({
            "budgetScope": "agent",
            "scopeHeader": "x-agent-id",
            "aggregateBudget": 3000,
            "window": "rolling-24h",
            "contribution": "fixed-weight",
            "fixedWeight": 800,
            "spendAmountField": "params.amount",
            "estimatedTokens": 500,
            "ledgerEndpoint": "",
            "mode": "block",
            "onDeny": "rpc-error",
            "resultHeader": "x-aggregate-risk-gate",
        });
        let overrides = overrides
            .as_object()
            .expect("overrides must be an object")
            .clone();
        let base_object = base
            .as_object_mut()
            .expect("base config is always an object");
        for (key, value) in overrides {
            base_object.insert(key, value);
        }
        base.to_string()
    }

    fn jsonrpc_request(body_json: Value, agent: Option<&str>) -> UnitHttpRequest {
        let body = body_json.to_string();
        let mut req = UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string());
        if let Some(agent) = agent {
            req = req.with_header("x-agent-id", agent);
        }
        req.with_body(body.into_bytes())
    }

    fn rpc_request(id: i64, agent: &str) -> UnitHttpRequest {
        jsonrpc_request(
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {}}),
            Some(agent),
        )
    }

    fn rpc_request_with_amount(id: i64, agent: &str, amount: f64) -> UnitHttpRequest {
        jsonrpc_request(
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"amount": amount}}),
            Some(agent),
        )
    }

    /// A JSON-RPC BATCH (array) request, one `tools/call` per id — for
    /// exercising the batch accounting/echo paths, never a single call.
    fn batch_request(ids: &[i64], agent: &str) -> UnitHttpRequest {
        let batch = Value::Array(
            ids.iter()
                .map(|id| json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {}}))
                .collect(),
        );
        jsonrpc_request(batch, Some(agent))
    }

    /// A request built from a raw, already-serialized body string rather than
    /// a `Value` — needed to construct bodies a `Value`/`json!` round-trip
    /// could never produce, such as a duplicate JSON object member.
    fn raw_request(body: &str, agent: Option<&str>) -> UnitHttpRequest {
        let mut req = UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string());
        if let Some(agent) = agent {
            req = req.with_header("x-agent-id", agent);
        }
        req.with_body(body.as_bytes().to_vec())
    }

    fn ok_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_header("content-length", body.len().to_string())
            .with_body(body.to_vec())
    }

    fn failing_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = b"upstream error";
        UnitHttpResponse::new(500)
            .with_header("content-length", body.len().to_string())
            .with_body(body.to_vec())
    }

    fn usage_backend(tokens: f64) -> impl Fn(UnitHttpRequest) -> UnitHttpResponse {
        move |_req| {
            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"text": "ok"},
                "usage": {"total_tokens": tokens}
            })
            .to_string();
            UnitHttpResponse::new(200)
                .with_header("content-type", "application/json")
                .with_header("content-length", body.len().to_string())
                .with_body(body.into_bytes())
        }
    }

    /// 10x the inspection cap — the response leg must stamp the header and
    /// return this untouched without ever buffering it (see `response_filter`).
    fn huge_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        let body = vec![b'x'; 10 * MAX_INSPECT_BYTES];
        UnitHttpResponse::new(200)
            .with_header("content-type", "text/plain")
            .with_header("content-length", body.len().to_string())
            .with_body(body)
    }

    fn response_error_code(response: &UnitHttpResponse) -> Option<i64> {
        let body: Value = serde_json::from_slice(response.body()).ok()?;
        body.get("error")?.get("code")?.as_i64()
    }

    // -----------------------------------------------------------------------
    // End-to-end through the compiled filter (request_filter -> ledger ->
    // response_filter), not just the ledger directly — the PDK wiring itself
    // is under test here.
    // -----------------------------------------------------------------------

    #[test]
    fn sequential_composition_through_the_real_filter_refuses_the_fourth_call() {
        // The companion repo's own scenario, driven end to end: cap 800/call
        // (enforced upstream, not modeled here), aggregate budget 3000. The
        // first three calls from the same agent commit; the fourth is refused
        // even though it is, on its own, identical to the first three.
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        for i in 0..3 {
            let response = tester.request(rpc_request(i, "broker-7"));
            assert_eq!(
                response_error_code(&response),
                None,
                "call {i} should be allowed"
            );
        }

        let response = tester.request(rpc_request(4, "broker-7"));
        assert_eq!(
            response.status_code(),
            200,
            "denial rendered as an in-band JSON-RPC error"
        );
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["id"], 4);
    }

    #[test]
    fn a_different_agent_has_an_independent_budget() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        for i in 0..3 {
            assert_eq!(
                tester.request(rpc_request(i, "broker-7")).status_code(),
                200
            );
        }
        // broker-9 has never spent anything: its own first call must be
        // admitted even though broker-7's scope is now exhausted.
        let response = tester.request(rpc_request(9, "broker-9"));
        assert_eq!(
            response_error_code(&response),
            None,
            "a fresh scope must not inherit another agent's exposure"
        );
    }

    #[test]
    fn monitor_mode_never_denies_even_past_budget() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"mode": "monitor"})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        for i in 0..6 {
            let response = tester.request(rpc_request(i, "broker-7"));
            assert_eq!(
                response_error_code(&response),
                None,
                "monitor mode must forward call {i} regardless of composition"
            );
        }
    }

    #[test]
    fn on_deny_empty_403_returns_no_body_and_no_jsonrpc_envelope() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"onDeny": "empty-403"})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);

        for i in 0..3 {
            tester.request(rpc_request(i, "broker-7"));
        }
        let response = tester.request(rpc_request(4, "broker-7"));
        assert_eq!(response.status_code(), 403);
        assert!(response.body().is_empty());
    }

    #[test]
    fn on_deny_rpc_error_falls_back_to_empty_403_for_non_jsonrpc_body() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"onDeny": "rpc-error"})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for i in 0..3 {
            tester.request(rpc_request(i, "broker-7"));
        }
        let not_jsonrpc = jsonrpc_request(json!({"not": "rpc"}), Some("broker-7"));
        let response = tester.request(not_jsonrpc);
        assert_eq!(
            response.status_code(),
            403,
            "an unparseable JSON-RPC body must fall back to empty-403"
        );
        assert!(response.body().is_empty());
    }

    #[test]
    fn a_jsonrpc_notification_gets_an_empty_202_on_deny() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for i in 0..3 {
            tester.request(rpc_request(i, "broker-7"));
        }
        // No "id" member at all: a JSON-RPC notification.
        let notification = jsonrpc_request(
            json!({"jsonrpc": "2.0", "method": "tools/call", "params": {}}),
            Some("broker-7"),
        );
        let response = tester.request(notification);
        assert_eq!(response.status_code(), 202);
        assert!(response.body().is_empty());
    }

    #[test]
    fn missing_scope_header_denies_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let request = jsonrpc_request(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"}),
            None,
        );
        let response = tester.request(request);
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
    }

    #[test]
    fn missing_scope_header_is_recorded_under_a_fixed_key_in_monitor_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"mode": "monitor"})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let request = jsonrpc_request(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"}),
            None,
        );
        let response = tester.request(request);
        assert!(response
            .header("x-aggregate-risk-gate")
            .unwrap()
            .contains("(missing)"));
    }

    #[test]
    fn budget_scope_fabric_ignores_the_scope_header_and_shares_one_total() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"budgetScope": "fabric"})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        // Three different agent identities still share the single fabric budget.
        for (i, agent) in [(0, "broker-7"), (1, "broker-9"), (2, "broker-11")] {
            let response = tester.request(rpc_request(i, agent));
            assert_eq!(response_error_code(&response), None);
        }
        let response = tester.request(rpc_request(4, "broker-13"));
        assert_eq!(
            response_error_code(&response),
            Some(MCP_BLOCKED_CODE),
            "a 4th call from ANY agent exhausts the shared fabric budget"
        );
    }

    #[test]
    fn spend_amount_contribution_is_read_from_the_configured_body_field() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "spend-amount"})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for i in 0..3 {
            let response = tester.request(rpc_request_with_amount(i, "broker-7", 800.0));
            assert_eq!(response_error_code(&response), None);
        }
        let response = tester.request(rpc_request_with_amount(4, "broker-7", 800.0));
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
    }

    #[test]
    fn spend_amount_contribution_denies_an_unpriceable_call_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "spend-amount"})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        // No params.amount field at all.
        let response = tester.request(rpc_request(1, "broker-7"));
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
    }

    #[test]
    fn spend_amount_contribution_records_zero_for_an_unpriceable_call_in_monitor_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(
                json!({"contribution": "spend-amount", "mode": "monitor"}),
            ))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let response = tester.request(rpc_request(1, "broker-7"));
        assert!(response
            .header("x-aggregate-risk-gate")
            .unwrap()
            .contains("unpriceable"));
        assert_eq!(
            response_error_code(&response),
            None,
            "monitor mode must still forward the call"
        );
    }

    #[test]
    fn a_failed_upstream_call_releases_its_reservation_and_does_not_count_against_budget() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "fixed-weight", "fixedWeight": 3000, "aggregateBudget": 3000})))
            .with_backend(failing_backend)
            .with_entrypoint(super::configure);
        // Even though a single call uses the ENTIRE budget, if the upstream
        // call fails, the reservation must be released, freeing budget for a
        // retry.
        tester.request(rpc_request(1, "broker-7"));
        let response = tester.request(rpc_request(2, "broker-7"));
        assert_eq!(
            response_error_code(&response),
            None,
            "a released reservation must free the full budget again"
        );
    }

    #[test]
    fn token_cost_contribution_commits_the_full_estimate_and_never_reads_the_response_body() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "token-cost", "estimatedTokens": 600, "aggregateBudget": 1000})))
            .with_backend(usage_backend(50.0))
            .with_entrypoint(super::configure);
        // The backend reports a real usage.total_tokens of 50, far below the
        // 600-token estimate — but the response leg is headers-only and never
        // reads the response body (see response_filter), so the FULL 600
        // estimate is what gets committed, not the smaller real figure.
        let first = tester.request(rpc_request(1, "broker-7"));
        assert_eq!(response_error_code(&first), None);
        let header = first.header("x-aggregate-risk-gate").unwrap();
        assert!(header.contains("600.00"));
        // A 2nd 600-token estimate only denies (600 + 600 = 1200 > 1000) if
        // the 1st call's estimate was committed IN FULL — a true-up to the
        // real 50-token usage would leave 50 + 600 = 650, still under budget.
        let second = tester.request(rpc_request(2, "broker-7"));
        assert_eq!(
            response_error_code(&second),
            Some(MCP_BLOCKED_CODE),
            "the full 600-token estimate, not the real 50-token usage, must have been committed"
        );
    }

    #[test]
    fn a_large_response_body_is_never_buffered_and_the_header_still_lands() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(huge_backend)
            .with_entrypoint(super::configure);
        // 10x the inspection cap: if response_filter ever called
        // into_headers_body_state() on the response leg, this is the body it
        // would have to buffer. It must not — the response leg is headers-only.
        let response = tester.request(rpc_request(1, "broker-7"));
        assert!(
            response
                .header("x-aggregate-risk-gate")
                .unwrap()
                .contains("allowed"),
            "the result header must still be stamped even on a huge response body"
        );
        assert_eq!(
            response.body().len(),
            10 * MAX_INSPECT_BYTES,
            "the (never-buffered) body must reach the caller unmodified"
        );
    }

    // -----------------------------------------------------------------------
    // Batch (array) JSON-RPC requests — must never fail-open the aggregate
    // check by pricing a batch of N calls as if it were one.
    // -----------------------------------------------------------------------

    #[test]
    fn an_over_budget_batch_is_denied_atomically_with_one_error_per_id() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        // fixed-weight=800, aggregateBudget=3000: a single batch of 4 calls
        // (3200) must be refused as ONE atomic unit — never split so that 3
        // of the 4 slip through underneath the per-item weight.
        let response = tester.request(batch_request(&[1, 2, 3, 4], "broker-7"));
        assert!(
            backend.next().is_none(),
            "an over-budget batch must never reach upstream"
        );
        assert_eq!(
            response.status_code(),
            200,
            "denial rendered as in-band JSON-RPC errors"
        );
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        let errors = body.as_array().expect("batch denial echoes a JSON array");
        assert_eq!(errors.len(), 4, "one error per id in the batch");
        for (id, error) in [1, 2, 3, 4].iter().zip(errors) {
            assert_eq!(error["id"], json!(id));
            assert_eq!(error["error"]["code"], MCP_BLOCKED_CODE);
        }
    }

    #[test]
    fn a_within_budget_batch_commits_the_full_per_item_contribution() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let response = tester.request(batch_request(&[1, 2, 3], "broker-7"));
        assert_eq!(response_error_code(&response), None);
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(
            header.contains("2400.00"),
            "3 items at 800 each must commit as 2400, not as a single 800"
        );
        // A follow-up single call only denies (2400 + 800 = 3200 > 3000) if
        // the batch really committed 2400 — an under-counted 800 would leave
        // 800 + 800 = 1600, still under budget.
        let response = tester.request(rpc_request(4, "broker-7"));
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
    }

    #[test]
    fn spend_amount_batch_sums_per_item_contributions() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "spend-amount"})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"amount": 800.0}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"amount": 800.0}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"amount": 800.0}},
        ]);
        let response = tester.request(jsonrpc_request(batch, Some("broker-7")));
        assert_eq!(response_error_code(&response), None);
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(header.contains("2400.00"));
        // Only denies (2400 + 800 = 3200 > 3000) if the batch truly summed to
        // 2400 rather than, say, pricing the whole batch as a single item.
        let response = tester.request(rpc_request_with_amount(4, "broker-7", 800.0));
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
    }

    #[test]
    fn spend_amount_batch_with_any_unpriceable_item_denies_the_whole_batch() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "spend-amount"})))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        // The 2nd item has no params.amount at all.
        let batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"amount": 100.0}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {}},
        ]);
        let response = tester.request(jsonrpc_request(batch, Some("broker-7")));
        assert!(
            backend.next().is_none(),
            "a batch with any unpriceable item must never reach upstream in block mode"
        );
        assert_eq!(response.status_code(), 200);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        let errors = body.as_array().expect("batch denial echoes a JSON array");
        assert_eq!(
            errors.len(),
            2,
            "fail-closed on the WHOLE batch, not just the unpriceable item"
        );
        for error in errors {
            assert_eq!(error["error"]["code"], MCP_BLOCKED_CODE);
        }
    }

    // -----------------------------------------------------------------------
    // Deny-path id-echo containment: never echo an id this policy cannot
    // trust, even when the underlying denial (budget exceeded) is genuine.
    // -----------------------------------------------------------------------

    #[test]
    fn a_duplicate_json_member_falls_back_to_empty_403_without_echoing_any_id() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        for i in 0..3 {
            tester.request(rpc_request(i, "broker-7"));
        }
        for _ in 0..3 {
            backend.next(); // discard the first three admitted calls
        }
        // A duplicate "id" member: a parser-differential body where this
        // policy and the upstream tool could legitimately disagree about
        // which id is "the" id. This 4th call is a genuine budget-exceeded
        // denial, but neither id may ever be echoed — fall back to the
        // generic empty-403, exactly as an unparseable body would (issue #36
        // containment).
        let ambiguous = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","id":999,"params":{}}"#;
        let response = tester.request(raw_request(ambiguous, Some("broker-7")));
        assert!(
            backend.next().is_none(),
            "the over-budget call must not reach upstream"
        );
        assert_eq!(
            response.status_code(),
            403,
            "an ambiguous body falls back to empty-403, echoing no id"
        );
        assert!(response.body().is_empty());
    }

    // -----------------------------------------------------------------------
    // PolicyViolations — mirrors the sibling decoy/binding policies' signal so
    // a downstream SIEM/Kill Switch can key off one code across the gateway.
    // -----------------------------------------------------------------------

    #[test]
    fn block_budget_exceeded_denial_sets_a_policy_violation() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for i in 0..3 {
            tester.request(rpc_request(i, "broker-7"));
        }
        let response = tester.request(rpc_request(4, "broker-7"));
        assert!(
            response.violation().is_some(),
            "a block-mode budget-exceeded denial must signal a policy violation"
        );
    }

    #[test]
    fn admitted_calls_do_not_generate_policy_violations() {
        for mode in ["block", "monitor"] {
            let backend = Rc::new(TraceBackend::new(ok_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(config(json!({ "mode": mode })))
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            tester.request(rpc_request(1, "broker-7"));
            assert!(
                backend.next().unwrap().violation().is_none(),
                "an admitted call under {} mode must not signal a policy violation",
                mode
            );
        }
    }

    #[test]
    fn monitor_over_budget_call_reports_violation_and_still_reaches_upstream() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"mode": "monitor"})))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        for i in 0..3 {
            tester.request(rpc_request(i, "broker-7"));
        }
        // The 4th call composes past budget (3200 > 3000); monitor mode never
        // denies, but the breach itself must be visible as a policy violation.
        tester.request(rpc_request(4, "broker-7"));
        for _ in 0..3 {
            backend.next(); // discard the first three admitted calls
        }
        let forwarded = backend.next().expect("monitor mode forwards every call");
        assert!(
            forwarded.violation().is_some(),
            "an over-budget call in monitor mode must signal a policy violation"
        );
    }

    #[test]
    fn token_cost_contribution_falls_back_to_the_estimate_when_usage_is_absent() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "token-cost", "estimatedTokens": 300, "aggregateBudget": 1000})))
            .with_backend(ok_backend) // no usage block in the body
            .with_entrypoint(super::configure);
        for i in 0..3 {
            let response = tester.request(rpc_request(i, "broker-7"));
            assert_eq!(
                response_error_code(&response),
                None,
                "call {i} at the 300-token estimate should be admitted"
            );
        }
        // A 4th call would push 900 + 300 = 1200, over the 1000 budget — this
        // only denies if the first three calls' estimates actually landed as
        // real committed exposure (the fallback), not zero.
        let response = tester.request(rpc_request(4, "broker-7"));
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
    }

    #[test]
    fn token_cost_contribution_releases_the_estimate_on_upstream_failure() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "token-cost", "estimatedTokens": 900, "aggregateBudget": 1000})))
            .with_backend(failing_backend)
            .with_entrypoint(super::configure);
        tester.request(rpc_request(1, "broker-7"));
        // If the failed call's 900-token estimate were not released, a second
        // 900-token reservation would exceed the 1000 budget (900+900=1800).
        let response = tester.request(rpc_request(2, "broker-7"));
        assert_eq!(
            response_error_code(&response),
            None,
            "a failed token-cost call must release its estimate"
        );
    }

    #[test]
    fn result_header_carries_the_running_total_on_allow() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let response = tester.request(rpc_request(1, "broker-7"));
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(header.contains("allowed"));
        assert!(header.contains("scope=agent:broker-7"));
        assert!(header.contains("800.00"));
    }

    #[test]
    fn result_header_on_deny_names_the_scope_and_totals_not_call_content() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for i in 0..3 {
            tester.request(rpc_request(i, "broker-7"));
        }
        let response = tester.request(rpc_request(4, "broker-7"));
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(header.contains("denied"));
        assert!(header.contains("scope=agent:broker-7"));
        assert!(header.contains("3200.00"));
    }

    // -----------------------------------------------------------------------
    // Gate::from_config validation — direct, no pdk_unit harness required.
    // -----------------------------------------------------------------------

    fn valid_config_struct() -> Config {
        Config {
            aggregate_budget: 3000.0,
            budget_scope: "agent".to_string(),
            contribution: "fixed-weight".to_string(),
            estimated_tokens: 500.0,
            fixed_weight: 800.0,
            ledger_endpoint: String::new(),
            mode: "block".to_string(),
            on_deny: "rpc-error".to_string(),
            result_header: "x-aggregate-risk-gate".to_string(),
            scope_header: "x-agent-id".to_string(),
            spend_amount_field: "params.amount".to_string(),
            window: "rolling-24h".to_string(),
        }
    }

    #[test]
    fn a_fully_valid_config_is_accepted() {
        assert!(Gate::from_config(&valid_config_struct()).is_ok());
    }

    #[test]
    fn invalid_budget_scope_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.budget_scope = "not-a-real-scope".to_string();
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn invalid_contribution_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.contribution = "not-a-real-contribution".to_string();
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn invalid_mode_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.mode = "not-a-real-mode".to_string();
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn invalid_on_deny_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.on_deny = "not-a-real-on-deny".to_string();
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn invalid_window_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.window = "not-a-real-window".to_string();
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn fixed_period_window_is_accepted() {
        let mut cfg = valid_config_struct();
        cfg.window = "fixed-period".to_string();
        assert!(Gate::from_config(&cfg).is_ok());
    }

    #[test]
    fn negative_aggregate_budget_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.aggregate_budget = -1.0;
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn non_finite_aggregate_budget_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.aggregate_budget = f64::NAN;
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn negative_fixed_weight_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.fixed_weight = -1.0;
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn negative_estimated_tokens_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.estimated_tokens = -1.0;
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn blank_scope_header_is_rejected_when_budget_scope_needs_one() {
        let mut cfg = valid_config_struct();
        cfg.scope_header = "   ".to_string();
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn blank_scope_header_is_accepted_when_budget_scope_is_fabric() {
        let mut cfg = valid_config_struct();
        cfg.budget_scope = "fabric".to_string();
        cfg.scope_header = String::new();
        assert!(Gate::from_config(&cfg).is_ok());
    }

    #[test]
    fn blank_spend_amount_field_is_rejected_when_contribution_needs_one() {
        let mut cfg = valid_config_struct();
        cfg.contribution = "spend-amount".to_string();
        cfg.spend_amount_field = String::new();
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn blank_result_header_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.result_header = String::new();
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn a_non_empty_ledger_endpoint_is_accepted_but_does_not_change_this_builds_behavior() {
        // Reserved for Stage B; accepted (not an error) but must not be
        // required, and this build's decisions come only from the in-process
        // ledger regardless of its value.
        let mut cfg = valid_config_struct();
        cfg.ledger_endpoint = "https://example.invalid/ledger".to_string();
        assert!(Gate::from_config(&cfg).is_ok());
    }

    // -----------------------------------------------------------------------
    // dot_path_value — the spend-amount field lookup helper.
    // -----------------------------------------------------------------------

    #[test]
    fn dot_path_value_reads_a_nested_field() {
        let value = json!({"params": {"amount": 42}});
        assert_eq!(dot_path_value(&value, "params.amount"), Some(&json!(42)));
    }

    #[test]
    fn dot_path_value_returns_none_for_a_missing_field() {
        let value = json!({"params": {}});
        assert_eq!(dot_path_value(&value, "params.amount"), None);
    }

    #[test]
    fn dot_path_value_returns_none_when_a_non_leaf_segment_is_not_an_object() {
        let value = json!({"params": "not-an-object"});
        assert_eq!(dot_path_value(&value, "params.amount"), None);
    }

    #[test]
    fn dot_path_value_returns_none_for_an_empty_path_segment() {
        let value = json!({"params": {"amount": 1}});
        assert_eq!(dot_path_value(&value, "params..amount"), None);
    }
}
