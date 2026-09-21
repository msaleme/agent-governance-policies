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
    /// A pre-flight ESTIMATE (token-cost); the real amount is only knowable
    /// from the upstream response and is reconciled in `response_filter`.
    Estimate(f64),
    /// contribution=spend-amount and the body was missing, unparseable, or
    /// missing/non-numeric at `spendAmountField`.
    Unpriceable,
}

fn compute_contribution(gate: &Gate, raw_body: Option<&[u8]>) -> ContributionOutcome {
    match gate.contribution {
        Contribution::FixedWeight => ContributionOutcome::Known(gate.fixed_weight),
        Contribution::TokenCost => ContributionOutcome::Estimate(gate.estimated_tokens),
        Contribution::SpendAmount => {
            let Some(body) = raw_body.filter(|body| body.len() <= MAX_INSPECT_BYTES) else {
                return ContributionOutcome::Unpriceable;
            };
            let Ok(value) = serde_json::from_slice::<Value>(body) else {
                return ContributionOutcome::Unpriceable;
            };
            match dot_path_value(&value, &gate.spend_amount_field).and_then(Value::as_f64) {
                Some(amount) if amount.is_finite() && amount >= 0.0 => {
                    ContributionOutcome::Known(amount)
                }
                _ => ContributionOutcome::Unpriceable,
            }
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
    /// A reservation made against an ESTIMATE (token-cost): reconcile with the
    /// real `usage.total_tokens` from the response on success (falling back to
    /// the estimate itself if usage is absent/unparseable), or release on
    /// failure.
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
    raw_body: Option<&[u8]>,
) -> Flow<Ticket> {
    let reservation = match gate.mode {
        Mode::Block => match gate
            .ledger
            .reserve(scope, contribution, gate.aggregate_budget)
        {
            Ok(reservation) => reservation,
            Err(denial) => {
                let reason = DenyReason::BudgetExceeded(denial);
                let stamp = reason.stamp(scope);
                let response = deny_response(
                    gate.on_deny,
                    raw_body,
                    &gate.result_header,
                    &stamp,
                    &reason.message(scope),
                );
                return Flow::Break(response);
            }
        },
        Mode::Monitor => gate.ledger.force_reserve(scope, contribution),
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
    raw_body: Option<&[u8]>,
) -> Flow<Ticket> {
    let header_value = if gate.needs_scope_header {
        handler.header(&gate.scope_header)
    } else {
        None
    };
    let (scope, missing_header) = gate.scope_key(header_value.as_deref());

    if missing_header && gate.mode == Mode::Block {
        let reason = DenyReason::MissingScopeHeader;
        let stamp = reason.stamp(&scope);
        let response = deny_response(
            gate.on_deny,
            raw_body,
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
                    raw_body,
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
        ContributionOutcome::Known(amount) => admit(gate, &scope, amount, false, raw_body),
        ContributionOutcome::Estimate(estimate) => admit(gate, &scope, estimate, true, raw_body),
    }
}

async fn request_filter(request_state: RequestState, gate: &Gate) -> Flow<Ticket> {
    let headers_state = request_state.into_headers_state().await;
    if !headers_state.contains_body() {
        let handler = headers_state.handler();
        return decide(handler, gate, None);
    }
    let state = headers_state.into_headers_body_state().await;
    let handler = state.handler();
    let body = handler.body();
    let raw_body: Option<&[u8]> = (body.len() <= MAX_INSPECT_BYTES).then(|| body.as_ref());
    decide(handler, gate, raw_body)
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

    if !is_estimate {
        if is_success(headers_state.status_code()) {
            gate.ledger.commit(reservation);
        } else {
            gate.ledger.release(reservation);
        }
        return;
    }

    // Estimated (token-cost): reconcile with the real usage.total_tokens once
    // known. The estimate is what was reserved, so it is also the honest
    // fallback if the response carries no usable usage figure — the call
    // still happened and consumed real exposure.
    let estimate = reservation.contribution;
    if !is_success(headers_state.status_code()) {
        gate.ledger.release(reservation);
        return;
    }
    if !headers_state.contains_body() {
        gate.ledger.reconcile(reservation, estimate);
        return;
    }
    let state = headers_state.into_headers_body_state().await;
    let handler = state.handler();
    let body = handler.body();
    let actual = (body.len() <= MAX_INSPECT_BYTES)
        .then(|| serde_json::from_slice::<Value>(&body).ok())
        .flatten()
        .and_then(|value| value.get("usage")?.get("total_tokens")?.as_f64())
        .filter(|tokens| tokens.is_finite() && *tokens >= 0.0);
    gate.ledger
        .reconcile(reservation, actual.unwrap_or(estimate));
}

#[entrypoint]
async fn configure(launcher: Launcher, Configuration(bytes): Configuration) -> Result<()> {
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

    let filter = on_request(|rs| request_filter(rs, &gate))
        .on_response(|res, data| response_filter(res, data, &gate));
    launcher.launch(filter).await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use pdk_unit::{UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder};
    use serde_json::json;

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
    fn token_cost_contribution_reconciles_with_real_usage_from_the_response() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "token-cost", "estimatedTokens": 600, "aggregateBudget": 1000})))
            .with_backend(usage_backend(50.0))
            .with_entrypoint(super::configure);
        // First call reserves the 600-token ESTIMATE, then reconciles down to
        // the real 50-token usage.total_tokens once the response is seen.
        let first = tester.request(rpc_request(1, "broker-7"));
        assert_eq!(response_error_code(&first), None);
        // A second call reserving another 600-token estimate only fits
        // (50 + 600 = 650 <= 1000) if the first call's ledger entry was
        // actually trued up to 50 — an un-reconciled 600 would make
        // 600 + 600 = 1200, over budget.
        let second = tester.request(rpc_request(2, "broker-7"));
        assert_eq!(
            response_error_code(&second),
            None,
            "reconciliation must free the unused estimate before the 2nd call"
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
