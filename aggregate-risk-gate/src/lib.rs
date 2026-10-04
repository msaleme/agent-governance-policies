// Copyright 2026 msaleme. Licensed under the MIT License.
//
// Cross-Session Aggregate-Risk Gate — a PDK policy that catches "death by a
// thousand authorized cuts": individually valid calls that each clear their own
// per-session cap, but compose across sessions past an aggregate exposure budget
// no per-call control ever sees. A per-call gate, a rate limit, and a per-session
// cap are all structurally blind to the SUM; this policy is a control that sees
// it.
//
// Governed calls: only JSON-RPC messages whose `method` is in `governedMethods`
// (default `["tools/call"]`) are priced. The rest of the MCP protocol
// (`initialize`, `tools/list`, `ping`, `notifications/*`, client responses to
// server requests, and bodyless requests such as the SSE GET and the session
// DELETE) passes through with no contribution and no ledger mutation (P4A
// review #47). See `compute_contribution`.
//
// Mechanism: reserve-then-authorize. On each governed call this policy computes
// the call's exposure contribution as an exact integer (an estimated-token
// weight, a spend amount in currency minor units read from the request body, or
// a fixed per-call weight), atomically reserves that
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
// Scope of the guarantee (see also the gcl.yaml field docs and README): a real,
// correct, exhaustively tested reserve-then-authorize engine. With the default
// `ledgerBackend: node` (`node_ledger.rs`, P4A review #48) there is one ledger
// per policy instance per gateway REPLICA, shared by all of its Envoy workers
// through compare-and-swap writes to node-local shared data; it is not shared
// across replicas and a gateway process restart resets it. `ledgerBackend:
// worker` (`ledger.rs`) keeps one in-memory ledger per worker, which a caller
// can multiply across workers (mitigation: `FLEX_SERVICE_ENVOY_CONCURRENCY=1`).
// A cross-replica, durable ledger (`cluster`) is not implemented and is
// rejected. No cryptographic non-repudiation claim is made about decisions.
//
// NIST SP 800-53 Rev 5: AC-6 (Least Privilege / aggregate exposure), SI-4
// (Monitoring), AU-6 (Audit Review — the running-total resultHeader).
mod generated;
mod ledger;
mod node_ledger;

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use pdk::authentication::{Authentication, AuthenticationData, AuthenticationHandler};
use pdk::hl::timer::Clock;
use pdk::hl::*;
use pdk::logger;
use pdk::policy_violation::PolicyViolations;
use pdk::script::Value as ScriptValue;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::generated::config::Config;
use crate::ledger::{Denial, Ledger, LedgerStats, LedgerStore, Refusal, Reservation, Settlement};
use crate::node_ledger::{KvStore, NodeLedger, PdkStore};
use pdk::data_storage::DataStorageBuilder;

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

/// The largest budget or contribution this policy accepts: 2^53 - 1, the
/// largest integer every JSON implementation represents exactly. Every amount
/// is an exact non-negative integer (points, estimated tokens, or currency
/// minor units); anything above this is rejected as out of range rather than
/// rounded, so ledger arithmetic can never lose precision (P4A review #18).
const MAX_UNITS: u64 = 9_007_199_254_740_991;

/// The longest canonical identity accepted, in bytes. Together with
/// `maxScopes` this bounds the ledger's memory (P4A review #14).
const MAX_IDENTITY_BYTES: usize = 256;

/// Where an agent/tenant identity is read from.
#[derive(Clone, Debug, PartialEq)]
enum IdentitySource {
    /// `budgetScope=fabric`: one shared scope, no identity.
    Shared,
    /// Verified PDK authentication data, set by an earlier auth policy.
    Authentication(IdentityField),
    /// A header that an earlier policy strips and re-injects. Not verifiable
    /// by this policy; see the README's trusted-header contract.
    TrustedHeader(String),
}

#[derive(Clone, Debug, PartialEq)]
enum IdentityField {
    ClientId,
    Principal,
    /// Dot path into `AuthenticationData::properties`.
    Property(String),
}

/// How a scope key is shown to clients.
#[derive(Clone, Debug, PartialEq)]
enum Disclosure {
    /// HMAC-SHA256 with this key, or plain SHA-256 when it is empty.
    Digest(Vec<u8>),
    None,
    Raw,
}

/// The outcome of resolving a call's identity.
#[derive(Clone, Debug, PartialEq)]
enum Identity {
    /// The ledger key to charge: "<budgetScope>:<canonical>" or "fabric:*".
    Scope(String),
    Missing,
    /// Present but malformed, oversized, or ambiguous.
    Invalid,
}

/// Canonicalizes an identity: trims surrounding spaces/tabs, requires 1 to
/// `MAX_IDENTITY_BYTES` visible ASCII characters excluding the header-stamp
/// delimiters `,` `;` `=` plus `"` and `\`, then lowercases. Case folding can only merge two
/// identities into one (stricter) budget, never split one identity into two.
fn canonical_identity(raw: &str) -> Identity {
    let trimmed = raw.trim_matches(|c| c == ' ' || c == '\t');
    if trimmed.is_empty() {
        return Identity::Missing;
    }
    let well_formed = trimmed.len() <= MAX_IDENTITY_BYTES
        && trimmed
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && !b",;=\"\\".contains(&b));
    if well_formed {
        Identity::Scope(trimmed.to_ascii_lowercase())
    } else {
        Identity::Invalid
    }
}

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
/// `MAX_INSPECT_BYTES`, a non-JSON Content-Type, a `charset` parameter other
/// than UTF-8, or any Content-Encoding (this build never decompresses) all
/// fail this gate. The charset check matters because this policy parses the
/// body as UTF-8 while an upstream may decode it with the declared charset:
/// under `charset=utf-7`, `"tools+AC8-call"` reads here as an unlisted method
/// but decodes upstream to `tools/call`. See README.md's
/// "Inspection boundary" section for the SSE/streaming/compressed/non-UTF-8
/// exclusions this enforces.
fn request_is_inspectable(handler: &(impl HeadersHandler + ?Sized)) -> bool {
    let length_ok = handler
        .header("content-length")
        .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|len| len <= MAX_INSPECT_BYTES);
    let json = handler.header("content-type").is_some_and(|value| {
        let mut parts = value.split(';');
        let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        let json_media = media == "application/json"
            || (media.starts_with("application/") && media.ends_with("+json"));
        json_media && parts.all(utf8_or_not_charset)
    });
    let uncompressed = handler.header("content-encoding").is_none();
    length_ok && json && uncompressed
}

/// True unless `param` is a `charset` parameter naming anything but UTF-8.
/// The name and value are case-insensitive, surrounding whitespace is ignored
/// and the value may be quoted. A malformed `charset` parameter (no `=`) is
/// not UTF-8.
fn utf8_or_not_charset(param: &str) -> bool {
    let param = param.trim();
    let (name, value) = match param.split_once('=') {
        Some((name, value)) => (name.trim(), Some(value.trim())),
        None => (param, None),
    };
    if !name.eq_ignore_ascii_case("charset") {
        return true;
    }
    let Some(value) = value else {
        return false;
    };
    let value = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
        .trim();
    value.eq_ignore_ascii_case("utf-8")
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
        // A client's JSON-RPC responses (to server-initiated requests) can
        // share a batch with its requests. They carry the SERVER's ids, so
        // they are skipped: only request ids are echoed on deny.
        Value::Array(items) if !items.is_empty() => items
            .iter()
            .filter(|item| !is_jsonrpc_response(item))
            .collect(),
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
    EstimatedTokenWeight,
    SpendAmount,
    FixedWeight,
}

/// Validates a configured amount as an exact integer in `0..=MAX_UNITS`.
/// Fractional and non-numeric values never get this far: the generated
/// `Config` types these fields as `i64`, so serde rejects them first.
fn config_units(name: &str, value: i64) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|units| *units <= MAX_UNITS)
        .ok_or_else(|| anyhow!("{name} must be an integer between 0 and {MAX_UNITS}"))
}

/// Validates `governedMethods`. An empty list would silently disable the
/// policy, so it is rejected, as are blank or space-padded entries (which
/// could never match, since matching is exact) and duplicates. `"*"` is not a
/// wildcard in this build and is rejected rather than matched literally.
fn governed_methods(methods: &[String]) -> Result<Vec<String>> {
    if methods.is_empty() {
        return Err(anyhow!(
            "governedMethods must list at least one JSON-RPC method, e.g. [\"tools/call\"]"
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for method in methods {
        if method.trim().is_empty() || method.trim() != method {
            return Err(anyhow!(
                "governedMethods entries must be non-blank with no surrounding whitespace, got {method:?}"
            ));
        }
        if method == "*" {
            return Err(anyhow!(
                "governedMethods does not support \"*\": list each JSON-RPC method to price"
            ));
        }
        if !seen.insert(method.as_str()) {
            return Err(anyhow!("governedMethods lists {method:?} more than once"));
        }
    }
    Ok(methods.to_vec())
}

/// Compiled, validated policy state, built once at configuration time and
/// shared (by reference) across every exchange this instance governs. Owns the
/// per-worker ledger described in the module doc comment.
struct Gate {
    budget_scope: String,
    identity_source: IdentitySource,
    disclosure: Disclosure,
    aggregate_budget: u64,
    contribution: Contribution,
    /// The unit every amount is counted in, stamped into `resultHeader` so a
    /// downstream reader never has to guess what "800" means.
    unit: String,
    fixed_weight: u64,
    /// The JSON-RPC methods that are priced. Matched case-sensitively.
    governed_methods: Vec<String>,
    spend_amount_field: String,
    estimated_tokens: u64,
    mode: Mode,
    on_deny: OnDeny,
    result_header: String,
    ledger: Box<dyn LedgerStore>,
}

/// The store name of the node ledger in a policy instance's own namespace.
const NODE_LEDGER_STORE: &str = "ledger";

/// Checks `ledgerNamespace`: empty, or 1 to 64 letters, digits, `.`, `_`, `-`.
fn ledger_namespace(raw: &str) -> Result<Option<String>> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() <= 64
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Ok(Some(raw.to_string()));
    }
    Err(anyhow!(
        "ledgerNamespace must be empty or 1 to 64 letters, digits, '.', '_' or '-'"
    ))
}

impl Gate {
    /// A gate whose node ledger uses an in-memory test store.
    #[cfg(test)]
    fn from_config(config: &Config) -> Result<Self> {
        Self::from_config_with(
            config,
            |_| Box::new(node_ledger::fake::FakeStore::default()),
        )
    }

    /// Builds the gate. `node_store` opens the shared-data store for the node
    /// ledger: the policy instance's own namespace for `None`, or the named
    /// shared one.
    fn from_config_with(
        config: &Config,
        node_store: impl FnOnce(Option<&str>) -> Box<dyn KvStore>,
    ) -> Result<Self> {
        let budget_scope = match config.budget_scope.as_str() {
            "agent" | "fabric" | "tenant" => config.budget_scope.clone(),
            other => {
                return Err(anyhow!(
                    "budgetScope must be agent, fabric, or tenant, got {other:?}"
                ))
            }
        };
        let contribution = match config.contribution.as_str() {
            "estimated-token-weight" => Contribution::EstimatedTokenWeight,
            "spend-amount" => Contribution::SpendAmount,
            "fixed-weight" => Contribution::FixedWeight,
            "token-cost" => {
                return Err(anyhow!(
                    "contribution \"token-cost\" was renamed to \"estimated-token-weight\": it \
                     charges a fixed estimate per call and never measures actual token usage"
                ))
            }
            other => {
                return Err(anyhow!(
                    "contribution must be estimated-token-weight, spend-amount, or fixed-weight, got {other:?}"
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
        let window = match config.window.as_str() {
            "fixed-period" => Some(
                u64::try_from(config.window_ms)
                    .ok()
                    .filter(|ms| (60_000..=31_622_400_000).contains(ms))
                    .ok_or_else(|| anyhow!("windowMs must be between 60000 and 31622400000"))?,
            ),
            "worker-lifetime" => None,
            "rolling-24h" => {
                return Err(anyhow!(
                    "window \"rolling-24h\" was removed: it never rolled. Use \"fixed-period\" \
                     with windowMs 86400000 for a daily budget, or \"worker-lifetime\""
                ))
            }
            other => {
                return Err(anyhow!(
                    "window must be fixed-period or worker-lifetime, got {other:?}"
                ))
            }
        };
        let aggregate_budget = config_units("aggregateBudget", config.aggregate_budget)?;
        let fixed_weight = config_units("fixedWeight", config.fixed_weight)?;
        let estimated_tokens = config_units("estimatedTokens", config.estimated_tokens)?;
        let spend_currency = config.spend_currency.trim();
        if spend_currency.len() != 3 || !spend_currency.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(anyhow!(
                "spendCurrency must be an ISO 4217 code of three uppercase letters, got {spend_currency:?}"
            ));
        }
        let unit = match contribution {
            Contribution::FixedWeight => "points".to_string(),
            Contribution::EstimatedTokenWeight => "estimated-tokens".to_string(),
            Contribution::SpendAmount => format!("{spend_currency}-minor"),
        };

        let identity_source = if budget_scope == "fabric" {
            IdentitySource::Shared
        } else {
            match config.identity_source.as_str() {
                "authentication" => {
                    IdentitySource::Authentication(match config.identity_field.trim() {
                        "client_id" => IdentityField::ClientId,
                        "principal" => IdentityField::Principal,
                        other => match other.strip_prefix("properties.") {
                            Some(path) if !path.is_empty() && !path.split('.').any(str::is_empty) => {
                                IdentityField::Property(path.to_string())
                            }
                            _ => {
                                return Err(anyhow!(
                                    "identityField must be client_id, principal, or properties.<path>, got {other:?}"
                                ))
                            }
                        },
                    })
                }
                "trusted-header" => {
                    let scope_header = config.scope_header.trim().to_string();
                    if scope_header.is_empty() {
                        return Err(anyhow!(
                            "scopeHeader must not be blank when identitySource is trusted-header"
                        ));
                    }
                    IdentitySource::TrustedHeader(scope_header)
                }
                other => {
                    return Err(anyhow!(
                        "identitySource must be authentication or trusted-header, got {other:?}"
                    ))
                }
            }
        };

        let max_scopes = usize::try_from(config.max_scopes)
            .ok()
            .filter(|max| (1..=1_000_000).contains(max))
            .ok_or_else(|| anyhow!("maxScopes must be between 1 and 1000000"))?;
        let reservation_timeout_ms = u64::try_from(config.reservation_timeout_ms)
            .ok()
            .filter(|ms| (1_000..=86_400_000).contains(ms))
            .ok_or_else(|| anyhow!("reservationTimeoutMs must be between 1000 and 86400000"))?;
        let namespace = ledger_namespace(&config.ledger_namespace)?;
        let node = match config.ledger_backend.as_str() {
            "node" => true,
            "worker" => {
                if namespace.is_some() {
                    return Err(anyhow!(
                        "ledgerNamespace applies only to ledgerBackend \"node\""
                    ));
                }
                false
            }
            "cluster" => {
                return Err(anyhow!(
                    "ledgerBackend \"cluster\" is not implemented: a cluster-wide ledger \
                     shared across gateway replicas does not exist yet. Use \"node\" (one \
                     budget per replica) or \"worker\""
                ))
            }
            other => {
                return Err(anyhow!(
                    "ledgerBackend must be node or worker, got {other:?}"
                ))
            }
        };

        let disclosure = match config.scope_disclosure.as_str() {
            "digest" => Disclosure::Digest(config.scope_digest_key.as_bytes().to_vec()),
            "none" => Disclosure::None,
            "raw" => Disclosure::Raw,
            other => {
                return Err(anyhow!(
                    "scopeDisclosure must be digest, none, or raw, got {other:?}"
                ))
            }
        };

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

        let governed_methods = governed_methods(&config.governed_methods)?;

        Ok(Self {
            budget_scope,
            identity_source,
            disclosure,
            aggregate_budget,
            contribution,
            unit,
            fixed_weight,
            governed_methods,
            spend_amount_field,
            estimated_tokens,
            mode,
            on_deny,
            result_header,
            ledger: if node {
                Box::new(NodeLedger::new(
                    node_store(namespace.as_deref()),
                    config.scope_digest_key.as_bytes().to_vec(),
                    max_scopes,
                    reservation_timeout_ms,
                    window,
                    node_ledger::random_prefix(),
                ))
            } else {
                Box::new(Ledger::with_limits(
                    max_scopes,
                    reservation_timeout_ms,
                    window,
                ))
            },
        })
    }

    /// Resolves this call's identity into a ledger key. `headers` is the full
    /// request header list, so a trusted header sent more than once (in any
    /// letter case) is caught as ambiguous rather than silently picking one.
    fn identity(
        &self,
        auth: Option<&AuthenticationData>,
        headers: &[(String, String)],
    ) -> Identity {
        let raw = match &self.identity_source {
            IdentitySource::Shared => return Identity::Scope(format!("{}:*", self.budget_scope)),
            IdentitySource::Authentication(field) => {
                let Some(data) = auth else {
                    return Identity::Missing;
                };
                let value = match field {
                    IdentityField::ClientId => data.client_id.clone(),
                    IdentityField::Principal => data.principal.clone(),
                    IdentityField::Property(path) => match property_value(&data.properties, path) {
                        None | Some(ScriptValue::Null) => None,
                        Some(ScriptValue::String(value)) => Some(value.clone()),
                        // A number, object, or array is not an identity.
                        Some(_) => return Identity::Invalid,
                    },
                };
                match value {
                    Some(value) => value,
                    None => return Identity::Missing,
                }
            }
            IdentitySource::TrustedHeader(name) => {
                let mut values = headers
                    .iter()
                    .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value);
                match (values.next(), values.next()) {
                    (None, _) => return Identity::Missing,
                    (Some(value), None) => value.clone(),
                    (Some(_), Some(_)) => return Identity::Invalid,
                }
            }
        };
        match canonical_identity(&raw) {
            Identity::Scope(canonical) => {
                Identity::Scope(format!("{}:{canonical}", self.budget_scope))
            }
            other => other,
        }
    }

    /// How a scope key appears in client-visible headers and messages.
    fn display_scope(&self, key: &str) -> String {
        // The shared fabric key and the monitor-mode "(missing)"/"(invalid)"
        // buckets carry no caller identity, so they are shown as-is. A space
        // never occurs in a canonical identity, so it marks a bucket key.
        if self.identity_source == IdentitySource::Shared || key.contains(' ') {
            return key.to_string();
        }
        match &self.disclosure {
            Disclosure::Raw => key.to_string(),
            Disclosure::None => self.budget_scope.clone(),
            Disclosure::Digest(secret) => {
                let (label, digest) = if secret.is_empty() {
                    ("sha256", Sha256::digest(key.as_bytes()).to_vec())
                } else {
                    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
                        .expect("HMAC-SHA256 accepts a key of any length");
                    mac.update(key.as_bytes());
                    ("hmac", mac.finalize().into_bytes().to_vec())
                };
                let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
                format!("{}:{label}-{hex}", self.budget_scope)
            }
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

/// Walks a dot path through the authentication properties an upstream
/// authentication policy attached. Same rules as `dot_path_value`.
fn property_value<'a>(root: &'a ScriptValue, path: &str) -> Option<&'a ScriptValue> {
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
    /// The exact contribution, in `0..=MAX_UNITS`: fixed-weight points, the
    /// estimated-token weight, or a parsed spend amount in minor units. Every
    /// mode charges exactly this on success; nothing is trued up afterwards.
    Known(u64),
    /// contribution=spend-amount and the body was missing, unparseable, or
    /// had no exact non-negative integer at `spendAmountField`.
    Unpriceable,
    /// The amount was a valid integer, but it (or the batch total) exceeds
    /// `MAX_UNITS`, so it cannot be charged exactly.
    OutOfRange,
    /// Nothing in the request is a governed call: pass it through with no
    /// contribution, no reservation and no scope entry.
    Ungoverned,
}

/// Reads a spend amount as an exact count of minor units. Only a JSON integer
/// literal qualifies: serde_json parses `12.34`, `1234.0`, and `1e3` as floats
/// and `-5` as a negative integer, so all of them fail `as_u64` and are
/// rejected rather than rounded. `Err(())` means a valid integer above
/// `MAX_UNITS`.
fn exact_minor_units(value: &Value) -> Option<Result<u64, ()>> {
    let units = value.as_u64()?;
    Some(if units <= MAX_UNITS {
        Ok(units)
    } else {
        Err(())
    })
}

/// `per_item * items`, or `OutOfRange` if that exceeds `MAX_UNITS`.
fn per_item_total(per_item: u64, items: usize) -> ContributionOutcome {
    u64::try_from(items)
        .ok()
        .and_then(|items| per_item.checked_mul(items))
        .filter(|total| *total <= MAX_UNITS)
        .map_or(ContributionOutcome::OutOfRange, ContributionOutcome::Known)
}

/// A JSON-RPC response object: `"jsonrpc": "2.0"`, no `method`, an `id`, and
/// exactly one of `result`/`error`. An MCP client POSTs these to answer
/// server-initiated requests such as `sampling/createMessage` or
/// `elicitation/create`.
fn is_jsonrpc_response(item: &Value) -> bool {
    let Some(object) = item.as_object() else {
        return false;
    };
    object.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && !object.contains_key("method")
        && object.contains_key("id")
        && object.contains_key("result") != object.contains_key("error")
}

/// Whether one JSON-RPC item is a governed call. Only an item this policy can
/// positively classify is ungoverned: a JSON-RPC 2.0 message whose string
/// `method` is not in `governedMethods` (a request or a notification), or a
/// JSON-RPC response. Anything it cannot classify (not an object, no
/// `"jsonrpc": "2.0"`, a non-string `method`, no `method` and not a response)
/// is governed, so it is priced or fails closed rather than slipping through.
/// A governed method sent as a notification (no `id`) is still governed: the
/// upstream may run it anyway.
fn is_governed(methods: &[String], item: &Value) -> bool {
    let Some(object) = item.as_object() else {
        return true;
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return true;
    }
    match object.get("method") {
        Some(Value::String(method)) => methods.iter().any(|governed| governed == method),
        Some(_) => true,
        None => !is_jsonrpc_response(item),
    }
}

/// Prices a request. A batch (JSON array) is never priced as if it were a
/// single call — that would fail-open the aggregate-risk check by letting a
/// batch of N calls each escape at 1/N of their real weight. Only governed
/// items are priced; a request with none is `Ungoverned`.
fn compute_contribution(gate: &Gate, raw_body: RawBody) -> ContributionOutcome {
    let body = match raw_body {
        // An uninspectable-but-present body might be a batch of any size —
        // fail closed rather than guess it is worth exactly one call.
        RawBody::Uninspectable => return ContributionOutcome::Unpriceable,
        // No body means no JSON-RPC message, so no governed call: the SSE
        // stream GET and the session DELETE. It cannot hide a batch.
        RawBody::NoBody => return ContributionOutcome::Ungoverned,
        RawBody::Present(bytes) => bytes,
    };
    let Ok(root) = serde_json::from_slice::<Value>(body) else {
        // Not JSON to this parser (malformed, a BOM, a lone surrogate, nesting
        // past serde's 128-level limit). Another parser upstream may still
        // read it, possibly as a batch of any size, so it cannot be priced as
        // one call. Fail closed.
        return ContributionOutcome::Unpriceable;
    };
    // A duplicate member (e.g. two `method`s) means this policy and the
    // upstream could classify the same bytes differently. Fail closed.
    if serde_json::from_slice::<NoDuplicateMembers>(body).is_err() {
        return ContributionOutcome::Unpriceable;
    }
    let items: Vec<&Value> = match &root {
        Value::Array(items) if !items.is_empty() => items.iter().collect(),
        _ => vec![&root],
    };
    let governed: Vec<&Value> = items
        .into_iter()
        .filter(|item| is_governed(&gate.governed_methods, item))
        .collect();
    price(gate, &governed)
}

/// Prices the governed items of a request.
fn price(gate: &Gate, governed: &[&Value]) -> ContributionOutcome {
    if governed.is_empty() {
        return ContributionOutcome::Ungoverned;
    }
    match gate.contribution {
        Contribution::FixedWeight => per_item_total(gate.fixed_weight, governed.len()),
        Contribution::EstimatedTokenWeight => per_item_total(gate.estimated_tokens, governed.len()),
        Contribution::SpendAmount => {
            let mut total: u64 = 0;
            for item in governed {
                match dot_path_value(item, &gate.spend_amount_field).and_then(exact_minor_units) {
                    Some(Ok(amount)) => match total.checked_add(amount) {
                        Some(sum) if sum <= MAX_UNITS => total = sum,
                        _ => return ContributionOutcome::OutOfRange,
                    },
                    Some(Err(())) => return ContributionOutcome::OutOfRange,
                    // Fail closed on the WHOLE batch if any one governed item
                    // is unpriceable — never silently price the batch at only
                    // the items that happened to parse.
                    None => return ContributionOutcome::Unpriceable,
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
    MissingIdentity,
    InvalidIdentity,
    ScopeCapacity,
    ScopeSaturated,
    LedgerContention,
    LedgerUnavailable,
    Unpriceable,
    OutOfRange,
    BudgetExceeded(Denial),
}

impl DenyReason {
    /// The `reason=` label for the non-budget refusals.
    fn label(&self) -> &'static str {
        match self {
            DenyReason::MissingIdentity => "missing-identity",
            DenyReason::InvalidIdentity => "invalid-identity",
            DenyReason::ScopeCapacity => "scope-capacity",
            DenyReason::ScopeSaturated => "scope-saturated",
            DenyReason::LedgerContention => "ledger-contention",
            DenyReason::LedgerUnavailable => "ledger-unavailable",
            DenyReason::Unpriceable => "unpriceable",
            DenyReason::OutOfRange => "out-of-range",
            DenyReason::BudgetExceeded(_) => "budget-exceeded",
        }
    }

    /// `scope` is the DISPLAY form (see `Gate::display_scope`), never the raw
    /// ledger key unless `scopeDisclosure=raw`.
    fn stamp(&self, scope: &str, unit: &str) -> String {
        match self {
            DenyReason::BudgetExceeded(denial) => format!(
                "denied;scope={scope};would-be-total={};budget={};unit={unit}",
                denial.would_be_total, denial.budget
            ),
            other => format!("denied;scope={scope};reason={}", other.label()),
        }
    }

    fn message(&self, scope: &str, unit: &str) -> String {
        match self {
            DenyReason::MissingIdentity => format!(
                "aggregate risk gate: no verified identity for budget scope \"{scope}\""
            ),
            DenyReason::InvalidIdentity => format!(
                "aggregate risk gate: malformed, oversized, or ambiguous identity for budget scope \"{scope}\""
            ),
            DenyReason::ScopeCapacity => format!(
                "aggregate risk gate: no capacity to track a new scope \"{scope}\""
            ),
            DenyReason::ScopeSaturated => format!(
                "aggregate risk gate: too many reservations in flight for scope \"{scope}\""
            ),
            DenyReason::LedgerContention => format!(
                "aggregate risk gate: the shared ledger stayed contended for scope \"{scope}\""
            ),
            DenyReason::LedgerUnavailable => format!(
                "aggregate risk gate: the shared ledger is unavailable for scope \"{scope}\""
            ),
            DenyReason::Unpriceable => {
                format!("aggregate risk gate: call could not be priced for scope \"{scope}\"")
            }
            DenyReason::OutOfRange => format!(
                "aggregate risk gate: call contribution for scope \"{scope}\" exceeds the maximum of {MAX_UNITS} {unit}"
            ),
            DenyReason::BudgetExceeded(denial) => format!(
                "aggregate risk gate: call would compose scope \"{scope}\" to {} {unit}, over its aggregate budget of {}",
                denial.would_be_total, denial.budget
            ),
        }
    }
}

/// The `reason=` label monitor mode stamps when the ledger refused to track
/// a call it still forwards.
fn refusal_label(refusal: &Refusal) -> &'static str {
    match refusal {
        Refusal::OverBudget(_) => "budget-exceeded",
        Refusal::AtCapacity => DenyReason::ScopeCapacity.label(),
        Refusal::Saturated => DenyReason::ScopeSaturated.label(),
        Refusal::Contention => DenyReason::LedgerContention.label(),
        Refusal::Unavailable => DenyReason::LedgerUnavailable.label(),
    }
}

/// Builds the block-mode refusal for `reason`.
fn refuse(gate: &Gate, reason: DenyReason, scope: &str, echo_bytes: Option<&[u8]>) -> Flow<Ticket> {
    let stamp = reason.stamp(scope, &gate.unit);
    Flow::Break(deny_response(
        gate.on_deny,
        echo_bytes,
        &gate.result_header,
        &stamp,
        &reason.message(scope, &gate.unit),
    ))
}

/// Carries the outcome of the request-phase reservation forward to the
/// response-phase filter. `stamp` is always applied to the CLIENT-facing
/// response header there — it must not be set on the request-phase
/// `HeadersHandler`, since that handler's `set_header` mutates the outbound
/// request to the upstream, not the response the caller sees.
#[derive(Clone, Debug)]
enum Ticket {
    /// Nothing was reserved (an ungoverned request, or a monitor-mode
    /// unpriceable or out-of-range call) — the response filter only needs to
    /// stamp the header.
    None(String),
    /// A reservation for the call's exact contribution: commit on a
    /// successful response, release otherwise. Every contribution mode,
    /// including estimated-token-weight, settles at exactly the reserved
    /// amount — this build never reads the response body (see
    /// `response_filter`).
    Reserved(String, Reservation),
}

/// Settlement is by HTTP status alone: 2xx and 3xx commit, everything else
/// (4xx, 5xx) releases. The response body is never read, so a JSON-RPC error
/// or an `isError` tool result inside an HTTP 200 is committed (charged), and
/// a 202 whose result arrives later over SSE is committed at the 202.
fn is_success(status: u32) -> bool {
    (200..400).contains(&status)
}

/// Reserves (block mode) or force-reserves (monitor mode, which never denies)
/// `contribution` against `scope`, builds the allow/monitor header stamp, and
/// returns the ticket to carry into the response phase — where the stamp is
/// actually applied to the client-facing response.
fn admit(
    gate: &Gate,
    scope: &str,
    contribution: u64,
    now: u64,
    echo_bytes: Option<&[u8]>,
    violations: &PolicyViolations,
) -> Flow<Ticket> {
    let display = gate.display_scope(scope);
    let reservation = match gate.mode {
        Mode::Block => match gate
            .ledger
            .reserve(scope, contribution, gate.aggregate_budget, now)
        {
            Ok(reservation) => reservation,
            Err(refusal) => {
                // An over-budget denial IS the aggregate-risk signal this
                // policy exists to catch: an individually valid call that
                // composes past the budget. A full scope table is also worth
                // an operator's attention. Mirrors the sibling decoy/binding
                // policies' PolicyViolations usage so a downstream SIEM/Kill
                // Switch can key off one signal across the whole gateway.
                violations.generate_policy_violation();
                let reason = match refusal {
                    Refusal::OverBudget(denial) => DenyReason::BudgetExceeded(denial),
                    Refusal::AtCapacity => DenyReason::ScopeCapacity,
                    Refusal::Saturated => DenyReason::ScopeSaturated,
                    Refusal::Contention => DenyReason::LedgerContention,
                    Refusal::Unavailable => DenyReason::LedgerUnavailable,
                };
                return refuse(gate, reason, &display, echo_bytes);
            }
        },
        Mode::Monitor => {
            match gate
                .ledger
                .force_reserve_checked(scope, contribution, gate.aggregate_budget, now)
            {
                Ok((reservation, breached)) => {
                    if breached {
                        // The call that would have been refused in block mode
                        // is still forwarded (monitor never denies), but the
                        // composition breach is real and must be visible as a
                        // policy violation, not just a log line.
                        violations.generate_policy_violation();
                    }
                    reservation
                }
                Err(refusal) => {
                    violations.generate_policy_violation();
                    return Flow::Continue(Ticket::None(format!(
                        "monitor;scope={display};reason={}",
                        refusal_label(&refusal)
                    )));
                }
            }
        }
    };
    let total_after = reservation.total;
    let verb = if gate.mode == Mode::Block {
        "allowed"
    } else {
        "monitor"
    };
    let stamp = format!(
        "{verb};scope={display};contribution={contribution};total={total_after}/{};unit={}",
        gate.aggregate_budget, gate.unit
    );
    Flow::Continue(Ticket::Reserved(stamp, reservation))
}

fn decide(
    identity: Identity,
    now: u64,
    gate: &Gate,
    raw_body: RawBody,
    violations: &PolicyViolations,
) -> Flow<Ticket> {
    // Captured before `raw_body` is moved into `compute_contribution` below —
    // `as_bytes` only borrows, so this stays valid for every deny path that
    // still needs the original bytes to attempt an in-band id-echo.
    let echo_bytes = raw_body.as_bytes();

    // Classified before identity: ungoverned traffic (the MCP handshake,
    // listings, pings, notifications, client responses, bodyless requests) is
    // never refused, even with no identity or an exhausted budget, and never
    // touches the ledger.
    let outcome = compute_contribution(gate, raw_body);
    if matches!(outcome, ContributionOutcome::Ungoverned) {
        return Flow::Continue(Ticket::None("pass;reason=ungoverned-method".to_string()));
    }

    let scope = match identity {
        Identity::Scope(key) => key,
        unidentified => {
            let (reason, bucket) = if unidentified == Identity::Missing {
                (DenyReason::MissingIdentity, "missing")
            } else {
                (DenyReason::InvalidIdentity, "invalid")
            };
            if gate.mode == Mode::Block {
                return refuse(gate, reason, &gate.budget_scope, echo_bytes);
            }
            // Monitor mode still prices the call, under one fixed bucket per
            // failure kind. The space makes the key impossible for any
            // canonical identity to collide with.
            format!("{} ({bucket})", gate.budget_scope)
        }
    };

    let reason = match outcome {
        ContributionOutcome::Known(amount) => {
            return admit(gate, &scope, amount, now, echo_bytes, violations)
        }
        ContributionOutcome::Unpriceable => DenyReason::Unpriceable,
        ContributionOutcome::OutOfRange => DenyReason::OutOfRange,
        ContributionOutcome::Ungoverned => unreachable!("returned above"),
    };
    let display = gate.display_scope(&scope);
    if gate.mode == Mode::Block {
        refuse(gate, reason, &display, echo_bytes)
    } else {
        // Monitor mode: the call still happened, so it is recorded (at a zero
        // contribution — its real exposure is unknown or unrepresentable, not
        // zero, but there is nothing exact to charge) so the scope shows up in
        // the ledger and an operator can see the gap; the gap itself is made
        // visible on the header rather than silently inflating or deflating the
        // running total. At the scope cap, or if the shared ledger is
        // contended or unavailable, nothing is recorded; the stamp already
        // flags the call.
        let _ = gate.ledger.record(&scope, 0, now);
        let stamp = format!("monitor;scope={display};reason={}", reason.label());
        Flow::Continue(Ticket::None(stamp))
    }
}

async fn request_filter(
    request_state: RequestState,
    auth: Authentication,
    clock: &Clock,
    gate: &Gate,
    violations: &PolicyViolations,
) -> Flow<Ticket> {
    let headers_state = request_state.into_headers_state().await;
    // The admission instant: a reservation's timeout runs from here.
    let now = epoch_ms(clock.now());
    // Resolved at the header phase, before any body is buffered.
    let identity = gate.identity(
        auth.authentication().as_ref(),
        &headers_state.handler().headers(),
    );
    if !headers_state.contains_body() {
        return decide(identity, now, gate, RawBody::NoBody, violations);
    }
    // Header-phase gate, BEFORE ever calling `into_headers_body_state()`:
    // an oversized, non-JSON, or compressed body is never buffered at all —
    // `decide` still runs (as `Uninspectable`) so this call gets the same
    // fail-closed handling as a body this policy read and found unpriceable.
    if !request_is_inspectable(headers_state.handler()) {
        return decide(identity, now, gate, RawBody::Uninspectable, violations);
    }
    let state = headers_state.into_headers_body_state().await;
    let body = state.handler().body();
    // Defense in depth: a Content-Length that undersold the real body size
    // must not smuggle an oversized body past the header-phase gate above.
    let raw_body = if body.len() <= MAX_INSPECT_BYTES {
        RawBody::Present(body.as_ref())
    } else {
        RawBody::Uninspectable
    };
    decide(identity, now, gate, raw_body, violations)
}

/// Milliseconds since the Unix epoch. A clock before the epoch reads as 0.
pub(crate) fn epoch_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Logs ledger counters (never identities) when a settlement was not the
/// normal on-time kind, so stranded and late reservations are visible.
fn log_unusual_settlement(settlement: Settlement, stats: LedgerStats) {
    logger::info!(
        "aggregate-risk-gate: settlement={} active={} committed={} released={} expired={} \
         late-committed={} late-released={} abandoned={} not-active={} deferred={} contended={}",
        settlement.label(),
        stats.active,
        stats.committed,
        stats.released,
        stats.expired,
        stats.late_committed,
        stats.late_released,
        stats.abandoned,
        stats.not_active,
        stats.deferred,
        stats.contended
    );
}

async fn response_filter(
    response_state: ResponseState,
    request_data: RequestData<Ticket>,
    clock: &Clock,
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
    let (stamp, reservation) = match ticket {
        Ticket::None(stamp) => (stamp, None),
        Ticket::Reserved(stamp, reservation) => (stamp, Some(reservation)),
    };
    let Some(reservation) = reservation else {
        headers_state
            .handler()
            .set_header(&gate.result_header, &stamp);
        return;
    };

    // Every contribution mode settles at exactly the reserved amount. In
    // particular estimated-token-weight is NOT reconciled against real usage:
    // this filter never calls `into_headers_body_state()` on the response leg
    // (headers-only, by design — buffering a large/streamed upstream reply
    // here would risk a 504 for no gain worth that risk), so there is no real
    // `usage.total_tokens` to read. See the Honesty boundaries section in
    // README.md and the `contribution` field doc in gcl.yaml.
    //
    // Settlement is by reservation id, so a duplicate or reordered response
    // cannot settle twice, and a reservation already reclaimed by timeout is
    // settled late (see `Settlement`). The header reports which happened.
    let now = epoch_ms(clock.now());
    let settlement = if is_success(headers_state.status_code()) {
        gate.ledger.commit(&reservation, now)
    } else {
        gate.ledger.release(&reservation, now)
    };
    headers_state.handler().set_header(
        &gate.result_header,
        &format!("{stamp};settlement={}", settlement.label()),
    );
    if !matches!(settlement, Settlement::Committed | Settlement::Released) {
        log_unusual_settlement(settlement, gate.ledger.stats());
    }
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    violations: PolicyViolations,
    clock: Clock,
    store_builder: DataStorageBuilder,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Invalid policy configuration at line {}, column {} ({:?})",
            err.line(),
            err.column(),
            err.classify()
        )
    })?;

    let clock = std::rc::Rc::new(clock);
    let gate = Gate::from_config_with(&config, |namespace| {
        let storage = match namespace {
            None => store_builder.local(NODE_LEDGER_STORE),
            Some(namespace) => store_builder
                .clone()
                .shared()
                .local(format!("aggregate-risk-gate-ledger-{namespace}")),
        };
        Box::new(PdkStore {
            storage,
            clock: clock.clone(),
        })
    })?;
    if gate
        .governed_methods
        .iter()
        .any(|method| method == "initialize" || method.starts_with("notifications/"))
    {
        logger::warn!(
            "Aggregate Risk Gate: governedMethods includes initialize or a notifications/* \
             method; an exhausted budget will then block the MCP handshake or cancellation"
        );
    }
    if config.ledger_backend == "node" && config.scope_digest_key.is_empty() {
        // Not refused: it is the default configuration, which must start.
        logger::warn!(
            "Aggregate Risk Gate: ledgerBackend is node and scopeDigestKey is empty, so \
             node ledger keys are an unkeyed HMAC of each identity; any filter on this \
             replica that can list shared-data keys can confirm a guessed identity. \
             Set scopeDigestKey to a secret."
        );
    }
    logger::info!(
        "Aggregate Risk Gate armed: budgetScope={}, aggregateBudget={}, contribution={}, \
         ledgerBackend={}, mode={}",
        gate.budget_scope,
        gate.aggregate_budget,
        config.contribution,
        config.ledger_backend,
        if gate.mode == Mode::Block {
            "block"
        } else {
            "monitor"
        }
    );

    let filter =
        on_request(|rs, auth: Authentication| request_filter(rs, auth, &clock, &gate, &violations))
            .on_response(|res, data| response_filter(res, data, &clock, &gate));
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
            // The arithmetic tests below drive identity through a header and
            // read raw scopes off the result header. The identity tests set
            // the production defaults (authentication + digest) explicitly.
            "identitySource": "trusted-header",
            "identityField": "client_id",
            "scopeHeader": "x-agent-id",
            "maxScopes": 10000,
            "ledgerBackend": "node",
            "ledgerNamespace": "",
            "reservationTimeoutMs": 60000,
            "scopeDisclosure": "raw",
            "scopeDigestKey": "",
            "aggregateBudget": 3000,
            "window": "fixed-period",
            "windowMs": 86400000,
            "contribution": "fixed-weight",
            "fixedWeight": 800,
            "governedMethods": ["tools/call"],
            "spendAmountField": "params.amount",
            "spendCurrency": "USD",
            "estimatedTokens": 500,
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

    fn rpc_request_with_amount(id: i64, agent: &str, amount: u64) -> UnitHttpRequest {
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

    /// A 200 whose body reports `usage` — any JSON value, so tests can send
    /// under-, over-, and malformed usage figures and show none of them
    /// changes what the estimated-token-weight mode charges.
    fn usage_backend(usage: Value) -> impl Fn(UnitHttpRequest) -> UnitHttpResponse {
        move |_req| {
            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"text": "ok"},
                "usage": usage
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
        assert_eq!(
            response.header("x-aggregate-risk-gate"),
            Some("denied;scope=agent;reason=missing-identity")
        );
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
            .starts_with("monitor;scope=agent (missing);"));
    }

    // -----------------------------------------------------------------------
    // Identity (issue #14) end to end: verified authentication by default, a
    // trusted header only when opted in, bounded cardinality, no raw IDs.
    // -----------------------------------------------------------------------

    /// The production identity defaults: verified `client_id`, digest display.
    fn auth_config(overrides: Value) -> String {
        let mut merged = json!({
            "identitySource": "authentication",
            "identityField": "client_id",
            "scopeDisclosure": "digest",
        });
        for (key, value) in overrides.as_object().unwrap() {
            merged[key] = value.clone();
        }
        config(merged)
    }

    fn authenticated(request: UnitHttpRequest, client_id: &str) -> UnitHttpRequest {
        request.with_authentication_data(AuthenticationData {
            client_id: Some(client_id.to_string()),
            ..Default::default()
        })
    }

    fn rpc_call(id: i64) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {}})
    }

    #[test]
    fn a_spoofed_scope_header_is_ignored_under_authentication_identity() {
        let mut tester = UnitTestBuilder::default()
            .with_config(auth_config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        // One verified client rotates the header value on every call. The
        // header plays no part, so all four calls share one budget.
        for i in 0..3 {
            let spoof = format!("fresh-agent-{i}");
            let request = authenticated(jsonrpc_request(rpc_call(i), Some(&spoof)), "app-1");
            assert_eq!(response_error_code(&tester.request(request)), None);
        }
        let request = authenticated(jsonrpc_request(rpc_call(4), Some("fresh-agent-4")), "app-1");
        assert_eq!(
            response_error_code(&tester.request(request)),
            Some(MCP_BLOCKED_CODE),
            "rotating the header must not mint a fresh budget"
        );
    }

    #[test]
    fn missing_authentication_fails_closed_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(auth_config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        // A scope header is present but is not an identity in this mode.
        let response = tester.request(jsonrpc_request(rpc_call(1), Some("broker-7")));
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
        assert_eq!(
            response.header("x-aggregate-risk-gate"),
            Some("denied;scope=agent;reason=missing-identity")
        );
    }

    #[test]
    fn a_malformed_authenticated_identity_is_denied_as_invalid() {
        let mut tester = UnitTestBuilder::default()
            .with_config(auth_config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let oversized = "a".repeat(MAX_IDENTITY_BYTES + 1);
        for (i, bad) in [oversized.as_str(), "app;scope=other", "app 1"]
            .iter()
            .enumerate()
        {
            let request = authenticated(jsonrpc_request(rpc_call(i as i64), None), bad);
            let response = tester.request(request);
            assert_eq!(
                response_error_code(&response),
                Some(MCP_BLOCKED_CODE),
                "{:?}",
                bad
            );
            assert_eq!(
                response.header("x-aggregate-risk-gate"),
                Some("denied;scope=agent;reason=invalid-identity")
            );
        }
    }

    #[test]
    fn case_and_whitespace_variants_of_one_identity_share_a_budget() {
        let mut tester = UnitTestBuilder::default()
            .with_config(auth_config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for (i, variant) in ["App-1", "app-1", " APP-1 "].iter().enumerate() {
            let request = authenticated(jsonrpc_request(rpc_call(i as i64), None), variant);
            assert_eq!(response_error_code(&tester.request(request)), None);
        }
        let request = authenticated(jsonrpc_request(rpc_call(4), None), "aPp-1");
        assert_eq!(
            response_error_code(&tester.request(request)),
            Some(MCP_BLOCKED_CODE)
        );
    }

    #[test]
    fn a_duplicated_trusted_header_is_denied_as_invalid() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let request =
            jsonrpc_request(rpc_call(1), Some("broker-7")).with_header("X-Agent-Id", "broker-9");
        let response = tester.request(request);
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
        assert_eq!(
            response.header("x-aggregate-risk-gate"),
            Some("denied;scope=agent;reason=invalid-identity")
        );
    }

    #[test]
    fn the_default_result_header_never_echoes_the_raw_identity() {
        let mut tester = UnitTestBuilder::default()
            .with_config(auth_config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for i in 0..4 {
            let request = authenticated(jsonrpc_request(rpc_call(i), None), "secret-client-77");
            let response = tester.request(request);
            let stamp = response
                .header("x-aggregate-risk-gate")
                .unwrap()
                .to_string();
            assert!(stamp.contains("scope=agent:sha256-"), "{}", stamp);
            assert!(!stamp.contains("secret-client-77"), "{}", stamp);
            assert!(!String::from_utf8_lossy(response.body()).contains("secret-client-77"));
        }
    }

    #[test]
    fn high_cardinality_identities_hit_the_scope_cap_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(auth_config(json!({"maxScopes": 2})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for (i, client) in ["app-1", "app-2"].iter().enumerate() {
            let request = authenticated(jsonrpc_request(rpc_call(i as i64), None), client);
            assert_eq!(response_error_code(&tester.request(request)), None);
        }
        // Both tracked scopes hold committed exposure, so neither is idle and
        // neither may be evicted to make room: the third identity is refused.
        let request = authenticated(jsonrpc_request(rpc_call(3), None), "app-3");
        let response = tester.request(request);
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
        assert!(response
            .header("x-aggregate-risk-gate")
            .unwrap()
            .ends_with(";reason=scope-capacity"));
        // The tracked scopes keep their budgets.
        let request = authenticated(jsonrpc_request(rpc_call(4), None), "app-1");
        assert_eq!(response_error_code(&tester.request(request)), None);
    }

    #[test]
    fn the_scope_cap_never_denies_in_monitor_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(auth_config(json!({"maxScopes": 1, "mode": "monitor"})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let request = authenticated(jsonrpc_request(rpc_call(1), None), "app-1");
        assert_eq!(response_error_code(&tester.request(request)), None);
        let request = authenticated(jsonrpc_request(rpc_call(2), None), "app-2");
        let response = tester.request(request);
        assert_eq!(response_error_code(&response), None);
        assert!(response
            .header("x-aggregate-risk-gate")
            .unwrap()
            .ends_with(";reason=scope-capacity"));
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
            let response = tester.request(rpc_request_with_amount(i, "broker-7", 800));
            assert_eq!(response_error_code(&response), None);
        }
        let response = tester.request(rpc_request_with_amount(4, "broker-7", 800));
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
    fn estimated_token_weight_commits_the_full_estimate_and_never_reads_the_response_body() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "estimated-token-weight", "estimatedTokens": 600, "aggregateBudget": 1000})))
            .with_backend(usage_backend(json!({"total_tokens": 50})))
            .with_entrypoint(super::configure);
        // The backend reports a real usage.total_tokens of 50, far below the
        // 600-token estimate — but the response leg is headers-only and never
        // reads the response body (see response_filter), so the FULL 600
        // estimate is what gets committed, not the smaller real figure.
        let first = tester.request(rpc_request(1, "broker-7"));
        assert_eq!(response_error_code(&first), None);
        let header = first.header("x-aggregate-risk-gate").unwrap();
        assert!(header.contains("contribution=600;"));
        assert!(header.ends_with(";unit=estimated-tokens;settlement=committed"));
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
            header.contains("total=2400/3000;unit=points"),
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
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"amount": 800}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"amount": 800}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"amount": 800}},
        ]);
        let response = tester.request(jsonrpc_request(batch, Some("broker-7")));
        assert_eq!(response_error_code(&response), None);
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(header.contains("total=2400/3000;unit=USD-minor"));
        // Only denies (2400 + 800 = 3200 > 3000) if the batch truly summed to
        // 2400 rather than, say, pricing the whole batch as a single item.
        let response = tester.request(rpc_request_with_amount(4, "broker-7", 800));
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
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"amount": 100}},
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
        // which id is "the" id. This 4th call is denied (a duplicate member
        // is unpriceable, and the budget is spent anyway), but neither id may
        // ever be echoed — fall back to the generic empty-403, exactly as an
        // unparseable body would (issue #36 containment).
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
    fn estimated_token_weight_charges_the_estimate_when_usage_is_absent() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "estimated-token-weight", "estimatedTokens": 300, "aggregateBudget": 1000})))
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
    fn estimated_token_weight_releases_the_estimate_on_upstream_failure() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "estimated-token-weight", "estimatedTokens": 900, "aggregateBudget": 1000})))
            .with_backend(failing_backend)
            .with_entrypoint(super::configure);
        tester.request(rpc_request(1, "broker-7"));
        // If the failed call's 900-token estimate were not released, a second
        // 900-token reservation would exceed the 1000 budget (900+900=1800).
        let response = tester.request(rpc_request(2, "broker-7"));
        assert_eq!(
            response_error_code(&response),
            None,
            "a failed estimated-token-weight call must release its estimate"
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
        assert!(header.contains("contribution=800;total=800/3000;unit=points"));
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
        assert!(header.contains("would-be-total=3200;budget=3000;unit=points"));
    }

    // -----------------------------------------------------------------------
    // Exact integer units (P4A review #18): amounts are counted, never
    // rounded; anything that is not an exact in-range integer is refused.
    // -----------------------------------------------------------------------

    fn spend_body(amount_literal: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"amount":{amount_literal}}}}}"#
        )
    }

    #[test]
    fn spend_amount_rejects_every_non_integer_or_negative_amount_in_block_mode() {
        // 12.34 and 1234.0 are decimals, 1e3 is an exponent, -5 is negative,
        // "1234" is a string, and 18446744073709551616 (2^64) does not fit a
        // u64 at all. Each must be refused before it reaches upstream, never
        // rounded or coerced into a charge.
        for literal in [
            "12.34",
            "1234.0",
            "1e3",
            "-5",
            "\"1234\"",
            "18446744073709551616",
        ] {
            let backend = Rc::new(TraceBackend::new(ok_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(config(json!({"contribution": "spend-amount"})))
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let response = tester.request(raw_request(&spend_body(literal), Some("broker-7")));
            assert!(
                backend.next().is_none(),
                "amount {} must never reach upstream",
                literal
            );
            assert_eq!(
                response_error_code(&response),
                Some(MCP_BLOCKED_CODE),
                "amount {literal}"
            );
            let header = response.header("x-aggregate-risk-gate").unwrap();
            assert!(
                header.contains("reason=unpriceable"),
                "amount {}: {}",
                literal,
                header
            );
        }
    }

    #[test]
    fn spend_amount_above_max_units_is_denied_as_out_of_range() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(
                json!({"contribution": "spend-amount", "aggregateBudget": MAX_UNITS}),
            ))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let over = (MAX_UNITS + 1).to_string();
        let response = tester.request(raw_request(&spend_body(&over), Some("broker-7")));
        assert!(backend.next().is_none());
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(header.contains("reason=out-of-range"), "{}", header);

        // Exactly MAX_UNITS is still an exact, chargeable amount.
        let response = tester.request(raw_request(
            &spend_body(&MAX_UNITS.to_string()),
            Some("broker-8"),
        ));
        assert_eq!(response_error_code(&response), None);
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(
            header.contains(&format!("contribution={MAX_UNITS};")),
            "{}",
            header
        );
    }

    #[test]
    fn a_spend_amount_batch_whose_sum_overflows_is_denied_as_out_of_range() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(
                json!({"contribution": "spend-amount", "aggregateBudget": MAX_UNITS}),
            ))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        // Each item is individually in range; their sum is not.
        let batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"amount": MAX_UNITS}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"amount": 1}},
        ]);
        let response = tester.request(jsonrpc_request(batch, Some("broker-7")));
        assert!(backend.next().is_none());
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(header.contains("reason=out-of-range"), "{}", header);
    }

    #[test]
    fn a_fixed_weight_batch_whose_product_overflows_is_denied_as_out_of_range() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(
                json!({"fixedWeight": MAX_UNITS, "aggregateBudget": MAX_UNITS}),
            ))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let response = tester.request(batch_request(&[1, 2], "broker-7"));
        assert!(backend.next().is_none());
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(header.contains("reason=out-of-range"), "{}", header);
    }

    #[test]
    fn monitor_mode_forwards_an_out_of_range_call_and_stamps_the_gap() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(
                json!({"contribution": "spend-amount", "mode": "monitor"}),
            ))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let over = (MAX_UNITS + 1).to_string();
        let response = tester.request(raw_request(&spend_body(&over), Some("broker-7")));
        assert!(backend.next().is_some(), "monitor mode never blocks");
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert_eq!(header, "monitor;scope=agent:broker-7;reason=out-of-range");
    }

    #[test]
    fn small_spend_amounts_accumulate_exactly_onto_the_budget() {
        // 10 + 20 minor units against a budget of 30: in binary floating point
        // 0.1 + 0.2 > 0.3, so a float ledger refuses this budget-exact call.
        // An integer ledger lands on the budget exactly and admits it; one
        // more minor unit is then refused.
        let mut tester = UnitTestBuilder::default()
            .with_config(config(
                json!({"contribution": "spend-amount", "aggregateBudget": 30}),
            ))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        assert_eq!(
            response_error_code(&tester.request(rpc_request_with_amount(1, "broker-7", 10))),
            None
        );
        let response = tester.request(rpc_request_with_amount(2, "broker-7", 20));
        assert_eq!(response_error_code(&response), None);
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert_eq!(
            header,
            "allowed;scope=agent:broker-7;contribution=20;total=30/30;unit=USD-minor;settlement=committed"
        );
        let response = tester.request(rpc_request_with_amount(3, "broker-7", 1));
        assert_eq!(response_error_code(&response), Some(MCP_BLOCKED_CODE));
    }

    #[test]
    fn the_spend_currency_is_stamped_as_the_unit() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(
                json!({"contribution": "spend-amount", "spendCurrency": "EUR"}),
            ))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let response = tester.request(rpc_request_with_amount(1, "broker-7", 1234));
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(
            header
                .ends_with("contribution=1234;total=1234/3000;unit=EUR-minor;settlement=committed"),
            "{}",
            header
        );
    }

    #[test]
    fn estimated_token_weight_ignores_over_and_malformed_usage_figures() {
        // Under-usage is covered above; here the backend reports usage far
        // OVER the estimate, and several malformed shapes. None of them may
        // change the charge: each first call commits exactly the 600 estimate,
        // so a second 600 call fits a 1200 budget and a third is refused.
        for usage in [
            json!({"total_tokens": 5000}),
            json!({"total_tokens": "lots"}),
            json!({"total_tokens": -1}),
            json!({"total_tokens": 12.5}),
            json!(null),
            json!("not-an-object"),
        ] {
            let mut tester = UnitTestBuilder::default()
                .with_config(config(json!({"contribution": "estimated-token-weight", "estimatedTokens": 600, "aggregateBudget": 1200})))
                .with_backend(usage_backend(usage.clone()))
                .with_entrypoint(super::configure);
            for id in 1..=2 {
                let response = tester.request(rpc_request(id, "broker-7"));
                assert_eq!(
                    response_error_code(&response),
                    None,
                    "usage {usage}, call {id}"
                );
                let header = response.header("x-aggregate-risk-gate").unwrap();
                assert!(
                    header.contains("contribution=600;"),
                    "usage {}: {}",
                    usage,
                    header
                );
            }
            let response = tester.request(rpc_request(3, "broker-7"));
            assert_eq!(
                response_error_code(&response),
                Some(MCP_BLOCKED_CODE),
                "usage {usage}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Gate::from_config validation — direct, no pdk_unit harness required.
    // -----------------------------------------------------------------------

    fn valid_config_struct() -> Config {
        Config {
            aggregate_budget: 3000,
            budget_scope: "agent".to_string(),
            contribution: "fixed-weight".to_string(),
            estimated_tokens: 500,
            fixed_weight: 800,
            governed_methods: vec!["tools/call".to_string()],
            identity_field: "client_id".to_string(),
            identity_source: "authentication".to_string(),
            ledger_backend: "node".to_string(),
            ledger_namespace: String::new(),
            max_scopes: 10000,
            reservation_timeout_ms: 60000,
            mode: "block".to_string(),
            on_deny: "rpc-error".to_string(),
            result_header: "x-aggregate-risk-gate".to_string(),
            scope_digest_key: String::new(),
            scope_disclosure: "digest".to_string(),
            scope_header: "x-agent-id".to_string(),
            spend_amount_field: "params.amount".to_string(),
            spend_currency: "USD".to_string(),
            window: "fixed-period".to_string(),
            window_ms: 86_400_000,
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
    fn both_window_kinds_are_accepted() {
        for window in ["fixed-period", "worker-lifetime"] {
            let mut cfg = valid_config_struct();
            cfg.window = window.to_string();
            assert!(Gate::from_config(&cfg).is_ok(), "{}", window);
        }
    }

    #[test]
    fn the_old_rolling_window_name_is_rejected_with_its_replacements() {
        let mut cfg = valid_config_struct();
        cfg.window = "rolling-24h".to_string();
        let err = Gate::from_config(&cfg).err().unwrap().to_string();
        assert!(err.contains("fixed-period"), "{}", err);
        assert!(err.contains("worker-lifetime"), "{}", err);
    }

    #[test]
    fn window_ms_must_be_between_one_minute_and_366_days() {
        for bad in [0, 59_999, -1, 31_622_400_001] {
            let mut cfg = valid_config_struct();
            cfg.window_ms = bad;
            assert!(Gate::from_config(&cfg).is_err(), "windowMs {}", bad);
        }
        for good in [60_000, 86_400_000, 31_622_400_000] {
            let mut cfg = valid_config_struct();
            cfg.window_ms = good;
            assert!(Gate::from_config(&cfg).is_ok(), "windowMs {}", good);
        }
        // Ignored, so not validated, without a fixed window.
        let mut cfg = valid_config_struct();
        cfg.window = "worker-lifetime".to_string();
        cfg.window_ms = 0;
        assert!(Gate::from_config(&cfg).is_ok());
    }

    #[test]
    fn the_old_token_cost_contribution_name_is_rejected_with_its_new_name() {
        let mut cfg = valid_config_struct();
        cfg.contribution = "token-cost".to_string();
        let err = Gate::from_config(&cfg)
            .err()
            .expect("token-cost must be rejected");
        assert!(
            err.to_string().contains("estimated-token-weight"),
            "{}",
            err
        );
    }

    #[test]
    fn estimated_token_weight_contribution_is_accepted() {
        let mut cfg = valid_config_struct();
        cfg.contribution = "estimated-token-weight".to_string();
        assert!(Gate::from_config(&cfg).is_ok());
    }

    #[test]
    fn spend_currency_must_be_three_uppercase_letters() {
        for bad in ["", "usd", "US", "USDX", "U$D", "€UR"] {
            let mut cfg = valid_config_struct();
            cfg.spend_currency = bad.to_string();
            assert!(Gate::from_config(&cfg).is_err(), "spendCurrency {:?}", bad);
        }
        let mut cfg = valid_config_struct();
        cfg.spend_currency = "JPY".to_string();
        assert!(Gate::from_config(&cfg).is_ok());
    }

    #[test]
    fn config_amounts_above_max_units_are_rejected() {
        let mut cfg = valid_config_struct();
        cfg.fixed_weight = MAX_UNITS as i64 + 1;
        assert!(Gate::from_config(&cfg).is_err());
        let mut cfg = valid_config_struct();
        cfg.estimated_tokens = i64::MAX;
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn a_fractional_config_amount_fails_to_deserialize() {
        // The generated Config types amounts as i64, so a fractional budget
        // never reaches Gate::from_config — serde refuses it outright.
        let mut value: Value = serde_json::from_str(&config(json!({}))).unwrap();
        value["aggregateBudget"] = json!(3000.5);
        assert!(serde_json::from_value::<Config>(value).is_err());
    }

    #[test]
    fn negative_aggregate_budget_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.aggregate_budget = -1;
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn aggregate_budget_above_max_units_is_rejected() {
        // Replaces the old non-finite (NaN) check: config amounts are now
        // integers, so the out-of-range edge is anything past 2^53 - 1.
        let mut cfg = valid_config_struct();
        cfg.aggregate_budget = MAX_UNITS as i64 + 1;
        assert!(Gate::from_config(&cfg).is_err());
        cfg.aggregate_budget = MAX_UNITS as i64;
        assert!(Gate::from_config(&cfg).is_ok());
    }

    #[test]
    fn negative_fixed_weight_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.fixed_weight = -1;
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn negative_estimated_tokens_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.estimated_tokens = -1;
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn blank_scope_header_is_rejected_for_a_trusted_header_identity() {
        let mut cfg = valid_config_struct();
        cfg.identity_source = "trusted-header".to_string();
        cfg.scope_header = "   ".to_string();
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn blank_scope_header_is_accepted_for_an_authentication_identity() {
        let mut cfg = valid_config_struct();
        cfg.scope_header = String::new();
        assert!(Gate::from_config(&cfg).is_ok());
    }

    #[test]
    fn blank_scope_header_is_accepted_when_budget_scope_is_fabric() {
        let mut cfg = valid_config_struct();
        cfg.budget_scope = "fabric".to_string();
        cfg.identity_source = "trusted-header".to_string();
        cfg.scope_header = String::new();
        assert!(Gate::from_config(&cfg).is_ok());
    }

    #[test]
    fn invalid_identity_source_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.identity_source = "header".to_string();
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn identity_field_accepts_only_known_fields_and_property_paths() {
        for good in [
            "client_id",
            "principal",
            "properties.sub",
            "properties.claims.agent",
        ] {
            let mut cfg = valid_config_struct();
            cfg.identity_field = good.to_string();
            assert!(Gate::from_config(&cfg).is_ok(), "identityField {:?}", good);
        }
        for bad in [
            "",
            "client_name",
            "properties.",
            "properties..sub",
            "properties.a.",
            "sub",
        ] {
            let mut cfg = valid_config_struct();
            cfg.identity_field = bad.to_string();
            assert!(Gate::from_config(&cfg).is_err(), "identityField {:?}", bad);
        }
    }

    #[test]
    fn a_successful_response_is_stamped_committed_and_a_failure_released() {
        let mut ok = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let header = ok.request(rpc_request(1, "broker-7"));
        assert!(
            header
                .header("x-aggregate-risk-gate")
                .unwrap()
                .ends_with(";settlement=committed"),
            "{:?}",
            header.header("x-aggregate-risk-gate")
        );

        let mut failing = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(failing_backend)
            .with_entrypoint(super::configure);
        let response = failing.request(rpc_request(1, "broker-7"));
        assert!(
            response
                .header("x-aggregate-risk-gate")
                .unwrap()
                .ends_with(";settlement=released"),
            "{:?}",
            response.header("x-aggregate-risk-gate")
        );
    }

    #[test]
    fn a_worker_restart_resets_the_in_process_ledger() {
        // Documented behavior: the ledger lives in worker memory, so a
        // restart forgets every committed and reserved amount (fail-open).
        let mut tester = UnitTestBuilder::default()
            .with_config(config(
                json!({"aggregateBudget": 2000, "fixedWeight": 1000}),
            ))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for id in 1..=2 {
            assert_eq!(
                response_error_code(&tester.request(rpc_request(id, "broker-7"))),
                None
            );
        }
        assert_eq!(
            response_error_code(&tester.request(rpc_request(3, "broker-7"))),
            Some(MCP_BLOCKED_CODE)
        );
        tester.restart();
        let after = tester.request(rpc_request(4, "broker-7"));
        assert_eq!(response_error_code(&after), None);
        assert!(after
            .header("x-aggregate-risk-gate")
            .unwrap()
            .contains("total=1000/2000"));
    }

    #[test]
    fn a_fixed_window_resets_the_budget_on_the_gateway_clock() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({
                "aggregateBudget": 2000,
                "fixedWeight": 1000,
                "windowMs": 60000,
            })))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for id in 1..=2 {
            assert_eq!(
                response_error_code(&tester.request(rpc_request(id, "broker-7"))),
                None
            );
        }
        assert_eq!(
            response_error_code(&tester.request(rpc_request(3, "broker-7"))),
            Some(MCP_BLOCKED_CODE)
        );
        tester.sleep(std::time::Duration::from_millis(59_000));
        assert_eq!(
            response_error_code(&tester.request(rpc_request(4, "broker-7"))),
            Some(MCP_BLOCKED_CODE),
            "still inside the first window"
        );
        tester.sleep(std::time::Duration::from_millis(1_000));
        let next = tester.request(rpc_request(5, "broker-7"));
        assert_eq!(response_error_code(&next), None);
        assert!(next
            .header("x-aggregate-risk-gate")
            .unwrap()
            .contains("total=1000/2000"));
    }

    #[test]
    fn a_worker_lifetime_window_never_resets() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({
                "aggregateBudget": 1000,
                "fixedWeight": 1000,
                "window": "worker-lifetime",
            })))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        assert_eq!(
            response_error_code(&tester.request(rpc_request(1, "broker-7"))),
            None
        );
        tester.sleep(std::time::Duration::from_millis(400 * 86_400_000));
        assert_eq!(
            response_error_code(&tester.request(rpc_request(2, "broker-7"))),
            Some(MCP_BLOCKED_CODE)
        );
    }

    #[test]
    fn reservation_timeout_must_be_between_one_second_and_one_day() {
        for bad in [0, 999, -1, 86_400_001] {
            let mut cfg = valid_config_struct();
            cfg.reservation_timeout_ms = bad;
            assert!(Gate::from_config(&cfg).is_err(), "timeout {}", bad);
        }
        for good in [1_000, 60_000, 86_400_000] {
            let mut cfg = valid_config_struct();
            cfg.reservation_timeout_ms = good;
            assert!(Gate::from_config(&cfg).is_ok(), "timeout {}", good);
        }
    }

    #[test]
    fn max_scopes_must_be_between_one_and_a_million() {
        for bad in [0, -1, 1_000_001] {
            let mut cfg = valid_config_struct();
            cfg.max_scopes = bad;
            assert!(Gate::from_config(&cfg).is_err(), "maxScopes {}", bad);
        }
        for good in [1, 1_000_000] {
            let mut cfg = valid_config_struct();
            cfg.max_scopes = good;
            assert!(Gate::from_config(&cfg).is_ok(), "maxScopes {}", good);
        }
    }

    #[test]
    fn invalid_scope_disclosure_is_rejected() {
        let mut cfg = valid_config_struct();
        cfg.scope_disclosure = "hash".to_string();
        assert!(Gate::from_config(&cfg).is_err());
    }

    // -----------------------------------------------------------------------
    // Identity canonicalization and disclosure — direct, no harness.
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_identity_trims_and_lowercases() {
        assert_eq!(
            canonical_identity("  Broker-7\t"),
            Identity::Scope("broker-7".to_string())
        );
        assert_eq!(
            canonical_identity("BROKER-7"),
            canonical_identity("broker-7")
        );
    }

    #[test]
    fn canonical_identity_treats_blank_as_missing() {
        assert_eq!(canonical_identity(""), Identity::Missing);
        assert_eq!(canonical_identity(" \t "), Identity::Missing);
    }

    #[test]
    fn canonical_identity_rejects_oversized_values() {
        let max = "a".repeat(MAX_IDENTITY_BYTES);
        assert_eq!(canonical_identity(&max), Identity::Scope(max.clone()));
        let over = "a".repeat(MAX_IDENTITY_BYTES + 1);
        assert_eq!(canonical_identity(&over), Identity::Invalid);
    }

    #[test]
    fn canonical_identity_rejects_stamp_delimiters_and_non_visible_ascii() {
        for bad in [
            "a,b", "a;b", "a=b", "a\"b", "a\\b", "a b", "a\u{7f}b", "a\u{0}b", "brökér", "a\nb",
        ] {
            assert_eq!(canonical_identity(bad), Identity::Invalid, "{:?}", bad);
        }
    }

    fn gate_with(overrides: Value) -> Gate {
        let cfg: Config = serde_json::from_str(&config(overrides)).unwrap();
        Gate::from_config(&cfg).unwrap()
    }

    #[test]
    fn digest_disclosure_hides_the_raw_identity() {
        let gate = gate_with(json!({"scopeDisclosure": "digest"}));
        let shown = gate.display_scope("agent:broker-7");
        // The README's example stamp; SHA-256("agent:broker-7"), first 8 bytes.
        assert_eq!(shown, "agent:sha256-b534199b5ab2d7a9");
        assert!(!shown.contains("broker-7"), "{}", shown);
        assert_eq!(shown.len(), "agent:sha256-".len() + 16);
        // Stable: the same identity always maps to the same digest.
        assert_eq!(shown, gate.display_scope("agent:broker-7"));
        assert_ne!(shown, gate.display_scope("agent:broker-9"));
    }

    #[test]
    fn keyed_digest_disclosure_uses_hmac_and_depends_on_the_key() {
        let a = gate_with(json!({"scopeDisclosure": "digest", "scopeDigestKey": "key-a"}));
        let b = gate_with(json!({"scopeDisclosure": "digest", "scopeDigestKey": "key-b"}));
        let shown_a = a.display_scope("agent:broker-7");
        assert!(shown_a.starts_with("agent:hmac-"), "{}", shown_a);
        assert_ne!(shown_a, b.display_scope("agent:broker-7"));
    }

    #[test]
    fn none_disclosure_shows_only_the_budget_scope() {
        let gate = gate_with(json!({"scopeDisclosure": "none"}));
        assert_eq!(gate.display_scope("agent:broker-7"), "agent");
    }

    #[test]
    fn bucket_keys_are_displayed_as_is() {
        let gate = gate_with(json!({"scopeDisclosure": "digest"}));
        assert_eq!(gate.display_scope("agent (missing)"), "agent (missing)");
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_trusted_header_sent_twice_in_any_case_is_invalid() {
        let gate = gate_with(json!({}));
        let dup = headers(&[("x-agent-id", "broker-7"), ("X-Agent-Id", "broker-9")]);
        assert_eq!(gate.identity(None, &dup), Identity::Invalid);
        let once = headers(&[("X-AGENT-ID", "Broker-7")]);
        assert_eq!(
            gate.identity(None, &once),
            Identity::Scope("agent:broker-7".to_string())
        );
        assert_eq!(gate.identity(None, &[]), Identity::Missing);
    }

    #[test]
    fn authentication_identity_reads_the_configured_field() {
        let auth = AuthenticationData {
            client_id: Some("App-1".to_string()),
            principal: Some("Alice".to_string()),
            properties: ScriptValue::Object(
                vec![
                    (
                        "sub".to_string(),
                        ScriptValue::String("Agent-42".to_string()),
                    ),
                    ("level".to_string(), ScriptValue::Number(3.0)),
                ]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let base = json!({"identitySource": "authentication"});
        let by = |field: &str| {
            let mut overrides = base.clone();
            overrides["identityField"] = json!(field);
            gate_with(overrides).identity(Some(&auth), &[])
        };
        assert_eq!(by("client_id"), Identity::Scope("agent:app-1".to_string()));
        assert_eq!(by("principal"), Identity::Scope("agent:alice".to_string()));
        assert_eq!(
            by("properties.sub"),
            Identity::Scope("agent:agent-42".to_string())
        );
        assert_eq!(by("properties.level"), Identity::Invalid);
        assert_eq!(by("properties.absent"), Identity::Missing);
        assert_eq!(
            gate_with(base).identity(None, &[]),
            Identity::Missing,
            "no authentication data at all"
        );
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

    // -----------------------------------------------------------------------
    // Governed methods (P4A review #47): only `governedMethods` are priced;
    // the rest of the MCP protocol passes through without touching the ledger.
    // -----------------------------------------------------------------------

    const PASS: &str = "pass;reason=ungoverned-method";

    /// A property store with nothing in it, so `decide` can be driven
    /// directly against a `Gate` whose ledger the test can then inspect.
    struct NoProperties;
    impl PropertyAccessor for NoProperties {
        fn read_property(&self, _path: &[&str]) -> Option<Vec<u8>> {
            None
        }
        fn set_property(&self, _path: &[&str], _value: Option<&[u8]>) {}
    }

    fn violations() -> PolicyViolations {
        PolicyViolations::new(NoProperties, String::new())
    }

    fn mcp(body: Value) -> UnitHttpRequest {
        jsonrpc_request(body, Some("broker-7"))
    }

    /// A client's JSON-RPC response to a server-initiated request.
    fn elicitation_response() -> Value {
        json!({"jsonrpc": "2.0", "id": "srv-1", "result": {"action": "accept"}})
    }

    #[test]
    fn a_full_mcp_session_runs_on_an_exhausted_spend_budget_and_only_tools_call_is_denied() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({
                "contribution": "spend-amount",
                "aggregateBudget": 1000,
            })))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        // Spend the whole budget with one governed call.
        let spent = tester.request(rpc_request_with_amount(0, "broker-7", 1000));
        assert_eq!(response_error_code(&spent), None);
        assert!(backend.next().is_some());

        let session = vec![
            mcp(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})),
            mcp(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})),
            mcp(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})),
            mcp(json!({"jsonrpc": "2.0", "id": 3, "method": "ping"})),
            UnitHttpRequest::get()
                .with_header("accept", "text/event-stream")
                .with_header("x-agent-id", "broker-7"),
            mcp(elicitation_response()),
            UnitHttpRequest::delete()
                .with_header("mcp-session-id", "session-1")
                .with_header("x-agent-id", "broker-7"),
        ];
        for (step, request) in session.into_iter().enumerate() {
            let response = tester.request(request);
            assert_eq!(response.status_code(), 200, "step {step}");
            assert_eq!(response_error_code(&response), None, "step {step}");
            assert_eq!(
                response.header("x-aggregate-risk-gate"),
                Some(PASS),
                "step {step}"
            );
            assert!(
                backend.next().is_some(),
                "step {} must reach upstream",
                step
            );
        }

        let over = tester.request(rpc_request_with_amount(4, "broker-7", 1));
        assert_eq!(response_error_code(&over), Some(MCP_BLOCKED_CODE));
        assert!(over
            .header("x-aggregate-risk-gate")
            .unwrap()
            .contains("would-be-total=1001;budget=1000"));
        // #18 still holds: a tools/call with no amount is unpriceable.
        let unpriced = tester.request(rpc_request(5, "broker-7"));
        assert_eq!(response_error_code(&unpriced), Some(MCP_BLOCKED_CODE));
        assert_eq!(
            unpriced.header("x-aggregate-risk-gate"),
            Some("denied;scope=agent:broker-7;reason=unpriceable")
        );
        assert!(
            backend.next().is_none(),
            "denied calls never reach upstream"
        );
    }

    #[test]
    fn ungoverned_traffic_creates_no_scope_reservation_or_ledger_change() {
        let gate = gate_with(json!({"contribution": "spend-amount"}));
        let bodies: Vec<Value> = vec![
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 9}}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
            elicitation_response(),
            json!({"jsonrpc": "2.0", "id": "srv-2", "error": {"code": -1, "message": "no"}}),
            json!([
                {"jsonrpc": "2.0", "id": 4, "method": "resources/list"},
                {"jsonrpc": "2.0", "method": "notifications/roots/list_changed"},
            ]),
        ];
        let identities = [
            Identity::Scope("agent:broker-7".to_string()),
            Identity::Missing,
            Identity::Invalid,
        ];
        let flows = bodies
            .iter()
            .map(|body| body.to_string().into_bytes())
            .flat_map(|bytes| {
                identities
                    .iter()
                    .map(move |identity| (identity.clone(), bytes.clone()))
            })
            .map(|(identity, bytes)| {
                decide(identity, 0, &gate, RawBody::Present(&bytes), &violations())
            })
            .chain(std::iter::once(decide(
                Identity::Missing,
                0,
                &gate,
                RawBody::NoBody,
                &violations(),
            )));
        for flow in flows {
            assert!(
                matches!(flow, Flow::Continue(Ticket::None(ref stamp)) if stamp == PASS),
                "{:?}",
                match flow {
                    Flow::Continue(ticket) => format!("{ticket:?}"),
                    Flow::Break(_) => "denied".to_string(),
                }
            );
        }
        assert_eq!(gate.ledger.scope_count(), 0, "no scope entry");
        assert_eq!(
            gate.ledger.stats(),
            LedgerStats::default(),
            "no ledger change"
        );
        assert_eq!(gate.ledger.snapshot("agent:broker-7").total(), 0);
    }

    #[test]
    fn ungoverned_traffic_never_takes_a_scope_slot() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"maxScopes": 1})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for agent in ["broker-1", "broker-2", "broker-3"] {
            let response = tester.request(jsonrpc_request(
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
                Some(agent),
            ));
            assert_eq!(response.header("x-aggregate-risk-gate"), Some(PASS));
        }
        // Had any initialize created a scope, this new identity would hit
        // the 1-scope cap and be refused with reason=scope-capacity.
        let response = tester.request(rpc_request(2, "broker-9"));
        assert_eq!(response_error_code(&response), None);
        assert!(response
            .header("x-aggregate-risk-gate")
            .unwrap()
            .starts_with("allowed;scope=agent:broker-9;contribution=800;total=800/3000"));
    }

    #[test]
    fn an_exhausted_fixed_weight_budget_still_forwards_initialize_ping_and_cancellation() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        for i in 0..3 {
            assert_eq!(
                response_error_code(&tester.request(rpc_request(i, "broker-7"))),
                None
            );
        }
        assert_eq!(
            response_error_code(&tester.request(rpc_request(3, "broker-7"))),
            Some(MCP_BLOCKED_CODE),
            "the budget is exhausted"
        );
        for body in [
            json!({"jsonrpc": "2.0", "id": 10, "method": "initialize", "params": {}}),
            json!({"jsonrpc": "2.0", "id": 11, "method": "ping"}),
            json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}}),
        ] {
            let response = tester.request(mcp(body.clone()));
            assert_eq!(response.status_code(), 200, "{body}");
            assert_eq!(response_error_code(&response), None, "{body}");
            assert_eq!(
                response.header("x-aggregate-risk-gate"),
                Some(PASS),
                "{body}"
            );
        }
        assert_eq!(
            response_error_code(&tester.request(rpc_request(4, "broker-7"))),
            Some(MCP_BLOCKED_CODE),
            "tools/call is still denied"
        );
    }

    #[test]
    fn an_all_ungoverned_batch_passes_and_is_charged_nothing() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "spend-amount"})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            elicitation_response(),
        ]);
        let response = tester.request(mcp(batch));
        assert_eq!(response_error_code(&response), None);
        assert_eq!(response.header("x-aggregate-risk-gate"), Some(PASS));
        // The whole budget is still there.
        let full = tester.request(rpc_request_with_amount(2, "broker-7", 3000));
        assert_eq!(response_error_code(&full), None);
        assert!(full
            .header("x-aggregate-risk-gate")
            .unwrap()
            .contains("contribution=3000;total=3000/3000"));
    }

    #[test]
    fn a_mixed_batch_is_charged_only_its_governed_items() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            elicitation_response(),
        ]);
        let response = tester.request(mcp(batch));
        assert_eq!(response_error_code(&response), None);
        assert!(
            response
                .header("x-aggregate-risk-gate")
                .unwrap()
                .contains("contribution=1600;total=1600/3000"),
            "two governed items at 800 each, nothing for the other three"
        );
    }

    #[test]
    fn a_mixed_batch_with_an_unpriceable_governed_item_is_denied_with_an_error_per_request_id() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"contribution": "spend-amount"})))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let batch = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"amount": 100}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            elicitation_response(),
        ]);
        let response = tester.request(mcp(batch));
        assert!(backend.next().is_none(), "the whole batch is refused");
        assert_eq!(response.status_code(), 200);
        assert_eq!(
            response.header("x-aggregate-risk-gate"),
            Some("denied;scope=agent:broker-7;reason=unpriceable")
        );
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        let errors = body.as_array().expect("batch denial echoes a JSON array");
        // Every request id, governed or not; never the server's response id.
        let ids: Vec<&Value> = errors.iter().map(|error| &error["id"]).collect();
        assert_eq!(ids, [&json!(1), &json!(2), &json!(3)]);
        for error in errors {
            assert_eq!(error["error"]["code"], MCP_BLOCKED_CODE);
        }
    }

    #[test]
    fn a_duplicate_method_member_fails_closed() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        // Read first-wins this is a ping, last-wins a tools/call. A fresh,
        // unspent budget: the denial is for the ambiguity alone.
        let ambiguous =
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{}}"#;
        let response = tester.request(raw_request(ambiguous, Some("broker-7")));
        assert!(backend.next().is_none());
        assert_eq!(response.status_code(), 403, "no id is echoed");
        assert_eq!(
            response.header("x-aggregate-risk-gate"),
            Some("denied;scope=agent:broker-7;reason=unpriceable")
        );
        // The same body in a batch fails closed the same way.
        let batch = format!(r#"[{{"jsonrpc":"2.0","id":2,"method":"tools/list"}},{ambiguous}]"#);
        let response = tester.request(raw_request(&batch, Some("broker-7")));
        assert!(backend.next().is_none());
        assert_eq!(response.status_code(), 403);
    }

    #[test]
    fn method_matching_is_exact_and_case_sensitive() {
        let gate = gate_with(json!({"governedMethods": ["tools/call", "resources/read"]}));
        let outcome = |body: Value| {
            let bytes = body.to_string().into_bytes();
            match compute_contribution(&gate, RawBody::Present(&bytes)) {
                ContributionOutcome::Known(amount) => Some(amount),
                ContributionOutcome::Ungoverned => None,
                _ => panic!("unexpected outcome for {}", body),
            }
        };
        let call = |method: &str| json!({"jsonrpc": "2.0", "id": 1, "method": method});
        assert_eq!(outcome(call("tools/call")), Some(800));
        assert_eq!(outcome(call("resources/read")), Some(800));
        for other in ["Tools/Call", "tools/call ", "tools/", "resources/list", "*"] {
            assert_eq!(outcome(call(other)), None, "{other:?}");
        }
    }

    #[test]
    fn an_item_that_cannot_be_classified_stays_governed() {
        let gate = gate_with(json!({}));
        for body in [
            json!({"not": "rpc"}),
            json!({"id": 1, "method": "initialize"}),
            json!({"jsonrpc": "1.0", "id": 1, "method": "initialize"}),
            json!({"jsonrpc": "2.0", "id": 1, "method": 7}),
            json!({"jsonrpc": "2.0", "id": 1}),
            json!({"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}}),
            json!({"jsonrpc": "2.0", "result": {}}),
            json!([]),
            json!("tools/call"),
            // A governed method sent as a notification is still governed.
            json!({"jsonrpc": "2.0", "method": "tools/call", "params": {}}),
        ] {
            let bytes = body.to_string().into_bytes();
            assert!(
                matches!(
                    compute_contribution(&gate, RawBody::Present(&bytes)),
                    ContributionOutcome::Known(800)
                ),
                "{}",
                body
            );
        }
        // A body this parser rejects may still parse upstream, possibly as a
        // batch, so it is never priced as one call: it fails closed.
        let mut lone_surrogate =
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":""#.to_vec();
        lone_surrogate.extend_from_slice(br#"\ud800"}}"#);
        let mut bom = b"\xEF\xBB\xBF".to_vec();
        bom.extend_from_slice(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#);
        for bytes in [b"not json".to_vec(), lone_surrogate, bom] {
            assert!(
                matches!(
                    compute_contribution(&gate, RawBody::Present(&bytes)),
                    ContributionOutcome::Unpriceable
                ),
                "{}",
                String::from_utf8_lossy(&bytes)
            );
        }
        assert!(matches!(
            compute_contribution(&gate, RawBody::Uninspectable),
            ContributionOutcome::Unpriceable
        ));
    }

    /// A batch whose item nests past serde's 128-level limit fails to parse
    /// here, but a parser without that limit could run every item. It must
    /// fail closed, not be charged as a single call.
    #[test]
    fn a_batch_nested_past_the_parser_limit_fails_closed() {
        let deep = format!("{}0{}", "[".repeat(200), "]".repeat(200));
        let item = |id: u64| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"x":{}}}}}"#,
                id, deep
            )
        };
        let body = format!("[{},{},{}]", item(1), item(2), item(3));
        assert!(serde_json::from_str::<Value>(&body).is_err());

        let gate = gate_with(json!({}));
        assert!(matches!(
            compute_contribution(&gate, RawBody::Present(body.as_bytes())),
            ContributionOutcome::Unpriceable
        ));

        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({})))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let response = tester.request(raw_request(&body, Some("broker-7")));
        assert!(backend.next().is_none(), "must never reach upstream");
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(header.contains("reason=unpriceable"), "{}", header);
    }

    fn charset_request(content_type: &str, body: &str) -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_header("content-type", content_type)
            .with_header("content-length", body.len().to_string())
            .with_header("x-agent-id", "broker-7")
            .with_body(body.as_bytes().to_vec())
    }

    /// Under UTF-7, `tools+AC8-call` decodes to `tools/call`. Read as UTF-8 it
    /// is an unlisted method, so a body in any charset but UTF-8 must not be
    /// classified at all: it is uninspectable and fails closed.
    const UTF7_TOOLS_CALL: &str =
        r#"{"jsonrpc":"2.0","id":9,"method":"tools+AC8-call","params":{"name":"place_order"}}"#;

    #[test]
    fn a_non_utf8_charset_is_uninspectable_and_denied_in_block_mode() {
        for content_type in [
            "application/json; charset=utf-7",
            "application/json;charset=UTF-7",
            "application/json; charset=\"utf-7\"",
            "application/json; charset=utf-16",
            "application/json; charset=iso-8859-1",
            "application/json; charset=",
            "application/json; charset",
            "application/json; charset=utf-8; charset=utf-7",
            "application/vnd.api+json; charset=utf-7",
        ] {
            let backend = Rc::new(TraceBackend::new(ok_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(config(json!({})))
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let response = tester.request(charset_request(content_type, UTF7_TOOLS_CALL));
            assert!(
                backend.next().is_none(),
                "{} must never reach upstream",
                content_type
            );
            assert_eq!(response.status_code(), 403, "{}", content_type);
            let header = response.header("x-aggregate-risk-gate").unwrap();
            assert!(
                header.contains("reason=unpriceable"),
                "{}: {}",
                content_type,
                header
            );
            assert_ne!(header, PASS, "{}", content_type);
        }
    }

    #[test]
    fn a_non_utf8_charset_is_flagged_unpriceable_in_monitor_mode() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"mode": "monitor"})))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let response = tester.request(charset_request(
            "application/json; charset=utf-7",
            UTF7_TOOLS_CALL,
        ));
        assert!(backend.next().is_some(), "monitor mode forwards");
        let header = response.header("x-aggregate-risk-gate").unwrap();
        assert!(
            header.starts_with("monitor;") && header.contains("reason=unpriceable"),
            "{}",
            header
        );
    }

    #[test]
    fn a_utf8_or_absent_charset_is_still_inspected() {
        let tools_call = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#;
        let tools_list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        for content_type in [
            "application/json",
            "application/json; charset=utf-8",
            "application/json; charset=UTF-8",
            "application/json;charset = \"Utf-8\" ",
            "application/json; profile=x; charset=utf-8",
            "application/vnd.api+json; charset=utf-8",
        ] {
            let backend = Rc::new(TraceBackend::new(ok_backend));
            let mut tester = UnitTestBuilder::default()
                .with_config(config(json!({})))
                .with_backend(Rc::clone(&backend))
                .with_entrypoint(super::configure);
            let admitted = tester.request(charset_request(content_type, tools_call));
            assert!(backend.next().is_some(), "{}", content_type);
            let header = admitted.header("x-aggregate-risk-gate").unwrap();
            assert!(
                header.starts_with("allowed;") && header.contains("contribution=800"),
                "{}: {}",
                content_type,
                header
            );
            let passed = tester.request(charset_request(content_type, tools_list));
            assert!(backend.next().is_some(), "{}", content_type);
            assert_eq!(
                passed.header("x-aggregate-risk-gate"),
                Some(PASS),
                "{}",
                content_type
            );
        }
    }

    #[test]
    fn governed_methods_rejects_empty_blank_padded_duplicate_and_wildcard_lists() {
        for bad in [
            vec![],
            vec![""],
            vec!["   "],
            vec![" tools/call"],
            vec!["tools/call", "tools/call"],
            vec!["*"],
            vec!["tools/call", "*"],
        ] {
            let mut cfg = valid_config_struct();
            cfg.governed_methods = bad.iter().map(|m| m.to_string()).collect();
            assert!(
                Gate::from_config(&cfg).is_err(),
                "governedMethods {:?}",
                bad
            );
        }
        for good in [vec!["tools/call"], vec!["tools/call", "resources/read"]] {
            let mut cfg = valid_config_struct();
            cfg.governed_methods = good.iter().map(|m| m.to_string()).collect();
            assert!(
                Gate::from_config(&cfg).is_ok(),
                "governedMethods {:?}",
                good
            );
        }
    }

    // -----------------------------------------------------------------------
    // Settlement is by HTTP status only (P4A review #49, finding B).
    // -----------------------------------------------------------------------

    fn status_backend(
        status: u32,
        body: &'static str,
    ) -> impl Fn(UnitHttpRequest) -> UnitHttpResponse {
        move |_req| {
            UnitHttpResponse::new(status)
                .with_header("content-type", "application/json")
                .with_header("content-length", body.len().to_string())
                .with_body(body.as_bytes().to_vec())
        }
    }

    #[test]
    fn settlement_commits_2xx_and_3xx_and_releases_4xx_and_5xx() {
        for (status, settlement) in [
            (200, "committed"),
            (202, "committed"),
            (302, "committed"),
            (404, "released"),
            (500, "released"),
            (504, "released"),
        ] {
            let mut tester = UnitTestBuilder::default()
                .with_config(config(json!({})))
                .with_backend(status_backend(status, ""))
                .with_entrypoint(super::configure);
            let first = tester.request(rpc_request(1, "broker-7"));
            assert!(
                first
                    .header("x-aggregate-risk-gate")
                    .unwrap()
                    .ends_with(&format!(";settlement={settlement}")),
                "{status}: {:?}",
                first.header("x-aggregate-risk-gate")
            );
            // The next call's running total shows whether 800 was charged.
            let charged = if settlement == "committed" { 1600 } else { 800 };
            let second = tester.request(rpc_request(2, "broker-7"));
            assert!(
                second
                    .header("x-aggregate-risk-gate")
                    .unwrap()
                    .contains(&format!("total={charged}/3000")),
                "{status}: {:?}",
                second.header("x-aggregate-risk-gate")
            );
        }
    }

    #[test]
    fn a_jsonrpc_error_or_is_error_result_inside_an_http_200_is_charged() {
        for body in [
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"tool failed"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":true}}"#,
        ] {
            let mut tester = UnitTestBuilder::default()
                .with_config(config(json!({})))
                .with_backend(status_backend(200, body))
                .with_entrypoint(super::configure);
            let first = tester.request(rpc_request(1, "broker-7"));
            assert!(
                first
                    .header("x-aggregate-risk-gate")
                    .unwrap()
                    .ends_with(";settlement=committed"),
                "{}",
                body
            );
            let second = tester.request(rpc_request(2, "broker-7"));
            assert!(
                second
                    .header("x-aggregate-risk-gate")
                    .unwrap()
                    .contains("total=1600/3000"),
                "the failed tool call was charged: {}",
                body
            );
        }
    }

    // -----------------------------------------------------------------------
    // Ledger backends (P4A review #48).
    // -----------------------------------------------------------------------

    /// A node-backend gate whose fake shared store the test can steer.
    fn node_gate(overrides: Value) -> (Gate, node_ledger::fake::FakeStore) {
        let store = node_ledger::fake::FakeStore::default();
        let cfg: Config = serde_json::from_str(&config(overrides)).unwrap();
        let handle = store.clone();
        let gate = Gate::from_config_with(&cfg, move |_| Box::new(handle)).unwrap();
        (gate, store)
    }

    fn tools_call() -> Vec<u8> {
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}})
            .to_string()
            .into_bytes()
    }

    fn scope_of(agent: &str) -> Identity {
        Identity::Scope(format!("agent:{agent}"))
    }

    #[test]
    fn a_contended_node_ledger_fails_closed_in_block_mode() {
        let (gate, store) = node_gate(json!({}));
        store.force_mismatches(u32::MAX);
        let body = tools_call();
        let flow = decide(
            scope_of("b7"),
            0,
            &gate,
            RawBody::Present(&body),
            &violations(),
        );
        assert!(matches!(flow, Flow::Break(_)));
        store.force_mismatches(0);
        assert_eq!(gate.ledger.snapshot("agent:b7").total(), 0);
        assert_eq!(gate.ledger.stats().contended, 1);
        assert_eq!(
            DenyReason::LedgerContention.stamp("agent:b7", "points"),
            "denied;scope=agent:b7;reason=ledger-contention"
        );
    }

    #[test]
    fn an_unavailable_node_ledger_fails_closed_in_block_mode() {
        let (gate, store) = node_gate(json!({}));
        store.set_failing(true);
        let body = tools_call();
        let flow = decide(
            scope_of("b7"),
            0,
            &gate,
            RawBody::Present(&body),
            &violations(),
        );
        assert!(matches!(flow, Flow::Break(_)));
        store.set_failing(false);
        assert_eq!(gate.ledger.snapshot("agent:b7").total(), 0);
    }

    #[test]
    fn a_contended_or_unavailable_node_ledger_is_forwarded_and_flagged_in_monitor_mode() {
        let (gate, store) = node_gate(json!({"mode": "monitor"}));
        let body = tools_call();
        store.force_mismatches(u32::MAX);
        let flow = decide(
            scope_of("b7"),
            0,
            &gate,
            RawBody::Present(&body),
            &violations(),
        );
        assert!(
            matches!(flow, Flow::Continue(Ticket::None(ref stamp))
                if stamp == "monitor;scope=agent:b7;reason=ledger-contention"),
            "{:?}",
            flow
        );
        store.force_mismatches(0);
        store.set_failing(true);
        let flow = decide(
            scope_of("b7"),
            0,
            &gate,
            RawBody::Present(&body),
            &violations(),
        );
        assert!(
            matches!(flow, Flow::Continue(Ticket::None(ref stamp))
                if stamp == "monitor;scope=agent:b7;reason=ledger-unavailable"),
            "{:?}",
            flow
        );
    }

    #[test]
    fn a_saturated_scope_fails_closed_in_block_mode_and_is_flagged_in_monitor_mode() {
        // P4A review M1: a scope record holds at most MAX_HELD in-flight
        // reservations; past that a call is refused, never grown into.
        for mode in ["block", "monitor"] {
            let (gate, _store) = node_gate(json!({
                "mode": mode, "fixedWeight": 1, "aggregateBudget": 1_000_000
            }));
            let body = tools_call();
            for _ in 0..crate::ledger::MAX_HELD {
                let flow = decide(
                    scope_of("b7"),
                    0,
                    &gate,
                    RawBody::Present(&body),
                    &violations(),
                );
                assert!(
                    matches!(flow, Flow::Continue(Ticket::Reserved(..))),
                    "{}",
                    mode
                );
            }
            let flow = decide(
                scope_of("b7"),
                0,
                &gate,
                RawBody::Present(&body),
                &violations(),
            );
            if mode == "block" {
                assert!(matches!(flow, Flow::Break(_)));
            } else {
                assert!(
                    matches!(flow, Flow::Continue(Ticket::None(ref stamp))
                        if stamp == "monitor;scope=agent:b7;reason=scope-saturated"),
                    "{:?}",
                    flow
                );
            }
            assert_eq!(
                gate.ledger.snapshot("agent:b7").reserved,
                crate::ledger::MAX_HELD as u64
            );
        }
        assert_eq!(
            DenyReason::ScopeSaturated.stamp("agent:b7", "points"),
            "denied;scope=agent:b7;reason=scope-saturated"
        );
    }

    #[test]
    fn two_node_gates_on_one_store_share_one_budget() {
        let (a, store) = node_gate(json!({}));
        let cfg: Config = serde_json::from_str(&config(json!({}))).unwrap();
        let handle = store.clone();
        let b = Gate::from_config_with(&cfg, move |_| Box::new(handle)).unwrap();
        let body = tools_call();
        let admitted = (0..10)
            .filter(|i| {
                let gate = if i % 2 == 0 { &a } else { &b };
                matches!(
                    decide(
                        scope_of("b7"),
                        0,
                        gate,
                        RawBody::Present(&body),
                        &violations()
                    ),
                    Flow::Continue(Ticket::Reserved(..))
                )
            })
            .count();
        assert_eq!(admitted, 3, "budget 3000 at weight 800 across both workers");
    }

    #[test]
    fn the_worker_backend_keeps_one_ledger_per_gate() {
        let a = gate_with(json!({"ledgerBackend": "worker"}));
        let b = gate_with(json!({"ledgerBackend": "worker"}));
        let body = tools_call();
        let admitted = (0..10)
            .filter(|i| {
                let gate = if i % 2 == 0 { &a } else { &b };
                matches!(
                    decide(
                        scope_of("b7"),
                        0,
                        gate,
                        RawBody::Present(&body),
                        &violations()
                    ),
                    Flow::Continue(Ticket::Reserved(..))
                )
            })
            .count();
        assert_eq!(admitted, 6, "each worker admits the full budget");
    }

    #[test]
    fn the_worker_backend_runs_through_the_filter() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config(json!({"ledgerBackend": "worker"})))
            .with_backend(Rc::new(TraceBackend::new(ok_backend)))
            .with_entrypoint(super::configure);
        let errors: Vec<Option<i64>> = (0..4)
            .map(|i| response_error_code(&tester.request(rpc_request(i, "broker-7"))))
            .collect();
        assert_eq!(errors, vec![None, None, None, Some(-32008)]);
    }

    #[test]
    fn a_cluster_ledger_is_rejected_as_not_implemented() {
        let mut cfg = valid_config_struct();
        cfg.ledger_backend = "cluster".to_string();
        let err = Gate::from_config(&cfg).err().unwrap().to_string();
        assert!(err.contains("not implemented"), "{}", err);
        cfg.ledger_backend = "redis".to_string();
        assert!(Gate::from_config(&cfg).is_err());
    }

    #[test]
    fn the_ledger_namespace_is_validated() {
        for ok in ["", "team-a", "fabric.v1_2", &"n".repeat(64)] {
            let mut cfg = valid_config_struct();
            cfg.ledger_namespace = ok.to_string();
            assert!(Gate::from_config(&cfg).is_ok(), "{:?}", ok);
        }
        for bad in ["a b", "a:b", "a/b", &"n".repeat(65), "é"] {
            let mut cfg = valid_config_struct();
            cfg.ledger_namespace = bad.to_string();
            assert!(Gate::from_config(&cfg).is_err(), "{:?}", bad);
        }
        let mut cfg = valid_config_struct();
        cfg.ledger_backend = "worker".to_string();
        cfg.ledger_namespace = "team-a".to_string();
        assert!(Gate::from_config(&cfg).is_err(), "namespace needs node");
    }

    #[test]
    fn the_node_ledger_store_is_opened_in_the_configured_namespace() {
        let mut cfg = valid_config_struct();
        let seen = std::cell::RefCell::new(Vec::new());
        for namespace in ["", "team-a"] {
            cfg.ledger_namespace = namespace.to_string();
            Gate::from_config_with(&cfg, |ns| {
                seen.borrow_mut().push(ns.map(str::to_string));
                Box::new(node_ledger::fake::FakeStore::default())
            })
            .unwrap();
        }
        assert_eq!(*seen.borrow(), vec![None, Some("team-a".to_string())]);
    }
}
