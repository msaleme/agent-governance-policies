// Copyright 2026 Salesforce, Inc. All rights reserved.
// Modifications Copyright (c) 2026 msaleme. Licensed under the MIT License.
//
// Approval-to-Execution Binding — closes the gap between "an action was approved"
// and "the action that executed is the one that was approved."
//
// Scope: this policy governs **MCP `tools/call`** JSON-RPC requests only. Every
// other JSON-RPC method is out of scope and is forwarded untouched (stamped
// `out-of-scope` on the result header) — this filter never attempts to bind an
// approval to a non-`tools/call` method.
//
// An MCP approval and its execution are almost always separated by time and by
// hops: a supervising broker approves; a downstream broker executes several calls
// later. Nothing at the gateway normally proves the two are the same tool call.
// This policy checks the approval record accompanying a governed `tools/call`
// against five independent predicates, each named in the Approval Binding Vectors
// (ABV) v0.1 conformance corpus
// (https://github.com/msaleme/approval-binding-vectors, MIT):
//
//   P1  Action        the approval's scope commits to the executed tool name.
//   P2  Arguments      the approval's scope commits to the executed argument bytes
//                       (a full canonical-byte match; referenced/`$ref` arguments
//                       are not supported and fail closed — see below).
//   P4  Freshness      the approval is still valid at the instant of execution
//                       (this gateway's own wall clock, never a caller-supplied one).
//   P5  Separate       a versioned, domain-separated approval attestation exists,
//       attester       its attester is not the executing party, its key is
//                       recognized, and it authenticates the reconstructed
//                       `mcp-v1` payload (see `check_separate_attester`).
//   P6  Single use     (opt-in profile choice) the approval's nonce has not been
//                       consumed by a prior execution (atomic, via DataStorage).
//
// Referenced-argument (`$ref`) handling: a prior build resolved `$ref` argument
// values against a caller-supplied `dereferenced` map (former "P3"). That gave the
// executing party influence over what its own arguments were compared against, so
// it is removed: any `$ref`-shaped object anywhere in the executed arguments now
// fails closed under P2 ("referenced arguments are not supported").
//
// Honesty boundary: this corpus (and this policy) test whether the RECORD proves
// the executed action is the approved one. Neither proves that approving the
// action was wise, and a sound record checked by the party it constrains still
// proves nothing — P5's separate attester is what keeps this from being a
// document an actor wrote about itself. P5's HMAC establishes separation of
// duties and authentication, NOT non-repudiation (a shared symmetric key cannot);
// an asymmetric JWS/JWKS attestation is the recommended upgrade (not built here).
// See README.md for the full boundary.
//
// Unlike the sibling MCP Honeytoken Tripwire, this filter registers ONLY an
// `on_request` handler (no `.on_response(...)`). That matters: PDK's `DualFilter`
// re-runs a configured response handler even over a request filter's own
// `Flow::Break` early reply, and a response handler that requires a declared
// `content-length` (as Tripwire's does) will treat that self-generated reply as
// an uninspectable body and withhold it — which is why, empirically, Tripwire's
// in-band JSON-RPC denial bodies come back empty under `pdk_unit`. Registering no
// response handler here means this policy's own `Response::new(...).with_body(...)`
// early replies are sent as constructed, with nothing downstream re-inspecting them.
//
// Every predicate-failure verdict — a block-mode denial AND a monitor-mode
// would-deny detection — registers a PDK policy violation via
// `PolicyViolations::generate_policy_violation()` (mirroring the sibling Decoy
// Tool Sentinel), so Anypoint Monitoring/SIEM records the hit even when monitor
// mode still forwards the request. See README.md's "PDK policy violation
// registration" note for exactly which paths do (and do not) register one.
mod generated;

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use pdk::authentication::{Authentication, AuthenticationHandler};
use pdk::data_storage::{DataStorage, DataStorageBuilder, DataStorageError, StoreMode};
use pdk::hl::*;
use pdk::logger;
use pdk::policy_violation::PolicyViolations;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::{BTreeMap, HashSet};

use crate::generated::config::Config;

/// JSON-RPC server-error code used when a policy prevents a request from
/// reaching its upstream tool. Matches the Sentinel/Tripwire/Coordinator family.
const MCP_BLOCKED_CODE: i64 = -32008;

/// Bound on the request body this policy will parse. This is an admission
/// filter, not an observed cap on bytes Flex buffers before exposing the body.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Minimum accepted attester-key length (bytes). A shorter shared secret is
/// rejected at configure time rather than silently accepted — publishability
/// finding #1. 32 bytes = the HMAC-SHA256 block-equivalent floor for a
/// meaningful key.
const MIN_ATTESTER_KEY_BYTES: usize = 32;

/// Version tag for the domain-separated P5 attestation payload. Bumping this is
/// how a future payload shape stays distinguishable from `mcp-v1` under the same
/// key (a MAC over one version can never be replayed as another).
const PAYLOAD_VERSION: &str = "mcp-v1";

/// DataStorage store name for the atomic single-use (P6) nonce reservations.
const NONCE_STORE_NAME: &str = "approval-nonces";

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Predicate {
    P1,
    P2,
    P4,
    P5,
    P6,
}

impl Predicate {
    const ALL: [Predicate; 5] = [
        Predicate::P1,
        Predicate::P2,
        Predicate::P4,
        Predicate::P5,
        Predicate::P6,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Predicate::P1 => "P1",
            Predicate::P2 => "P2",
            Predicate::P4 => "P4",
            Predicate::P5 => "P5",
            Predicate::P6 => "P6",
        }
    }

    fn parse(value: &str) -> Option<Predicate> {
        Predicate::ALL.iter().copied().find(|p| p.as_str() == value)
    }

    fn index(self) -> usize {
        match self {
            Predicate::P1 => 0,
            Predicate::P2 => 1,
            Predicate::P4 => 2,
            Predicate::P5 => 3,
            Predicate::P6 => 4,
        }
    }
}

/// A fixed-order, fixed-size membership set over the six predicates. Iteration
/// order is always P1..P6, which keeps "the first required predicate" and log
/// output deterministic (a `HashSet<Predicate>` would not guarantee that).
#[derive(Clone, Debug, Default)]
struct PredicateSet([bool; 5]);

impl PredicateSet {
    fn insert(&mut self, predicate: Predicate) {
        self.0[predicate.index()] = true;
    }

    fn contains(&self, predicate: Predicate) -> bool {
        self.0[predicate.index()]
    }

    /// The lowest-numbered required predicate, used to attribute a denial that
    /// precedes predicate-specific evaluation (e.g. no approval record at all).
    fn first(&self) -> Option<Predicate> {
        Predicate::ALL.iter().copied().find(|p| self.contains(*p))
    }
}

// ---------------------------------------------------------------------------
// Canonical form (JCS-equivalent) and digests
// ---------------------------------------------------------------------------

/// Versioned canonical form: a fail-closed subset of RFC 8785 JCS covering the
/// JSON shapes this policy actually needs to hash and MAC — objects, arrays,
/// strings, booleans, null, and INTEGERS only. Object members are sorted by key
/// and emitted with compact separators, matching the ABV reference checker's
/// `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
///
/// RFC 8785 also specifies an exact ECMA-262 number-to-string form for
/// non-integer JSON numbers, which this function deliberately does NOT implement.
/// Rather than emit a form that might disagree with another canonicalizer (and so
/// silently break byte-equality — the whole guarantee P2/P5 rest on), any
/// non-integer number FAILS CLOSED with an error. Callers propagate that error
/// into a malformed/denied verdict.
fn canonical_json(value: &Value) -> Result<String, String> {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut members: Vec<String> = Vec::with_capacity(keys.len());
            for key in keys {
                members.push(format!(
                    "{}:{}",
                    serde_json::to_string(key).map_err(|_| "unencodable object key".to_string())?,
                    canonical_json(&map[key])?
                ));
            }
            Ok(format!("{{{}}}", members.join(",")))
        }
        Value::Array(items) => {
            let mut members: Vec<String> = Vec::with_capacity(items.len());
            for item in items {
                members.push(canonical_json(item)?);
            }
            Ok(format!("[{}]", members.join(",")))
        }
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                Ok(n.to_string())
            } else {
                Err("non-integer JSON number is not canonicalizable (fail closed)".to_string())
            }
        }
        Value::String(_) | Value::Bool(_) | Value::Null => {
            serde_json::to_string(value).map_err(|_| "unencodable scalar".to_string())
        }
    }
}

fn digest_value(value: &Value) -> Result<String, String> {
    use sha2::Digest;
    let bytes = canonical_json(value)?.into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(value.get(i..i + 2)?, 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// P2: argument-byte match (referenced/$ref arguments are not supported)
// ---------------------------------------------------------------------------

/// True if `value` contains, at any depth, a JSON object carrying a `$ref`
/// member (with or without sibling members). A bare `$ref` STRING VALUE
/// (e.g. `{"kind": "$ref"}`) is not a reference object and is allowed — only an
/// object whose own key set includes `"$ref"` is treated as a reference.
///
/// Reference-shaped arguments are rejected because resolving them would require
/// the executing party to supply what its own arguments are compared against,
/// handing the constrained party influence over its own check (former "P3").
fn contains_ref_object(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.contains_key("$ref") || map.values().any(contains_ref_object),
        Value::Array(items) => items.iter().any(contains_ref_object),
        _ => false,
    }
}

/// P1 (action) and, when required, P2 (a full canonical argument-byte match).
/// No dereferencing: any `$ref`-shaped object anywhere in the executed arguments
/// fails closed. A non-canonicalizable argument value (e.g. a float) also fails
/// closed via `digest_value`.
fn check_action_and_arguments(
    scope: &ApprovalScope,
    executed_action: &str,
    executed_arguments: &Value,
    required: &PredicateSet,
) -> Result<(), (Predicate, String)> {
    if required.contains(Predicate::P1) && executed_action != scope.action {
        return Err((
            Predicate::P1,
            format!(
                "approved action '{}', executed '{}'",
                scope.action, executed_action
            ),
        ));
    }

    if !required.contains(Predicate::P2) {
        return Ok(());
    }

    if contains_ref_object(executed_arguments) {
        return Err((
            Predicate::P2,
            "referenced arguments are not supported".to_string(),
        ));
    }

    let digest = digest_value(executed_arguments).map_err(|reason| {
        (
            Predicate::P2,
            format!("arguments not canonicalizable: {reason}"),
        )
    })?;
    if digest == scope.arguments_digest {
        Ok(())
    } else {
        Err((
            Predicate::P2,
            "executed arguments are not the approved arguments".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// P4: freshness
// ---------------------------------------------------------------------------

/// Real wall-clock freshness: valid while `now <= not_after + clockSkewSeconds`,
/// where `now` is this gateway's own clock — never a caller-supplied instant,
/// since a caller-supplied execution time would let the executing party grade
/// its own freshness check.
fn check_freshness(approval: &ApprovalRecord, clock_skew_seconds: i64) -> Result<(), String> {
    let not_after_raw = approval
        .not_after
        .as_deref()
        .ok_or_else(|| "approval has no not_after; cannot establish freshness".to_string())?;
    let not_after = chrono::DateTime::parse_from_rfc3339(not_after_raw)
        .map_err(|err| format!("malformed not_after '{not_after_raw}': {err}"))?
        .with_timezone(&chrono::Utc);
    let now = chrono::Utc::now();
    let deadline = not_after + chrono::Duration::seconds(clock_skew_seconds.max(0));
    if now > deadline {
        Err(format!(
            "executed at {now} after approval expired {not_after} (+{clock_skew_seconds}s skew)"
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// P5: separate attester
// ---------------------------------------------------------------------------

/// The versioned, domain-separated payload that a P5 attestation authenticates.
/// Reconstructed identically at verify time from the approval record, this
/// gateway's configured deployment identity (`aud`/`tenant`/`env`), the attester
/// kid (`iss`), and the VERIFIED executor subject (`sub`). Binding all of these
/// under one MAC means an attestation minted for one audience/tenant/env/executor
/// cannot be replayed against another.
#[allow(clippy::too_many_arguments)]
fn mcp_v1_payload(
    iss: &str,
    aud: &str,
    tenant: &str,
    env: &str,
    sub: &str,
    action: &str,
    arguments_digest: &str,
    not_after: &str,
    nonce: &str,
) -> Value {
    json!({
        "v": PAYLOAD_VERSION,
        "iss": iss,
        "aud": aud,
        "tenant": tenant,
        "env": env,
        "sub": sub,
        "action": action,
        "arguments_digest": arguments_digest,
        "not_after": not_after,
        "nonce": nonce,
    })
}

/// An approval attestation must exist, its attester must not be the party about
/// to execute, its key must be one this gateway recognizes, and it must
/// authenticate (HMAC-SHA256) the reconstructed `mcp-v1` payload — binding the
/// approval scope to THIS gateway's audience/tenant/environment and to the
/// verified executor subject. Requires `not_after` and `nonce` to be present
/// (they are part of the signed payload).
///
/// This establishes separateness and authentication only. It does not, and
/// cannot, establish that the attester was ENTITLED to approve this action —
/// that is a policy question this record cannot answer on its own. The shared
/// symmetric HMAC gives separation of duties, NOT non-repudiation.
fn check_separate_attester(
    approval: &ApprovalRecord,
    attestations: &[Attestation],
    executor: &str,
    attester_keys: &BTreeMap<String, Vec<u8>>,
    expected_audience: &str,
    expected_tenant: &str,
    expected_environment: &str,
) -> Result<(), String> {
    if executor.is_empty() {
        return Err("executor identity missing; cannot establish separateness".to_string());
    }
    let not_after = approval
        .not_after
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "approval has no not_after; cannot authenticate mcp-v1 payload".to_string()
        })?;
    let nonce = approval
        .nonce
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "approval has no nonce; cannot authenticate mcp-v1 payload".to_string())?;

    let approval_attestations: Vec<&Attestation> = attestations
        .iter()
        .filter(|attestation| attestation.claim.as_deref() == Some("approval"))
        .collect();
    if approval_attestations.is_empty() {
        return Err("no approval attestation".to_string());
    }

    for attestation in approval_attestations {
        if attestation.authority == executor {
            return Err(format!(
                "approval attested by the executing party ({})",
                attestation.authority
            ));
        }
        let key = attester_keys
            .get(&attestation.authority)
            .ok_or_else(|| format!("unknown attesting authority {}", attestation.authority))?;
        let payload = mcp_v1_payload(
            &attestation.authority,
            expected_audience,
            expected_tenant,
            expected_environment,
            executor,
            &approval.scope.action,
            &approval.scope.arguments_digest,
            not_after,
            nonce,
        );
        let payload_bytes = canonical_json(&payload)
            .map_err(|reason| format!("mcp-v1 payload not canonicalizable: {reason}"))?
            .into_bytes();
        let mac_bytes = hex_decode(&attestation.mac)
            .ok_or_else(|| "attestation mac is not valid hex".to_string())?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .map_err(|_| "invalid attester key length".to_string())?;
        mac.update(&payload_bytes);
        mac.verify_slice(&mac_bytes).map_err(|_| {
            "approval attestation does not authenticate the mcp-v1 payload".to_string()
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Envelope shape and strict JSON parsing
// ---------------------------------------------------------------------------

#[derive(Deserialize, Clone, Debug)]
struct ApprovalScope {
    action: String,
    arguments_digest: String,
}

#[derive(Deserialize, Clone, Debug)]
struct ApprovalRecord {
    scope: ApprovalScope,
    #[serde(default)]
    not_after: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
struct Attestation {
    #[serde(default)]
    claim: Option<String>,
    authority: String,
    mac: String,
}

#[derive(Deserialize, Clone, Debug, Default)]
struct RawEnvelope {
    #[serde(default)]
    approval: Option<ApprovalRecord>,
    #[serde(default)]
    attestations: Vec<Attestation>,
}

struct Envelope {
    approval: ApprovalRecord,
    attestations: Vec<Attestation>,
}

/// Deserialize JSON while rejecting a duplicate member in any object, at any
/// depth, before a map-backed `Value` is built. The same defense the sibling
/// Tripwire policy uses: without this, two consumers of the same bytes (this
/// policy and whatever actually executes upstream) could disagree about which
/// duplicate member is "the" value — turning a parser difference into a bypass
/// of exactly the byte-equality guarantee P2/P3 exist to provide.
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
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON object member"));
            }
            map.next_value::<NoDuplicateMembers>()?;
        }
        Ok(NoDuplicateMembers)
    }
}

fn parse_strict_json(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice::<NoDuplicateMembers>(bytes)
        .map_err(|_| "duplicate JSON object member".to_string())?;
    serde_json::from_slice(bytes).map_err(|err| format!("invalid JSON: {err}"))
}

fn declared_body_length(value: Option<String>) -> Option<usize> {
    value
        .filter(|length| !length.is_empty() && length.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|length| length.parse::<usize>().ok())
}

// ---------------------------------------------------------------------------
// JSON-RPC single-call parsing
// ---------------------------------------------------------------------------

/// A single (non-batch) MCP `tools/call` JSON-RPC 2.0 request, with the executed
/// tool name and arguments already extracted from `params`.
struct JsonRpcCall {
    /// The whole parsed request body, so `approvalSource=rpc-param` can pull a
    /// sibling top-level member out of it.
    root: Value,
    /// `None` means the request has no `"id"` member at all — a JSON-RPC
    /// notification, which forbids any response.
    id: Option<Value>,
    action: String,
    arguments: Value,
}

/// The outcome of parsing one JSON-RPC request against this policy's scope.
enum ParsedRequest {
    /// A well-formed `tools/call` — the only method this policy binds.
    ToolsCall(JsonRpcCall),
    /// A well-formed JSON-RPC request whose method is not `tools/call`. It is out
    /// of scope for approval binding and is forwarded untouched.
    OutOfScope { method: String },
}

/// Parses a single JSON-RPC 2.0 request. Only `method == "tools/call"` produces a
/// bindable `ToolsCall`; every other method is `OutOfScope` and forwarded. A
/// structurally malformed body (bad JSON, batch, missing `jsonrpc`/`method`,
/// invalid `id` type, or a malformed `tools/call` params shape) still returns
/// `Err` so the caller fails closed.
fn parse_single_jsonrpc(body: &[u8]) -> Result<ParsedRequest, String> {
    let root = parse_strict_json(body)?;
    let members = root.as_object().ok_or_else(|| {
        "request body is not a single JSON-RPC object (batches are out of scope for approval binding)"
            .to_string()
    })?;
    if members.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err("missing or invalid \"jsonrpc\":\"2.0\" member".to_string());
    }
    if let Some(id_value) = members.get("id") {
        if !matches!(id_value, Value::String(_) | Value::Number(_) | Value::Null) {
            return Err("\"id\" member has an invalid JSON-RPC type".to_string());
        }
    }
    let method = members
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing \"method\" member".to_string())?
        .to_string();

    if method != "tools/call" {
        return Ok(ParsedRequest::OutOfScope { method });
    }

    let params = members
        .get("params")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "tools/call is missing params.name".to_string())?
        .to_string();
    // `arguments` must be an object or absent; absent means the empty object.
    // An explicit null, array, or scalar `arguments` is malformed and fails closed.
    let arguments = match params.get("arguments") {
        None => Value::Object(Default::default()),
        Some(Value::Object(map)) => Value::Object(map.clone()),
        Some(_) => {
            return Err("tools/call params.arguments must be an object or absent".to_string())
        }
    };

    let id = members.get("id").cloned();
    Ok(ParsedRequest::ToolsCall(JsonRpcCall {
        root,
        id,
        action: name,
        arguments,
    }))
}

// ---------------------------------------------------------------------------
// Config surface
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ApprovalSource {
    Header,
    RpcParam,
}

struct Binding {
    approval_source: ApprovalSource,
    approval_header: String,
    approval_rpc_field: String,
    executor_header: String,
    required: PredicateSet,
    attester_keys: BTreeMap<String, Vec<u8>>,
    expected_audience: String,
    expected_tenant: String,
    expected_environment: String,
    clock_skew_seconds: i64,
    block: bool,
    deny_with_rpc_error: bool,
    result_header: String,
}

impl Binding {
    fn from_config(config: &Config) -> Result<Self> {
        let approval_source = match config.approval_source.as_str() {
            "header" => ApprovalSource::Header,
            "rpc-param" => ApprovalSource::RpcParam,
            "sidecar" => {
                return Err(anyhow!(
                "approvalSource=sidecar is not implemented in this build; use header or rpc-param"
            ))
            }
            other => return Err(anyhow!("unknown approvalSource '{other}'")),
        };

        if config.required_predicates.is_empty() {
            return Err(anyhow!(
                "requiredPredicates must not be empty: a binding that checks nothing is not a binding"
            ));
        }
        let mut required = PredicateSet::default();
        for raw in &config.required_predicates {
            let predicate = Predicate::parse(raw)
                .ok_or_else(|| anyhow!("unknown predicate '{raw}' in requiredPredicates"))?;
            required.insert(predicate);
        }

        let mut attester_keys = BTreeMap::new();
        for entry in &config.attester_keys {
            if entry.kid.trim().is_empty() {
                return Err(anyhow!("attesterKeys entries must have a non-blank kid"));
            }
            if entry.key.len() < MIN_ATTESTER_KEY_BYTES {
                return Err(anyhow!(
                    "attesterKeys entry '{}' has a key shorter than the {}-byte minimum",
                    entry.kid,
                    MIN_ATTESTER_KEY_BYTES
                ));
            }
            if attester_keys
                .insert(entry.kid.clone(), entry.key.as_bytes().to_vec())
                .is_some()
            {
                return Err(anyhow!(
                    "attesterKeys must have unique kid values ('{}' repeated)",
                    entry.kid
                ));
            }
        }

        // When P5 is required, the mcp-v1 payload binds this gateway's deployment
        // identity — an empty audience/tenant/environment would make that binding
        // vacuous, so reject it at configure time (fail closed).
        if required.contains(Predicate::P5) {
            for (label, value) in [
                ("expectedAudience", config.expected_audience.trim()),
                ("expectedTenant", config.expected_tenant.trim()),
                ("expectedEnvironment", config.expected_environment.trim()),
            ] {
                if value.is_empty() {
                    return Err(anyhow!(
                        "{label} must be non-empty when P5 is in requiredPredicates"
                    ));
                }
            }
        }

        let mode = config.mode.to_ascii_lowercase();
        let block = match mode.as_str() {
            "block" => true,
            "monitor" => false,
            other => return Err(anyhow!("unknown mode '{other}'")),
        };
        let on_deny = config.on_deny.to_ascii_lowercase();
        let deny_with_rpc_error = match on_deny.as_str() {
            "rpc-error" => true,
            "empty-403" => false,
            other => return Err(anyhow!("unknown onDeny '{other}'")),
        };

        Ok(Self {
            approval_source,
            approval_header: config.approval_header.clone(),
            approval_rpc_field: config.approval_rpc_field.clone(),
            executor_header: config.executor_header.clone(),
            required,
            attester_keys,
            expected_audience: config.expected_audience.clone(),
            expected_tenant: config.expected_tenant.clone(),
            expected_environment: config.expected_environment.clone(),
            clock_skew_seconds: config.clock_skew_seconds,
            block,
            deny_with_rpc_error,
            result_header: config.result_header.clone(),
        })
    }
}

fn extract_envelope(
    binding: &Binding,
    header_value: Option<String>,
    call: &JsonRpcCall,
) -> Result<Envelope, String> {
    let raw = match binding.approval_source {
        ApprovalSource::Header => {
            let value = header_value.ok_or_else(|| "missing approval header".to_string())?;
            parse_strict_json(value.as_bytes())?
        }
        ApprovalSource::RpcParam => call
            .root
            .as_object()
            .and_then(|members| members.get(&binding.approval_rpc_field))
            .cloned()
            .ok_or_else(|| "missing approval rpc-param field".to_string())?,
    };
    let raw_envelope: RawEnvelope =
        serde_json::from_value(raw).map_err(|err| format!("malformed approval envelope: {err}"))?;
    let approval = raw_envelope
        .approval
        .ok_or_else(|| "approval envelope missing 'approval' record".to_string())?;
    Ok(Envelope {
        approval,
        attestations: raw_envelope.attestations,
    })
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

enum Verdict {
    Allow,
    Deny {
        predicate: Option<Predicate>,
        reason: String,
    },
}

/// Evaluates every predicate the operator required, in the fixed order
/// P5, P6, P1/P2, P4 — separate attester first (an unattested approval makes
/// every later comparison a comparison against something nobody stands behind),
/// then single-use presence, then action/arguments, then freshness.
///
/// P6 here is PRESENCE-only: it confirms the approval carries a non-empty nonce.
/// The atomic single-use RESERVATION happens in `request_filter` against
/// DataStorage, and only once the request is actually being forwarded — a denied
/// attempt must never burn a legitimate future execution's single use.
///
/// `executor_verified` reports whether `executor` came from verified
/// authentication data (see #6). When P5 is required, an unverified executor
/// fails closed under P5: the signed `sub` must equal a subject this gateway
/// actually authenticated, never a caller-asserted header.
fn evaluate(
    binding: &Binding,
    call: &JsonRpcCall,
    envelope: Result<Envelope, String>,
    executor: &str,
    executor_verified: bool,
) -> Verdict {
    let envelope = match envelope {
        Ok(envelope) => envelope,
        Err(reason) => {
            let predicate = if binding.required.contains(Predicate::P5) {
                Some(Predicate::P5)
            } else {
                binding.required.first()
            };
            return Verdict::Deny { predicate, reason };
        }
    };

    if binding.required.contains(Predicate::P5) {
        if !executor_verified {
            return Verdict::Deny {
                predicate: Some(Predicate::P5),
                reason: "executor identity is not from verified authentication; \
                         cannot bind the signed subject (P5 fails closed)"
                    .to_string(),
            };
        }
        if let Err(reason) = check_separate_attester(
            &envelope.approval,
            &envelope.attestations,
            executor,
            &binding.attester_keys,
            &binding.expected_audience,
            &binding.expected_tenant,
            &binding.expected_environment,
        ) {
            return Verdict::Deny {
                predicate: Some(Predicate::P5),
                reason,
            };
        }
    }

    if binding.required.contains(Predicate::P6) {
        match envelope.approval.nonce.as_deref() {
            Some(nonce) if !nonce.is_empty() => {}
            _ => {
                return Verdict::Deny {
                    predicate: Some(Predicate::P6),
                    reason: "approval has no nonce; cannot enforce single use".to_string(),
                };
            }
        }
    }

    if binding.required.contains(Predicate::P1) || binding.required.contains(Predicate::P2) {
        if let Err((predicate, reason)) = check_action_and_arguments(
            &envelope.approval.scope,
            &call.action,
            &call.arguments,
            &binding.required,
        ) {
            return Verdict::Deny {
                predicate: Some(predicate),
                reason,
            };
        }
    }

    if binding.required.contains(Predicate::P4) {
        if let Err(reason) = check_freshness(&envelope.approval, binding.clock_skew_seconds) {
            return Verdict::Deny {
                predicate: Some(Predicate::P4),
                reason,
            };
        }
    }

    Verdict::Allow
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

fn log_verdict(action: &str, predicate: Option<Predicate>, reason: &str) {
    logger::warn!(
        "{}",
        json!({
            "event": "approval_execution_binding",
            "action": action,
            "predicate": predicate.map(Predicate::as_str),
            "reason": reason,
        })
    );
}

/// The response for a denial where no request could be identified at all
/// (malformed body, batch, missing id where one was expected to exist, or the
/// approval-parsing/predicate check ran but there is no id to echo). Always an
/// empty body: echoing an id we cannot trust risks exposing a protected value,
/// mirroring the decoy-coordinator's containment rule.
fn empty_denial(result_header: &str, tag: &str) -> Response {
    Response::new(403).with_headers([(result_header.to_string(), tag.to_string())])
}

fn rpc_error_denial(result_header: &str, tag: &str, id: Value, predicate_label: &str) -> Response {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": MCP_BLOCKED_CODE,
            "message": format!("approval-to-execution binding denied ({predicate_label})"),
        }
    })
    .to_string();
    Response::new(200)
        .with_headers([
            ("Content-Type".to_string(), "application/json".to_string()),
            (result_header.to_string(), tag.to_string()),
        ])
        .with_body(body)
}

fn notification_denial(result_header: &str, tag: &str) -> Response {
    Response::new(202).with_headers([(result_header.to_string(), tag.to_string())])
}

/// Renders the correct block-mode denial for a `label`, given the request's
/// `id`: a notification (`None`) → 202; an in-band rpc-error (when configured and
/// an id exists) → 200 JSON-RPC error; otherwise → empty 403. Centralizes the
/// id-echo containment rule so every block-mode denial path (predicate failure
/// AND the P6 replay reservation) renders it identically.
fn render_denial(binding: &Binding, id: Option<Value>, label: &str) -> Response {
    let tag = format!("denied;predicate={label}");
    match id {
        None => notification_denial(&binding.result_header, &tag),
        Some(id) if binding.deny_with_rpc_error => {
            rpc_error_denial(&binding.result_header, &tag, id, label)
        }
        Some(_) => empty_denial(&binding.result_header, &tag),
    }
}

// ---------------------------------------------------------------------------
// Request filter
// ---------------------------------------------------------------------------

async fn request_filter<S: DataStorage>(
    request_state: RequestState,
    auth: Authentication,
    binding: &Binding,
    violations: &PolicyViolations,
    store: &S,
) -> Flow<()> {
    let headers_state = request_state.into_headers_state().await;
    let handler = headers_state.handler();

    // Executor identity: prefer VERIFIED authentication data (client_id, then
    // principal) established by an upstream authentication policy. Only when no
    // verified subject is present do we fall back to the caller-asserted header,
    // flagged unverified — a P5-required binding fails closed on that (see
    // `evaluate`). This is finding #6: never let the constrained party name
    // itself for the signed `sub`.
    let (executor, executor_verified) = match auth
        .authentication()
        .and_then(|data| data.client_id.or(data.principal))
        .filter(|subject| !subject.is_empty())
    {
        Some(subject) => (subject, true),
        None => (
            handler.header(&binding.executor_header).unwrap_or_default(),
            false,
        ),
    };
    let header_value = handler.header(&binding.approval_header);

    if !headers_state.contains_body() {
        let tag = "denied;predicate=malformed".to_string();
        log_verdict(
            "deny",
            None,
            "no request body: nothing to bind an approval to",
        );
        return if binding.block {
            Flow::Break(empty_denial(&binding.result_header, &tag))
        } else {
            handler.set_header(&binding.result_header, "monitor;predicate=malformed");
            Flow::Continue(())
        };
    }

    // Header-phase exclusion for bodies this policy cannot safely buffer and
    // parse as JSON at all: a non-JSON content-type (SSE/streaming media types
    // included) or any content-encoding (a compressed body, whose decoded size
    // is not what the declared content-length bounds). Checked before the body
    // is ever buffered, mirroring the sibling Decoy Tool Sentinel's admission
    // gate — see README "Inspection boundary" for the documented exclusions.
    let content_type_is_json = handler.header("content-type").is_some_and(|value| {
        let media = value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        media == "application/json"
            || (media.starts_with("application/") && media.ends_with("+json"))
    });
    let is_encoded = handler.header("content-encoding").is_some();
    if !content_type_is_json || is_encoded {
        let reason =
            "request body cannot be safely inspected (non-JSON content-type, SSE/streaming, or content-encoding present)";
        log_verdict("deny", None, reason);
        return if binding.block {
            Flow::Break(empty_denial(
                &binding.result_header,
                "denied;predicate=malformed",
            ))
        } else {
            handler.set_header(&binding.result_header, "monitor;predicate=malformed");
            Flow::Continue(())
        };
    }

    let declared_length = declared_body_length(handler.header("content-length"));
    let admissible = declared_length.is_some_and(|length| length <= MAX_BODY_BYTES);
    if !admissible {
        let reason = "request body has no valid, admissible declared content-length";
        log_verdict("deny", None, reason);
        return if binding.block {
            Flow::Break(empty_denial(
                &binding.result_header,
                "denied;predicate=malformed",
            ))
        } else {
            handler.set_header(&binding.result_header, "monitor;predicate=malformed");
            Flow::Continue(())
        };
    }
    let declared_length = declared_length.expect("admissible implies present");

    let state = headers_state.into_headers_body_state().await;
    let handler = state.handler();
    let body = handler.body();
    if body.len() != declared_length {
        log_verdict(
            "deny",
            None,
            "request body length does not match its declared content-length",
        );
        return if binding.block {
            Flow::Break(empty_denial(
                &binding.result_header,
                "denied;predicate=malformed",
            ))
        } else {
            handler.set_header(&binding.result_header, "monitor;predicate=malformed");
            Flow::Continue(())
        };
    }

    let call = match parse_single_jsonrpc(&body) {
        Ok(ParsedRequest::ToolsCall(call)) => call,
        Ok(ParsedRequest::OutOfScope { method }) => {
            // Not a tools/call — out of scope for approval binding. Forward
            // untouched in BOTH modes, stamped so downstream can see the policy
            // ran and deliberately did not bind this method.
            logger::info!(
                "{}",
                json!({
                    "event": "approval_execution_binding",
                    "action": "out-of-scope",
                    "method": method,
                })
            );
            handler.set_header(&binding.result_header, "out-of-scope");
            return Flow::Continue(());
        }
        Err(reason) => {
            log_verdict("deny", None, &reason);
            return if binding.block {
                Flow::Break(empty_denial(
                    &binding.result_header,
                    "denied;predicate=malformed",
                ))
            } else {
                handler.set_header(&binding.result_header, "monitor;predicate=malformed");
                Flow::Continue(())
            };
        }
    };

    let envelope = extract_envelope(binding, header_value, &call);
    // Capture the signed nonce (if any) BEFORE the envelope is moved into
    // `evaluate`; it is the DataStorage reservation key on the allowed path.
    let reserved_nonce = envelope
        .as_ref()
        .ok()
        .and_then(|env| env.approval.nonce.clone())
        .filter(|nonce| !nonce.is_empty());
    let verdict = evaluate(binding, &call, envelope, &executor, executor_verified);

    match verdict {
        Verdict::Allow => {
            // Atomic single-use (P6): reserve the nonce key in DataStorage with
            // Absent semantics, but ONLY in block mode and ONLY once the request
            // is actually being forwarded. Monitor mode never consumes a nonce.
            if binding.block && binding.required.contains(Predicate::P6) {
                if let Some(nonce) = reserved_nonce {
                    match store.store(&nonce, &StoreMode::Absent, &1u8).await {
                        Ok(()) => {}
                        Err(DataStorageError::CasMismatch) => {
                            log_verdict(
                                "deny",
                                Some(Predicate::P6),
                                "approval nonce already reserved (single-use replay)",
                            );
                            violations.generate_policy_violation();
                            return Flow::Break(render_denial(binding, call.id.clone(), "P6"));
                        }
                        Err(_) => {
                            // Storage unavailable or any other error → fail closed:
                            // we cannot prove single use, so we do not forward.
                            log_verdict(
                                "deny",
                                Some(Predicate::P6),
                                "single-use nonce store unavailable; failing closed",
                            );
                            violations.generate_policy_violation();
                            return Flow::Break(render_denial(binding, call.id.clone(), "P6"));
                        }
                    }
                }
            }
            log_verdict("allow", None, "all required predicates hold");
            handler.set_header(&binding.result_header, "allowed");
            Flow::Continue(())
        }
        Verdict::Deny { predicate, reason } => {
            let label = predicate.map(Predicate::as_str).unwrap_or("malformed");
            log_verdict("deny", predicate, &reason);
            // Register a PDK policy violation for every predicate-failure
            // decision — a block-mode denial AND a monitor-mode would-deny
            // detection — so Anypoint Monitoring/SIEM records the hit even
            // when the request is still forwarded. Mirrors the sibling Decoy
            // Tool Sentinel's `violations.generate_policy_violation()` call,
            // made before either return path below.
            violations.generate_policy_violation();
            if !binding.block {
                handler.set_header(
                    &binding.result_header,
                    &format!("would-deny;predicate={label}"),
                );
                return Flow::Continue(());
            }
            Flow::Break(render_denial(binding, call.id, label))
        }
    }
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    violations: PolicyViolations,
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

    let binding = Binding::from_config(&config)?;
    logger::info!(
        "Approval-to-Execution Binding armed: predicates={:?}, mode={}",
        Predicate::ALL
            .iter()
            .copied()
            .filter(|p| binding.required.contains(*p))
            .map(Predicate::as_str)
            .collect::<Vec<_>>(),
        if binding.block { "block" } else { "monitor" }
    );

    let store = store_builder.local(NONCE_STORE_NAME);
    let filter = on_request(|rs, auth: Authentication| {
        request_filter(rs, auth, &binding, &violations, &store)
    });
    launcher.launch(filter).await?;
    Ok(())
}

#[cfg(test)]
mod test;
