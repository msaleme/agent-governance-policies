// Copyright 2026 Salesforce, Inc. All rights reserved.
// Modifications Copyright (c) 2026 msaleme. Licensed under the MIT License.
//
// Approval-to-Execution Binding — closes the gap between "an action was approved"
// and "the action that executed is the one that was approved."
//
// An Agent Fabric approval and its execution are almost always separated by time
// and by hops: a supervising broker approves; a downstream broker executes several
// calls later. Nothing at the gateway normally proves the two are the same action.
// This policy checks the approval record accompanying a governed MCP/A2A JSON-RPC
// execution against six independent predicates (P1..P6), each named in the
// Approval Binding Vectors (ABV) v0.1 conformance corpus
// (https://github.com/msaleme/approval-binding-vectors, MIT):
//
//   P1  Action        the approval's scope commits to the executed action/tool.
//   P2  Arguments      the approval's scope commits to the executed argument bytes.
//   P3  Dereference    a reference-named argument's DEREFERENCED bytes match what
//                       the approval committed (P3 takes precedence over P2
//                       whenever a reference is involved).
//   P4  Freshness      the approval is still valid at the instant of execution
//                       (this gateway's own wall clock, never a caller-supplied one).
//   P5  Separate       an approval attestation exists, its attester is not the
//       attester       executing party, its key is recognized, and it verifies
//                       over the approval scope.
//   P6  Single use     (opt-in profile choice) the approval's nonce has not been
//                       consumed by a prior execution.
//
// Honesty boundary: this corpus (and this policy) test whether the RECORD proves
// the executed action is the approved one. Neither proves that approving the
// action was wise, and a sound record checked by the party it constrains still
// proves nothing — P5's separate attester is what keeps this from being a
// document an actor wrote about itself. See README.md for the full boundary.
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
mod generated;

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use pdk::hl::*;
use pdk::logger;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::rc::Rc;

use crate::generated::config::Config;

/// JSON-RPC server-error code used when a policy prevents a request from
/// reaching its upstream tool. Matches the Sentinel/Tripwire/Coordinator family.
const MCP_BLOCKED_CODE: i64 = -32008;

/// Bound on the request body this policy will parse. This is an admission
/// filter, not an observed cap on bytes Flex buffers before exposing the body.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Bound on the in-process P6 nonce set, so a long-lived worker cannot grow this
/// unboundedly. Oldest nonces are evicted first (FIFO), which trades a very old
/// nonce's reuse-detection for bounded memory — a documented limitation, not a
/// silent one (see README "Honesty boundaries").
const NONCE_STORE_CAP: usize = 100_000;

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Predicate {
    P1,
    P2,
    P3,
    P4,
    P5,
    P6,
}

impl Predicate {
    const ALL: [Predicate; 6] = [
        Predicate::P1,
        Predicate::P2,
        Predicate::P3,
        Predicate::P4,
        Predicate::P5,
        Predicate::P6,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Predicate::P1 => "P1",
            Predicate::P2 => "P2",
            Predicate::P3 => "P3",
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
            Predicate::P3 => 2,
            Predicate::P4 => 3,
            Predicate::P5 => 4,
            Predicate::P6 => 5,
        }
    }
}

/// A fixed-order, fixed-size membership set over the six predicates. Iteration
/// order is always P1..P6, which keeps "the first required predicate" and log
/// output deterministic (a `HashSet<Predicate>` would not guarantee that).
#[derive(Clone, Debug, Default)]
struct PredicateSet([bool; 6]);

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

/// When a mismatch could be named as either P2 or P3, name it `natural` if the
/// operator required that predicate; otherwise fall back to the other one (which
/// this function is only called when at least one of the two is required for).
/// The fallback reason says so explicitly rather than silently relabeling.
fn attribute(natural: Predicate, required: &PredicateSet, reason: String) -> (Predicate, String) {
    if required.contains(natural) {
        (natural, reason)
    } else {
        let other = if natural == Predicate::P3 {
            Predicate::P2
        } else {
            Predicate::P3
        };
        (
            other,
            format!(
                "{reason} (surfaced as {} because {} is not in requiredPredicates)",
                other.as_str(),
                natural.as_str()
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// Canonical form (JCS-equivalent) and digests
// ---------------------------------------------------------------------------

/// Approximates RFC 8785 JCS for the JSON shapes this policy handles: objects,
/// arrays, strings, booleans, null, and integers. Object members are sorted by
/// key and emitted with compact separators, matching the ABV reference checker's
/// `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
///
/// Honest limitation: RFC 8785 also specifies an exact ECMA-262 number-to-string
/// form for non-integer JSON numbers, which this function does not implement —
/// every value in the ABV corpus and in this policy's own tests is a string,
/// bool, or integer, so that gap is real but untested here.
fn canonical_json_string(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let members: Vec<String> = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_default(),
                        canonical_json_string(&map[key])
                    )
                })
                .collect();
            format!("{{{}}}", members.join(","))
        }
        Value::Array(items) => {
            let members: Vec<String> = items.iter().map(canonical_json_string).collect();
            format!("[{}]", members.join(","))
        }
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => {
            serde_json::to_string(value).unwrap_or_default()
        }
    }
}

fn digest_value(value: &Value) -> String {
    use sha2::Digest;
    let bytes = canonical_json_string(value).into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex_encode(&hasher.finalize())
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
// P2 / P3: dereferencing executed arguments
// ---------------------------------------------------------------------------

/// Replaces every top-level `{"$ref": uri}` argument value with the SHA-256 hex
/// digest of the dereferenced bytes, per the `dereferenced` map the caller
/// supplied (this gateway has no blob store of its own — see README). Returns
/// an error naming the unresolvable URI if the map does not cover it.
fn resolve_arguments(
    args: &Value,
    dereferenced: &BTreeMap<String, String>,
) -> Result<Value, String> {
    let members = match args {
        Value::Object(map) => map.clone(),
        Value::Null => serde_json::Map::new(),
        _ => return Err("executed arguments must be a JSON object".to_string()),
    };
    let mut resolved = serde_json::Map::with_capacity(members.len());
    for (key, value) in members {
        if let Value::Object(inner) = &value {
            if let Some(Value::String(uri)) = inner.get("$ref") {
                match dereferenced.get(uri) {
                    Some(digest_hex) => {
                        resolved.insert(key, Value::String(digest_hex.clone()));
                        continue;
                    }
                    None => return Err(format!("unresolvable reference '{uri}'")),
                }
            }
        }
        resolved.insert(key, value);
    }
    Ok(Value::Object(resolved))
}

fn has_reference(args: &Value) -> bool {
    match args {
        Value::Object(map) => map
            .values()
            .any(|value| matches!(value, Value::Object(inner) if inner.contains_key("$ref"))),
        _ => false,
    }
}

/// P1 (action) and, when required, P2/P3 (arguments / dereferenced bytes).
/// Ports the precedence rule from the ABV reference checker: when the resolved
/// digest does not match, first check whether the approval committed the
/// UNRESOLVED form (a P3-shaped mistake — the commitment was over a reference,
/// never bound to bytes); otherwise, if the executed arguments carry any
/// reference at all, the mismatch is P3 (the referenced bytes changed); only a
/// mismatch with no reference involved is P2.
fn check_action_and_arguments(
    scope: &ApprovalScope,
    executed_action: &str,
    executed_arguments: &Value,
    dereferenced: &BTreeMap<String, String>,
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

    if !required.contains(Predicate::P2) && !required.contains(Predicate::P3) {
        return Ok(());
    }

    let resolved = match resolve_arguments(executed_arguments, dereferenced) {
        Ok(value) => value,
        Err(reason) => {
            return Err(attribute(
                Predicate::P3,
                required,
                format!("unresolvable reference: {reason}"),
            ));
        }
    };

    if digest_value(&resolved) == scope.arguments_digest {
        return Ok(());
    }

    if digest_value(executed_arguments) == scope.arguments_digest {
        return Err(attribute(
            Predicate::P3,
            required,
            "approval committed the reference, not the dereferenced bytes".to_string(),
        ));
    }

    let natural = if has_reference(executed_arguments) {
        Predicate::P3
    } else {
        Predicate::P2
    };
    let reason = if natural == Predicate::P3 {
        "referenced bytes at execution are not the approved bytes".to_string()
    } else {
        "executed arguments are not the approved arguments".to_string()
    };
    Err(attribute(natural, required, reason))
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

/// An approval attestation must exist, its attester must not be the party about
/// to execute, its key must be one this gateway recognizes, and it must verify
/// (HMAC-SHA256) over the approval's `scope` — never the full approval, and
/// never the executed arguments, matching the ABV reference checker exactly.
///
/// This establishes separateness and authentication only. It does not, and
/// cannot, establish that the attester was ENTITLED to approve this action —
/// that is a policy question this record cannot answer on its own.
fn check_separate_attester(
    scope: &ApprovalScope,
    attestations: &[Attestation],
    executor: &str,
    attester_keys: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    if executor.is_empty() {
        return Err("executor identity header missing; cannot establish separateness".to_string());
    }

    let approval_attestations: Vec<&Attestation> = attestations
        .iter()
        .filter(|attestation| attestation.claim.as_deref() == Some("approval"))
        .collect();
    if approval_attestations.is_empty() {
        return Err("no approval attestation".to_string());
    }

    let scope_bytes = canonical_json_string(&json!({
        "action": scope.action,
        "arguments_digest": scope.arguments_digest,
    }))
    .into_bytes();

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
        let mac_bytes = hex_decode(&attestation.mac)
            .ok_or_else(|| "attestation mac is not valid hex".to_string())?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .map_err(|_| "invalid attester key length".to_string())?;
        mac.update(&scope_bytes);
        mac.verify_slice(&mac_bytes)
            .map_err(|_| "approval attestation does not verify over the scope".to_string())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// P6: single use (real, in-process, bounded — see README honesty boundary)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct NonceStore {
    used: HashSet<String>,
    order: VecDeque<String>,
}

impl NonceStore {
    fn contains(&self, nonce: &str) -> bool {
        self.used.contains(nonce)
    }

    fn mark_used(&mut self, nonce: String) {
        if self.used.insert(nonce.clone()) {
            self.order.push_back(nonce);
            while self.order.len() > NONCE_STORE_CAP {
                if let Some(oldest) = self.order.pop_front() {
                    self.used.remove(&oldest);
                }
            }
        }
    }
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
    #[serde(default)]
    dereferenced: BTreeMap<String, String>,
}

struct Envelope {
    approval: ApprovalRecord,
    attestations: Vec<Attestation>,
    dereferenced: BTreeMap<String, String>,
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

/// A single (non-batch) JSON-RPC 2.0 request, with the executed action and
/// arguments already extracted (unwrapping `tools/call` if present).
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

fn parse_single_jsonrpc(body: &[u8]) -> Result<JsonRpcCall, String> {
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
    let params = members
        .get("params")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));

    let (action, arguments) = if method == "tools/call" {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "tools/call is missing params.name".to_string())?
            .to_string();
        let call_arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default()));
        (name, call_arguments)
    } else {
        (method, params)
    };

    let id = members.get("id").cloned();
    Ok(JsonRpcCall {
        root,
        id,
        action,
        arguments,
    })
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
    clock_skew_seconds: i64,
    block: bool,
    deny_with_rpc_error: bool,
    result_header: String,
    nonces: Rc<RefCell<NonceStore>>,
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
            clock_skew_seconds: config.clock_skew_seconds,
            block,
            deny_with_rpc_error,
            result_header: config.result_header.clone(),
            nonces: Rc::new(RefCell::new(NonceStore::default())),
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
        dereferenced: raw_envelope.dereferenced,
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
/// P5, P6, P1/P2/P3, P4 — separate attester first (an unattested approval makes
/// every later comparison a comparison against something nobody stands behind),
/// then single-use, then action/arguments, then freshness. Does not mark the
/// nonce used; the caller does that only once the request is actually allowed
/// through (or, in monitor mode, forwarded).
fn evaluate(
    binding: &Binding,
    call: &JsonRpcCall,
    envelope: Result<Envelope, String>,
    executor: &str,
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
        if let Err(reason) = check_separate_attester(
            &envelope.approval.scope,
            &envelope.attestations,
            executor,
            &binding.attester_keys,
        ) {
            return Verdict::Deny {
                predicate: Some(Predicate::P5),
                reason,
            };
        }
    }

    if binding.required.contains(Predicate::P6) {
        match envelope.approval.nonce.as_deref() {
            Some(nonce) if !nonce.is_empty() => {
                if binding.nonces.borrow().contains(nonce) {
                    return Verdict::Deny {
                        predicate: Some(Predicate::P6),
                        reason: format!("approval nonce '{nonce}' already used"),
                    };
                }
            }
            _ => {
                return Verdict::Deny {
                    predicate: Some(Predicate::P6),
                    reason: "approval has no nonce; cannot enforce single use".to_string(),
                };
            }
        }
    }

    if binding.required.contains(Predicate::P1)
        || binding.required.contains(Predicate::P2)
        || binding.required.contains(Predicate::P3)
    {
        if let Err((predicate, reason)) = check_action_and_arguments(
            &envelope.approval.scope,
            &call.action,
            &call.arguments,
            &envelope.dereferenced,
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

// ---------------------------------------------------------------------------
// Request filter
// ---------------------------------------------------------------------------

async fn request_filter(request_state: RequestState, binding: &Binding) -> Flow<()> {
    let headers_state = request_state.into_headers_state().await;
    let handler = headers_state.handler();
    let executor = handler.header(&binding.executor_header).unwrap_or_default();
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
            Flow::Continue(())
        };
    }

    let call = match parse_single_jsonrpc(&body) {
        Ok(call) => call,
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
    let verdict = evaluate(binding, &call, envelope, &executor);

    match verdict {
        Verdict::Allow => {
            if binding.required.contains(Predicate::P6) {
                // Only mark the nonce used once the call is actually going
                // through — a denied attempt must not burn a legitimate
                // future execution's single use.
                if let Ok(envelope) =
                    extract_envelope(binding, handler.header(&binding.approval_header), &call)
                {
                    if let Some(nonce) = envelope.approval.nonce {
                        binding.nonces.borrow_mut().mark_used(nonce);
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
            if !binding.block {
                handler.set_header(
                    &binding.result_header,
                    &format!("would-deny;predicate={label}"),
                );
                return Flow::Continue(());
            }
            let tag = format!("denied;predicate={label}");
            match call.id {
                None => Flow::Break(notification_denial(&binding.result_header, &tag)),
                Some(id) if binding.deny_with_rpc_error => {
                    Flow::Break(rpc_error_denial(&binding.result_header, &tag, id, label))
                }
                Some(_) => Flow::Break(empty_denial(&binding.result_header, &tag)),
            }
        }
    }
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

    let filter = on_request(|rs| request_filter(rs, &binding));
    launcher.launch(filter).await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use pdk_unit::{
        TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder,
    };
    use std::rc::Rc;

    // -----------------------------------------------------------------
    // Config helpers
    // -----------------------------------------------------------------

    fn attester(kid: &str, key: &str) -> Value {
        json!({"kid": kid, "key": key})
    }

    fn config_with(overrides: Value) -> String {
        let mut base = json!({
            "approvalSource": "header",
            "approvalHeader": "x-approval",
            "approvalRpcField": "approvalBinding",
            "executorHeader": "client_id",
            "requiredPredicates": ["P1", "P2", "P3", "P5", "P6"],
            "attesterKeys": [
                attester("approver.example", "abv/approver"),
                attester("executor.example", "abv/executor")
            ],
            "clockSkewSeconds": 60,
            "mode": "block",
            "onDeny": "rpc-error",
            "resultHeader": "x-approval-binding"
        });
        for (key, value) in overrides.as_object().expect("overrides must be an object") {
            base[key] = value.clone();
        }
        base.to_string()
    }

    fn block_config() -> String {
        config_with(json!({}))
    }

    fn monitor_config() -> String {
        config_with(json!({"mode": "monitor"}))
    }

    // -----------------------------------------------------------------
    // Envelope / request builders — mirror the ABV neutral record shape
    // -----------------------------------------------------------------

    fn approval_envelope(
        action: &str,
        arguments_digest: &str,
        not_after: &str,
        nonce: &str,
        attestations: Value,
        dereferenced: Value,
    ) -> Value {
        json!({
            "approval": {
                "scope": {"action": action, "arguments_digest": arguments_digest},
                "authority": "approver.example",
                "not_after": not_after,
                "nonce": nonce
            },
            "attestations": attestations,
            "dereferenced": dereferenced
        })
    }

    fn jsonrpc_call(id: i64, action: &str, arguments: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": action, "arguments": arguments}
        })
    }

    fn request_with(envelope: &Value, executor: &str, body: &Value) -> UnitHttpRequest {
        let body_text = body.to_string();
        UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_header("content-length", body_text.len().to_string())
            .with_header("x-approval", envelope.to_string())
            .with_header("client_id", executor)
            .with_body(body_text)
    }

    fn ok_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_header("content-type", "application/json")
            .with_body(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}")
    }

    fn far_future() -> String {
        (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    fn far_past() -> String {
        (chrono::Utc::now() - chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    // -----------------------------------------------------------------
    // Fixture-vector driven tests: CTRL-* must ALLOW, NEG-P{1,2,3,5,6}-*
    // must DENY for exactly the predicate they negate. P4 is excluded
    // from these vectors' requiredPredicates (see module doc below) —
    // ABV's vectors encode fixed calendar timestamps meant for a checker
    // that trusts a record-supplied "at"; this policy instead binds P4 to
    // real wall-clock time, so it is tested separately with dynamically
    // computed timestamps (see the P4 tests further down). Testing P4
    // against a byte-for-byte-replayed 2026-09-19 vector from "today"
    // would either always fail (correctly, but for the wrong reason) or
    // require trusting a caller-supplied clock — exactly what P4 exists
    // to refuse.
    const CTRL01_DIGEST: &str = "d0d1ec939e9bfcf5975980e0c16531326065562613a192baf9596f2398dc09b4";
    const CTRL01_MAC: &str = "6497cb9cdddd7ac205938d8d6ab105542563f004ac991dda344343fdbd983f41";
    const CTRL03_DIGEST: &str = "c59c75a359af15682154442e91943d4a1aeee497ec6aeb5c3a918835d2826821";
    const CTRL03_MAC: &str = "c404872bf533275f4a9b1babe1cd4564d746d8f7ac519164c275e3792730159c";

    fn vector_config() -> String {
        config_with(json!({"requiredPredicates": ["P1", "P2", "P3", "P5", "P6"]}))
    }

    // Real SHA-256 digest of the dereferenced bytes behind `blob://plan-v1`
    // (`{"target":"prod","replicas":3}`), independently recomputed and
    // cross-checked against `check.py`'s own reference `BLOBS` fixture.
    // Every CTRL/allow test below whose executed arguments carry
    // `{"$ref": "blob://plan-v1"}` must supply this in its `dereferenced`
    // map — the empty `{}` used in earlier drafts of these tests made P3
    // fail closed with "unresolvable reference," which an
    // `onDeny: rpc-error` denial then renders as HTTP 200 with a JSON-RPC
    // error body. Because that denial shares the same HTTP 200 status as a
    // genuine allow, a bare `assert_eq!(status_code(), 200)` cannot tell
    // the two apart — every allow assertion below therefore also checks
    // that the backend was actually reached and that the body is not a
    // JSON-RPC error envelope.
    const PLAN_V1_DIGEST: &str = "3037042beda915ee41ba5727f1899ec4e6941faae90194d6af8fdc3fb104d276";

    #[test]
    fn ctrl_01_fully_sound_record_is_allowed() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            CTRL01_DIGEST,
            "2026-09-19T12:00:00Z",
            "n-0001",
            json!([{"claim": "approval", "authority": "approver.example", "mac": CTRL01_MAC}]),
            json!({"blob://plan-v1": PLAN_V1_DIGEST}),
        );
        let body = jsonrpc_call(
            1,
            "deploy.apply",
            json!({"manifest": {"$ref": "blob://plan-v1"}, "confirm": true}),
        );
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        assert_eq!(response.status_code(), 200);
        // Both a genuine allow (ok_backend's response) and an in-band
        // `onDeny: rpc-error` denial are valid, HTTP-200 JSON bodies, so
        // parseability alone can't distinguish them. What can: the exact
        // bytes match ok_backend's own canned response (never this policy's
        // own -32008 error shape), AND the request is recorded as having
        // actually reached the upstream.
        assert_eq!(
            response.body(),
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
            "a sound record must return the upstream's own response body, not a policy-generated denial"
        );
        assert!(
            backend.next().is_some(),
            "a sound record must actually reach the upstream, not just return HTTP 200"
        );
    }

    #[test]
    fn ctrl_02_near_miss_member_reordering_is_still_allowed() {
        // Same content as CTRL-01, JSON object members emitted in a different
        // order. Canonicalization must make this indistinguishable.
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let envelope = json!({
            "approval": {
                "nonce": "n-0001",
                "not_after": "2026-09-19T12:00:00Z",
                "authority": "approver.example",
                "scope": {"arguments_digest": CTRL01_DIGEST, "action": "deploy.apply"}
            },
            "attestations": [{"authority": "approver.example", "claim": "approval", "mac": CTRL01_MAC}],
            "dereferenced": {"blob://plan-v1": PLAN_V1_DIGEST}
        });
        let body = json!({
            "id": 1,
            "jsonrpc": "2.0",
            "params": {"arguments": {"confirm": true, "manifest": {"$ref": "blob://plan-v1"}}, "name": "deploy.apply"},
            "method": "tools/call"
        });
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        assert_eq!(response.status_code(), 200);
        // Both a genuine allow (ok_backend's response) and an in-band
        // `onDeny: rpc-error` denial are valid, HTTP-200 JSON bodies, so
        // parseability alone can't distinguish them. What can: the exact
        // bytes match ok_backend's own canned response (never this policy's
        // own -32008 error shape), AND the request is recorded as having
        // actually reached the upstream.
        assert_eq!(
            response.body(),
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
            "a sound record must return the upstream's own response body, not a policy-generated denial"
        );
        assert!(
            backend.next().is_some(),
            "a sound record must actually reach the upstream, not just return HTTP 200"
        );
    }

    #[test]
    fn ctrl_03_sound_record_with_no_reference_is_allowed() {
        // Guards against a checker that only works when a $ref is present.
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "fs.write",
            CTRL03_DIGEST,
            "2026-09-19T12:00:00Z",
            "n-0002",
            json!([{"claim": "approval", "authority": "approver.example", "mac": CTRL03_MAC}]),
            json!({}),
        );
        let body = jsonrpc_call(
            1,
            "fs.write",
            json!({"path": "/etc/app.conf", "mode": "0644"}),
        );
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn neg_p1_wrong_action_is_denied_for_p1() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            CTRL01_DIGEST,
            "2026-09-19T12:00:00Z",
            "n-0001",
            json!([{"claim": "approval", "authority": "approver.example", "mac": CTRL01_MAC}]),
            json!({}),
        );
        let body = jsonrpc_call(
            7,
            "deploy.destroy",
            json!({"manifest": {"$ref": "blob://plan-v1"}, "confirm": true}),
        );
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        assert_eq!(response.status_code(), 200);
        let json: Value = serde_json::from_slice(response.body()).expect("valid json body");
        assert_eq!(json["error"]["code"], MCP_BLOCKED_CODE);
        assert!(json["error"]["message"].as_str().unwrap().contains("P1"));
        assert!(
            backend.next().is_none(),
            "denied execution must not reach upstream"
        );
    }

    #[test]
    fn neg_p2_changed_numeric_argument_is_denied_for_p2() {
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let digest = super::digest_value(&json!({"service": "checkout", "replicas": 3}));
        let mac = hmac_hex(
            "abv/approver",
            &json!({"action": "deploy.scale", "arguments_digest": digest}),
        );
        let envelope = approval_envelope(
            "deploy.scale",
            &digest,
            "2026-09-19T12:00:00Z",
            "n-0003",
            json!([{"claim": "approval", "authority": "approver.example", "mac": mac}]),
            json!({}),
        );
        let body = jsonrpc_call(
            3,
            "deploy.scale",
            json!({"service": "checkout", "replicas": 300}),
        );
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        let json: Value = serde_json::from_slice(response.body()).expect("valid json body");
        assert!(json["error"]["message"].as_str().unwrap().contains("P2"));
    }

    #[test]
    fn neg_p2_changed_string_argument_is_denied_for_p2() {
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "fs.write",
            CTRL03_DIGEST,
            "2026-09-19T12:00:00Z",
            "n-0004",
            json!([{"claim": "approval", "authority": "approver.example", "mac": CTRL03_MAC}]),
            json!({}),
        );
        let body = jsonrpc_call(
            4,
            "fs.write",
            json!({"path": "/etc/shadow", "mode": "0644"}),
        );
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        let json: Value = serde_json::from_slice(response.body()).expect("valid json body");
        assert!(json["error"]["message"].as_str().unwrap().contains("P2"));
    }

    #[test]
    fn neg_p3_dereferenced_bytes_changed_is_denied_for_p3() {
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            CTRL01_DIGEST,
            "2026-09-19T12:00:00Z",
            "n-0001",
            json!([{"claim": "approval", "authority": "approver.example", "mac": CTRL01_MAC}]),
            json!({"blob://plan-v2": "dc1b41cb6999def6f863076486282f7dfeb18fc84f6cd0d2c85f720981b95c0c"}),
        );
        let body = jsonrpc_call(
            1,
            "deploy.apply",
            json!({"manifest": {"$ref": "blob://plan-v2"}, "confirm": true}),
        );
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        let json: Value = serde_json::from_slice(response.body()).expect("valid json body");
        assert!(json["error"]["message"].as_str().unwrap().contains("P3"));
    }

    #[test]
    fn neg_p3_approval_committed_reference_not_bytes_is_denied_for_p3() {
        // The approval commits the reference as an unresolvable pointer (no
        // dereferenced-bytes entry at all): the referenced bytes were never
        // bound to anything this gateway can verify.
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            "75b7f88f01f41b94dd79d00488241812b1cf689c1fd2b058cf4e1fbc07c39e20",
            "2026-09-19T12:00:00Z",
            "n-0001",
            json!([{"claim": "approval", "authority": "approver.example", "mac": "31f446c4f11971948b7f1561865b174a7312ee2e4a695c9fa7bfb0e450b870df"}]),
            json!({}),
        );
        let body = jsonrpc_call(
            1,
            "deploy.apply",
            json!({"manifest": {"$ref": "blob://plan-v2"}, "confirm": true}),
        );
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        let json: Value = serde_json::from_slice(response.body()).expect("valid json body");
        assert!(json["error"]["message"].as_str().unwrap().contains("P3"));
    }

    #[test]
    fn neg_p5_executor_is_only_attester_is_denied_for_p5() {
        let mac = hmac_hex(
            "abv/executor",
            &json!({"action": "deploy.apply", "arguments_digest": CTRL01_DIGEST}),
        );
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            CTRL01_DIGEST,
            "2026-09-19T12:00:00Z",
            "n-0001",
            json!([{"claim": "approval", "authority": "executor.example", "mac": mac}]),
            json!({}),
        );
        let body = jsonrpc_call(
            1,
            "deploy.apply",
            json!({"manifest": {"$ref": "blob://plan-v1"}, "confirm": true}),
        );
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        let json: Value = serde_json::from_slice(response.body()).expect("valid json body");
        assert!(json["error"]["message"].as_str().unwrap().contains("P5"));
    }

    #[test]
    fn neg_p5_no_attestation_at_all_is_denied_for_p5() {
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            CTRL01_DIGEST,
            "2026-09-19T12:00:00Z",
            "n-0001",
            json!([]),
            json!({}),
        );
        let body = jsonrpc_call(
            1,
            "deploy.apply",
            json!({"manifest": {"$ref": "blob://plan-v1"}, "confirm": true}),
        );
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        let json: Value = serde_json::from_slice(response.body()).expect("valid json body");
        assert!(json["error"]["message"].as_str().unwrap().contains("P5"));
    }

    #[test]
    fn neg_p6_nonce_reused_across_two_executions_is_denied_for_p6() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            CTRL01_DIGEST,
            "2026-09-19T12:00:00Z",
            "n-0001",
            json!([{"claim": "approval", "authority": "approver.example", "mac": CTRL01_MAC}]),
            json!({"blob://plan-v1": PLAN_V1_DIGEST}),
        );
        let body = jsonrpc_call(
            1,
            "deploy.apply",
            json!({"manifest": {"$ref": "blob://plan-v1"}, "confirm": true}),
        );
        let first = tester.request(request_with(&envelope, "executor.example", &body));
        assert_eq!(
            first.status_code(),
            200,
            "first use of the nonce must be allowed"
        );
        // Parseability alone can't distinguish an allow from an in-band
        // denial (both are valid JSON at HTTP 200) — check the exact
        // upstream response bytes and that the upstream was actually hit.
        assert_eq!(
            first.body(),
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
            "first use must return the upstream's own response body, not a policy-generated denial"
        );
        assert!(
            backend.next().is_some(),
            "first use must actually reach the upstream, not just return HTTP 200"
        );

        let second_body = jsonrpc_call(
            2,
            "deploy.apply",
            json!({"manifest": {"$ref": "blob://plan-v1"}, "confirm": true}),
        );
        let second = tester.request(request_with(&envelope, "executor.example", &second_body));
        let json: Value = serde_json::from_slice(second.body()).expect("valid json body");
        assert!(json["error"]["message"].as_str().unwrap().contains("P6"));
        assert!(
            backend.next().is_none(),
            "a nonce-reuse denial must not reach the upstream a second time"
        );
    }

    /// Re-derives an HMAC-SHA256 the same way `check_separate_attester` does,
    /// so hand-authored (non-vendored) test cases don't need a pre-baked mac.
    fn hmac_hex(key: &str, scope: &Value) -> String {
        use hmac::Mac;
        let bytes = super::canonical_json_string(scope).into_bytes();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(&bytes);
        super::hex_encode(&mac.finalize().into_bytes())
    }

    // -----------------------------------------------------------------
    // P4 freshness — dynamically computed timestamps (see module doc above)
    // -----------------------------------------------------------------

    fn p4_config() -> String {
        config_with(json!({"requiredPredicates": ["P4"], "clockSkewSeconds": 60}))
    }

    #[test]
    fn p4_approval_fresh_within_window_is_allowed() {
        let mut tester = UnitTestBuilder::default()
            .with_config(p4_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            CTRL01_DIGEST,
            &far_future(),
            "n-fresh",
            json!([]),
            json!({}),
        );
        let body = jsonrpc_call(1, "deploy.apply", json!({}));
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn p4_approval_expired_is_denied_for_p4() {
        let mut tester = UnitTestBuilder::default()
            .with_config(p4_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            CTRL01_DIGEST,
            &far_past(),
            "n-expired",
            json!([]),
            json!({}),
        );
        let body = jsonrpc_call(1, "deploy.apply", json!({}));
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        let json: Value = serde_json::from_slice(response.body()).expect("valid json body");
        assert!(json["error"]["message"].as_str().unwrap().contains("P4"));
    }

    #[test]
    fn p4_approval_with_no_not_after_is_denied_for_p4() {
        let mut tester = UnitTestBuilder::default()
            .with_config(p4_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let envelope = json!({
            "approval": {"scope": {"action": "deploy.apply", "arguments_digest": CTRL01_DIGEST}, "nonce": "n-1"},
            "attestations": [],
            "dereferenced": {}
        });
        let body = jsonrpc_call(1, "deploy.apply", json!({}));
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        let json: Value = serde_json::from_slice(response.body()).expect("valid json body");
        assert!(json["error"]["message"].as_str().unwrap().contains("P4"));
    }

    // -----------------------------------------------------------------
    // Config validation (belt-and-suspenders; the GCL schema also enforces
    // these enums/non-empty constraints before a policy instance is armed)
    // -----------------------------------------------------------------

    fn parse_config(json: Value) -> Result<Config> {
        serde_json::from_value(json).map_err(|err| anyhow!("{err}"))
    }

    #[test]
    fn empty_required_predicates_is_rejected_at_configure_time() {
        let config = parse_config(json!({
            "approvalSource": "header", "approvalHeader": "x-approval", "approvalRpcField": "approvalBinding",
            "executorHeader": "client_id", "requiredPredicates": [], "attesterKeys": [],
            "clockSkewSeconds": 60, "mode": "block", "onDeny": "rpc-error", "resultHeader": "x-approval-binding"
        }))
        .unwrap();
        assert!(Binding::from_config(&config).is_err());
    }

    #[test]
    fn sidecar_approval_source_is_rejected_at_configure_time() {
        let config = parse_config(json!({
            "approvalSource": "sidecar", "approvalHeader": "x-approval", "approvalRpcField": "approvalBinding",
            "executorHeader": "client_id", "requiredPredicates": ["P1"], "attesterKeys": [],
            "clockSkewSeconds": 60, "mode": "block", "onDeny": "rpc-error", "resultHeader": "x-approval-binding"
        }))
        .unwrap();
        match Binding::from_config(&config) {
            Ok(_) => panic!("expected approvalSource=sidecar to be rejected at startup"),
            Err(err) => assert!(err.to_string().contains("not implemented")),
        }
    }

    #[test]
    fn duplicate_attester_kid_is_rejected_at_configure_time() {
        let config = parse_config(json!({
            "approvalSource": "header", "approvalHeader": "x-approval", "approvalRpcField": "approvalBinding",
            "executorHeader": "client_id", "requiredPredicates": ["P1"],
            "attesterKeys": [attester("a", "k1"), attester("a", "k2")],
            "clockSkewSeconds": 60, "mode": "block", "onDeny": "rpc-error", "resultHeader": "x-approval-binding"
        }))
        .unwrap();
        assert!(Binding::from_config(&config).is_err());
    }

    #[test]
    fn blank_attester_kid_is_rejected_at_configure_time() {
        let config = parse_config(json!({
            "approvalSource": "header", "approvalHeader": "x-approval", "approvalRpcField": "approvalBinding",
            "executorHeader": "client_id", "requiredPredicates": ["P1"],
            "attesterKeys": [attester("  ", "k1")],
            "clockSkewSeconds": 60, "mode": "block", "onDeny": "rpc-error", "resultHeader": "x-approval-binding"
        }))
        .unwrap();
        assert!(Binding::from_config(&config).is_err());
    }

    // -----------------------------------------------------------------
    // Structural / fail-closed edge cases
    // -----------------------------------------------------------------

    #[test]
    fn missing_approval_header_is_denied() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let body = jsonrpc_call(1, "deploy.apply", json!({}));
        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", body.to_string().len().to_string())
                .with_body(body.to_string()),
        );
        let json: Value = serde_json::from_slice(response.body()).expect("valid json body");
        assert!(json["error"]["message"].as_str().unwrap().contains("P5"));
    }

    #[test]
    fn malformed_approval_header_json_fails_closed() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let body = jsonrpc_call(1, "deploy.apply", json!({}));
        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", body.to_string().len().to_string())
                .with_header("x-approval", "{not json")
                .with_body(body.to_string()),
        );
        assert_eq!(response.status_code(), 200);
        let json: Value = serde_json::from_slice(response.body()).expect("valid json body");
        assert_eq!(json["error"]["code"], MCP_BLOCKED_CODE);
    }

    #[test]
    fn non_jsonrpc_body_fails_closed_with_empty_403_in_block_mode() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let body = "{\"hello\":\"world\"}";
        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", body.len().to_string())
                .with_body(body),
        );
        assert_eq!(response.status_code(), 403);
        assert!(response.body().is_empty());
        assert!(
            backend.next().is_none(),
            "malformed input must not reach upstream in block mode"
        );
    }

    #[test]
    fn non_jsonrpc_body_passes_through_in_monitor_mode() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(monitor_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let body = "{\"hello\":\"world\"}";
        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", body.len().to_string())
                .with_body(body),
        );
        assert_eq!(response.status_code(), 200);
        assert!(backend.next().is_some(), "monitor mode always forwards");
    }

    #[test]
    fn jsonrpc_batch_is_out_of_scope_and_fails_closed_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let batch =
            json!([{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}]).to_string();
        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", batch.len().to_string())
                .with_body(batch),
        );
        assert_eq!(response.status_code(), 403);
        assert!(response.body().is_empty());
    }

    #[test]
    fn notification_without_id_is_denied_with_202_and_no_body() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let body = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "deploy.apply", "arguments": {}}
        });
        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", body.to_string().len().to_string())
                .with_body(body.to_string()),
        );
        assert_eq!(response.status_code(), 202);
        assert!(response.body().is_empty());
    }

    #[test]
    fn forged_short_content_length_fails_closed_as_malformed() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let body = jsonrpc_call(1, "deploy.apply", json!({}));
        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", "1")
                .with_body(body.to_string()),
        );
        assert_eq!(response.status_code(), 403);
        assert!(response.body().is_empty());
    }

    #[test]
    fn oversized_declared_length_fails_closed_before_reading_body() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let body = jsonrpc_call(1, "deploy.apply", json!({}));
        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", (super::MAX_BODY_BYTES + 1).to_string())
                .with_body(body.to_string()),
        );
        assert_eq!(response.status_code(), 403);
        assert!(backend.next().is_none());
    }

    #[test]
    fn no_body_at_all_fails_closed_in_block_mode() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let response = tester.request(UnitHttpRequest::get());
        assert_eq!(response.status_code(), 403);
    }

    #[test]
    fn on_deny_empty_403_never_echoes_an_id() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(
                json!({"onDeny": "empty-403", "requiredPredicates": ["P1"]}),
            ))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            CTRL01_DIGEST,
            &far_future(),
            "n-1",
            json!([]),
            json!({}),
        );
        let body = jsonrpc_call(42, "deploy.destroy", json!({}));
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        assert_eq!(response.status_code(), 403);
        assert!(response.body().is_empty());
        assert_eq!(
            response.header("x-approval-binding"),
            Some("denied;predicate=P1")
        );
    }

    #[test]
    fn monitor_mode_records_verdict_but_forwards_a_denying_request() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(
                json!({"mode": "monitor", "requiredPredicates": ["P1"]}),
            ))
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            CTRL01_DIGEST,
            &far_future(),
            "n-1",
            json!([]),
            json!({}),
        );
        let body = jsonrpc_call(1, "deploy.destroy", json!({}));
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        assert_eq!(response.status_code(), 200);
        let forwarded = backend
            .next()
            .expect("monitor mode must forward the request");
        assert_eq!(
            forwarded.header("x-approval-binding"),
            Some("would-deny;predicate=P1")
        );
    }

    #[test]
    fn allowed_request_is_stamped_and_forwarded() {
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        let envelope = approval_envelope(
            "deploy.apply",
            CTRL01_DIGEST,
            "2026-09-19T12:00:00Z",
            "n-allow-1",
            json!([{"claim": "approval", "authority": "approver.example", "mac": CTRL01_MAC}]),
            json!({"blob://plan-v1": PLAN_V1_DIGEST}),
        );
        let body = jsonrpc_call(
            1,
            "deploy.apply",
            json!({"manifest": {"$ref": "blob://plan-v1"}, "confirm": true}),
        );
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        assert_eq!(response.status_code(), 200);
        let forwarded = backend.next().expect("allowed request forwards upstream");
        assert_eq!(forwarded.header("x-approval-binding"), Some("allowed"));
    }

    #[test]
    fn rpc_param_approval_source_is_read_from_body_sibling_field() {
        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(
                json!({"approvalSource": "rpc-param", "requiredPredicates": ["P1", "P2", "P5"]}),
            ))
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        // Real, freshly computed digest/MAC (not vendored constants) — this
        // test exercises the rpc-param plumbing itself, so the cryptographic
        // values only need to be internally consistent, computed the same
        // way the production check_p5/check_action_and_arguments code does.
        let arguments = json!({"confirm": true});
        let digest = super::digest_value(&arguments);
        let mac = hmac_hex(
            "abv/approver",
            &json!({"action": "deploy.apply", "arguments_digest": digest}),
        );
        let envelope = approval_envelope(
            "deploy.apply",
            &digest,
            "2026-09-19T12:00:00Z",
            "n-rpc-param-1",
            json!([{"claim": "approval", "authority": "approver.example", "mac": mac}]),
            json!({}),
        );
        let mut body = jsonrpc_call(1, "deploy.apply", arguments);
        body["approvalBinding"] = envelope;
        let body_text = body.to_string();
        let request = UnitHttpRequest::post()
            .with_header("content-type", "application/json")
            .with_header("content-length", body_text.len().to_string())
            .with_header("client_id", "executor.example")
            .with_body(body_text);
        let response = tester.request(request);
        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn tools_call_without_matching_name_field_fails_closed() {
        let mut tester = UnitTestBuilder::default()
            .with_config(block_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}});
        let response = tester.request(
            UnitHttpRequest::post()
                .with_header("content-type", "application/json")
                .with_header("content-length", body.to_string().len().to_string())
                .with_body(body.to_string()),
        );
        assert_eq!(response.status_code(), 403);
    }

    #[test]
    fn generic_method_uses_method_and_params_directly() {
        // Not every governed call is tools/call — a generic JSON-RPC method's
        // name is the action and its params are the arguments.
        let mut tester = UnitTestBuilder::default()
            .with_config(vector_config())
            .with_backend(ok_backend)
            .with_entrypoint(super::configure);
        let digest = super::digest_value(&json!({"target": "prod"}));
        let mac = hmac_hex(
            "abv/approver",
            &json!({"action": "system.reboot", "arguments_digest": digest}),
        );
        let envelope = approval_envelope(
            "system.reboot",
            &digest,
            "2026-09-19T12:00:00Z",
            "n-generic-1",
            json!([{"claim": "approval", "authority": "approver.example", "mac": mac}]),
            json!({}),
        );
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "system.reboot", "params": {"target": "prod"}});
        let response = tester.request(request_with(&envelope, "executor.example", &body));
        assert_eq!(response.status_code(), 200);
    }
}
