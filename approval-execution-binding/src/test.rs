// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Unit tests for the Approval-to-Execution Binding policy.
//!
//! Scope after the #1–#7 reviewer findings:
//!   * The policy binds ONLY MCP `tools/call` requests; any other JSON-RPC
//!     method is forwarded out-of-scope (finding #7).
//!   * Canonicalization is versioned and fail-closed — non-integer numbers and
//!     `$ref`-shaped arguments are rejected, never coerced (findings #5, #2).
//!   * P5 authenticates the versioned, domain-separated `mcp-v1` payload; the
//!     executor `sub` is taken from VERIFIED `AuthenticationData`, never a
//!     caller-asserted header (findings #4, #6).
//!   * P6 single-use is enforced atomically through DataStorage in block mode
//!     only; monitor mode never consumes a nonce (finding #3).
//!
//! The ABV corpus (`tests/fixtures/abv/*.json`) is exercised at FUNCTION LEVEL
//! only, as an interop conformance harness for `canonical_json`/`digest_value`/
//! HMAC. Its short demo keys and `{action, arguments_digest}` MAC scope are NOT
//! the production `mcp-v1` P5 path.

use super::*;
use pdk::authentication::AuthenticationData;
use pdk_unit::{TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder};
use std::rc::Rc;

// ---------------------------------------------------------------------------
// Deployment-identity constants (mirror config expected* fields)
// ---------------------------------------------------------------------------
const AUD: &str = "mcp-gateway-prod";
const TENANT: &str = "acme";
const ENVIRONMENT: &str = "prod";
const APPROVER: &str = "approver.example";
const EXECUTOR: &str = "executor.example";
// Attester keys must clear the >=32-byte from_config gate (finding #1).
const APPROVER_KEY: &str = "approver-hmac-key-0123456789abcdefXY";
const EXECUTOR_KEY: &str = "executor-hmac-key-0123456789abcdefXY";

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

fn attester(kid: &str, key: &str) -> Value {
    json!({"kid": kid, "key": key})
}

fn config_with(overrides: Value) -> String {
    let mut base = json!({
        "approvalSource": "header",
        "approvalHeader": "x-approval",
        "approvalRpcField": "approvalBinding",
        "executorHeader": "client_id",
        "requiredPredicates": ["P1", "P2", "P5", "P6"],
        "attesterKeys": [
            attester(APPROVER, APPROVER_KEY),
            attester(EXECUTOR, EXECUTOR_KEY)
        ],
        "expectedAudience": AUD,
        "expectedTenant": TENANT,
        "expectedEnvironment": ENVIRONMENT,
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

fn parse_config(json: Value) -> Result<Config> {
    serde_json::from_value(json).map_err(|err| anyhow!("{err}"))
}

// ---------------------------------------------------------------------------
// Crypto helpers — reuse the policy's OWN canonicalizer and hasher so the tests
// cannot silently diverge from the production code path.
// ---------------------------------------------------------------------------

fn hmac_over_canonical(key: &[u8], value: &Value) -> String {
    let bytes = super::canonical_json(value)
        .expect("test payload must canonicalize")
        .into_bytes();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(&bytes);
    super::hex_encode(&mac.finalize().into_bytes())
}

#[allow(clippy::too_many_arguments)]
fn mcp_v1_mac(
    key: &[u8],
    iss: &str,
    sub: &str,
    action: &str,
    digest: &str,
    not_after: &str,
    nonce: &str,
) -> String {
    hmac_over_canonical(
        key,
        &super::mcp_v1_payload(
            iss,
            AUD,
            TENANT,
            ENVIRONMENT,
            sub,
            action,
            digest,
            not_after,
            nonce,
        ),
    )
}

// ---------------------------------------------------------------------------
// Envelope / request builders
// ---------------------------------------------------------------------------

fn approval_envelope(
    action: &str,
    arguments_digest: &str,
    not_after: &str,
    nonce: &str,
    attestations: Value,
) -> Value {
    json!({
        "approval": {
            "scope": {"action": action, "arguments_digest": arguments_digest},
            "authority": APPROVER,
            "not_after": not_after,
            "nonce": nonce
        },
        "attestations": attestations
    })
}

/// A fully sound approval: approver-signed `mcp-v1` MAC over the executed
/// action + arguments digest, bound to the verified executor `sub`.
fn sound_approval(action: &str, args: &Value, nonce: &str, not_after: &str) -> Value {
    let digest = super::digest_value(args).expect("args must canonicalize");
    let mac = mcp_v1_mac(
        APPROVER_KEY.as_bytes(),
        APPROVER,
        EXECUTOR,
        action,
        &digest,
        not_after,
        nonce,
    );
    approval_envelope(
        action,
        &digest,
        not_after,
        nonce,
        json!([{"claim": "approval", "authority": APPROVER, "mac": mac}]),
    )
}

fn jsonrpc_call(id: i64, action: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": action, "arguments": arguments}
    })
}

fn jsonrpc_notification(action: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": action, "arguments": arguments}
    })
}

fn auth_of(subject: &str) -> AuthenticationData {
    AuthenticationData {
        client_id: Some(subject.to_string()),
        principal: Some(subject.to_string()),
        ..Default::default()
    }
}

/// Standard request: header `client_id` AND verified `AuthenticationData` both
/// name `executor`.
fn request_with(envelope: &Value, executor: &str, body: &Value) -> UnitHttpRequest {
    let body_text = body.to_string();
    UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("content-length", body_text.len().to_string())
        .with_header("x-approval", envelope.to_string())
        .with_header("client_id", executor)
        .with_body(body_text)
        .with_authentication_data(auth_of(executor))
}

/// Request from raw body bytes (for member-reordering / malformed-shape tests),
/// with a truthful content-length and a verified executor.
fn raw_request(envelope: &Value, executor: &str, body_text: &str) -> UnitHttpRequest {
    UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("content-length", body_text.len().to_string())
        .with_header("x-approval", envelope.to_string())
        .with_header("client_id", executor)
        .with_body(body_text.to_string())
        .with_authentication_data(auth_of(executor))
}

fn ok_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
    UnitHttpResponse::new(200)
        .with_header("content-type", "application/json")
        .with_body(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}")
}

const OK_BODY: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";

fn far_future() -> String {
    (chrono::Utc::now() + chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn far_past() -> String {
    (chrono::Utc::now() - chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Build a tester + trace backend for a given policy config. Kept as a macro so
/// the concrete `UnitTest`/`TraceBackend` types stay inferred at the call site.
macro_rules! harness {
    ($cfg:expr) => {{
        let backend = Rc::new(TraceBackend::new(ok_backend));
        let tester = UnitTestBuilder::default()
            .with_config($cfg)
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);
        (backend, tester)
    }};
}

fn is_rpc_error(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|json| json.get("error").cloned())
        .is_some()
}

// ===========================================================================
// A. Sound / allow  (P1, P2, P5, P6)
// ===========================================================================

#[test]
fn fully_sound_record_is_allowed() {
    let (backend, mut tester) = harness!(block_config());
    let args = json!({"service": "checkout", "replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-0001", &far_future());
    let body = jsonrpc_call(1, "deploy.apply", args);
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 200);
    assert_eq!(
        response.body(),
        OK_BODY,
        "sound record returns upstream body"
    );
    assert!(backend.next().is_some(), "sound record must reach upstream");
}

#[test]
fn member_reordering_is_still_allowed() {
    // Same content, JSON object members emitted in a different textual order in
    // the raw request bytes. Canonicalization must make this indistinguishable.
    let (backend, mut tester) = harness!(block_config());
    let args = json!({"replicas": 3, "service": "checkout"});
    let envelope = sound_approval("deploy.apply", &args, "n-reorder", &far_future());
    let raw_body = "{\"params\":{\"arguments\":{\"service\":\"checkout\",\"replicas\":3},\
\"name\":\"deploy.apply\"},\"method\":\"tools/call\",\"id\":1,\"jsonrpc\":\"2.0\"}";
    let response = tester.request(raw_request(&envelope, EXECUTOR, raw_body));
    assert_eq!(response.status_code(), 200);
    assert_eq!(response.body(), OK_BODY);
    assert!(backend.next().is_some());
}

// ===========================================================================
// B. P1 — action binding
// ===========================================================================

#[test]
fn wrong_action_is_denied_for_p1() {
    let (backend, mut tester) = harness!(config_with(json!({"requiredPredicates": ["P1"]})));
    let envelope = approval_envelope(
        "deploy.apply",
        "irrelevant",
        &far_future(),
        "n-p1",
        json!([]),
    );
    let body = jsonrpc_call(1, "deploy.destroy", json!({}));
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 200);
    assert!(is_rpc_error(response.body()));
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=P1")
    );
    assert!(backend.next().is_none(), "a denied action must not forward");
}

// ===========================================================================
// C. P2 — canonical argument match + $ref fail-closed  (finding #2)
// ===========================================================================

#[test]
fn changed_argument_is_denied_for_p2() {
    let (_backend, mut tester) = harness!(config_with(json!({"requiredPredicates": ["P1", "P2"]})));
    let approved = json!({"replicas": 3});
    let digest = super::digest_value(&approved).unwrap();
    let envelope = approval_envelope("deploy.apply", &digest, &far_future(), "n-p2", json!([]));
    let body = jsonrpc_call(1, "deploy.apply", json!({"replicas": 9}));
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 200);
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=P2")
    );
}

#[test]
fn top_level_ref_argument_is_denied() {
    let (_backend, mut tester) = harness!(config_with(json!({"requiredPredicates": ["P1", "P2"]})));
    let args = json!({"manifest": {"$ref": "blob://plan-v1"}});
    let digest = super::digest_value(&json!({})).unwrap();
    let envelope = approval_envelope("deploy.apply", &digest, &far_future(), "n-ref1", json!([]));
    let body = jsonrpc_call(1, "deploy.apply", args);
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=P2")
    );
}

#[test]
fn nested_ref_argument_is_denied() {
    let (_backend, mut tester) = harness!(config_with(json!({"requiredPredicates": ["P1", "P2"]})));
    let args = json!({"outer": {"inner": {"$ref": "blob://x"}}});
    let digest = super::digest_value(&json!({})).unwrap();
    let envelope = approval_envelope("deploy.apply", &digest, &far_future(), "n-ref2", json!([]));
    let body = jsonrpc_call(1, "deploy.apply", args);
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=P2")
    );
}

#[test]
fn ref_object_with_extra_members_is_denied() {
    let (_backend, mut tester) = harness!(config_with(json!({"requiredPredicates": ["P1", "P2"]})));
    let args = json!({"m": {"$ref": "blob://x", "extra": 1}});
    let digest = super::digest_value(&json!({})).unwrap();
    let envelope = approval_envelope("deploy.apply", &digest, &far_future(), "n-ref3", json!([]));
    let body = jsonrpc_call(1, "deploy.apply", args);
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=P2")
    );
}

#[test]
fn ref_as_string_value_is_allowed() {
    // A bare `$ref` STRING VALUE is not a reference object — it is ordinary data.
    let (backend, mut tester) = harness!(config_with(json!({"requiredPredicates": ["P1", "P2"]})));
    let args = json!({"kind": "$ref"});
    let digest = super::digest_value(&args).unwrap();
    let envelope = approval_envelope("deploy.apply", &digest, &far_future(), "n-ref4", json!([]));
    let body = jsonrpc_call(1, "deploy.apply", args);
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 200);
    assert_eq!(response.body(), OK_BODY);
    assert!(backend.next().is_some());
}

// ===========================================================================
// D. P4 — freshness (dynamic wall-clock timestamps)
// ===========================================================================

#[test]
fn fresh_within_window_is_allowed_for_p4() {
    let (backend, mut tester) = harness!(config_with(json!({"requiredPredicates": ["P1", "P4"]})));
    let envelope = approval_envelope("deploy.apply", "x", &far_future(), "n-p4a", json!([]));
    let body = jsonrpc_call(1, "deploy.apply", json!({}));
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 200);
    assert_eq!(response.body(), OK_BODY);
    assert!(backend.next().is_some());
}

#[test]
fn expired_approval_is_denied_for_p4() {
    let (backend, mut tester) = harness!(config_with(json!({"requiredPredicates": ["P1", "P4"]})));
    let envelope = approval_envelope("deploy.apply", "x", &far_past(), "n-p4b", json!([]));
    let body = jsonrpc_call(1, "deploy.apply", json!({}));
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=P4")
    );
    assert!(backend.next().is_none());
}

#[test]
fn missing_not_after_is_denied_for_p4() {
    let (_backend, mut tester) = harness!(config_with(json!({"requiredPredicates": ["P1", "P4"]})));
    let envelope = approval_envelope("deploy.apply", "x", "", "n-p4c", json!([]));
    let body = jsonrpc_call(1, "deploy.apply", json!({}));
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=P4")
    );
}

// ===========================================================================
// E. #5 — versioned canonicalization is fail-closed
// ===========================================================================

#[test]
fn float_argument_is_not_canonicalizable() {
    assert!(super::digest_value(&json!({"x": 1.5})).is_err());
}

#[test]
fn integer_outside_i64_u64_is_not_canonicalizable() {
    let huge: Value =
        serde_json::from_str("123456789012345678901234567890").expect("valid json number");
    assert!(super::digest_value(&huge).is_err());
}

#[test]
fn null_object_array_and_scalar_have_distinct_digests() {
    let digests = [
        super::digest_value(&Value::Null).unwrap(),
        super::digest_value(&json!({})).unwrap(),
        super::digest_value(&json!([])).unwrap(),
        super::digest_value(&json!(0)).unwrap(),
    ];
    for i in 0..digests.len() {
        for j in (i + 1)..digests.len() {
            assert_ne!(
                digests[i], digests[j],
                "distinct JSON shapes must not collide"
            );
        }
    }
}

// ===========================================================================
// F. #6 — executor identity comes from VERIFIED AuthenticationData
// ===========================================================================

#[test]
fn verified_auth_overrides_spoofed_executor_header() {
    // The MAC binds sub=EXECUTOR. The request carries a SPOOFED client_id header
    // ("attacker.example") but a VERIFIED AuthenticationData naming EXECUTOR. P5
    // must trust the verified subject and allow — proving the header is ignored.
    let (backend, mut tester) = harness!(block_config());
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-spoof", &far_future());
    let body = jsonrpc_call(1, "deploy.apply", args);
    let body_text = body.to_string();
    let request = UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("content-length", body_text.len().to_string())
        .with_header("x-approval", envelope.to_string())
        .with_header("client_id", "attacker.example")
        .with_body(body_text)
        .with_authentication_data(auth_of(EXECUTOR));
    let response = tester.request(request);
    assert_eq!(response.status_code(), 200);
    assert_eq!(response.body(), OK_BODY);
    assert!(backend.next().is_some());
}

#[test]
fn missing_verified_auth_with_p5_required_fails_closed() {
    // No AuthenticationData at all — only a caller-asserted header. A P5-required
    // binding must fail closed rather than trust the unverified header.
    let (backend, mut tester) = harness!(block_config());
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-noauth", &far_future());
    let body = jsonrpc_call(1, "deploy.apply", args);
    let body_text = body.to_string();
    let request = UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("content-length", body_text.len().to_string())
        .with_header("x-approval", envelope.to_string())
        .with_header("client_id", EXECUTOR)
        .with_body(body_text);
    let response = tester.request(request);
    assert!(
        response
            .header("x-approval-binding")
            .unwrap_or_default()
            .starts_with("denied"),
        "P5 without verified auth must deny"
    );
    assert!(backend.next().is_none());
}

// ===========================================================================
// G. #3 — atomic single-use via DataStorage
// ===========================================================================

#[test]
fn first_use_allowed_second_use_is_p6_replay_denied_in_block_mode() {
    let (backend, mut tester) = harness!(block_config());
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-single", &far_future());
    let body = jsonrpc_call(1, "deploy.apply", args);

    let first = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(first.status_code(), 200);
    assert_eq!(first.body(), OK_BODY);
    assert!(backend.next().is_some(), "first use reaches upstream");

    let second = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(second.status_code(), 200);
    assert_eq!(
        second.header("x-approval-binding"),
        Some("denied;predicate=P6")
    );
    assert!(is_rpc_error(second.body()));
    assert!(
        backend.next().is_none(),
        "a replayed nonce must not reach upstream a second time"
    );
}

#[test]
fn monitor_mode_does_not_reserve_the_nonce() {
    // In monitor mode the same sound nonce may be replayed and both requests are
    // forwarded and stamped "allowed" — monitor never consumes a nonce.
    let (backend, mut tester) = harness!(monitor_config());
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-monitor", &far_future());
    let body = jsonrpc_call(1, "deploy.apply", args);

    let first = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(first.status_code(), 200);
    let forwarded_first = backend.next().expect("first request forwards");
    assert_eq!(
        forwarded_first.header("x-approval-binding"),
        Some("allowed")
    );

    let second = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(second.status_code(), 200);
    let forwarded_second = backend
        .next()
        .expect("second request forwards (nonce not consumed)");
    assert_eq!(
        forwarded_second.header("x-approval-binding"),
        Some("allowed"),
        "monitor mode must not have consumed the nonce"
    );
}

// ===========================================================================
// H. #7 — only tools/call is bound; other methods forward out-of-scope
// ===========================================================================

#[test]
fn non_tools_call_method_is_forwarded_out_of_scope() {
    let (backend, mut tester) = harness!(block_config());
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "resources/list", "params": {}});
    let envelope = approval_envelope("unused", "x", &far_future(), "n-oos", json!([]));
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 200);
    let forwarded = backend.next().expect("out-of-scope method must forward");
    assert_eq!(forwarded.header("x-approval-binding"), Some("out-of-scope"));
}

#[test]
fn jsonrpc_batch_fails_closed() {
    let (backend, mut tester) = harness!(block_config());
    let body = json!([{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}]);
    let envelope = approval_envelope("x", "x", &far_future(), "n-batch", json!([]));
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 403);
    assert!(backend.next().is_none());
}

// ===========================================================================
// I. Structural / fail-closed edge cases
// ===========================================================================

#[test]
fn missing_approval_header_with_p5_is_denied() {
    let (backend, mut tester) = harness!(block_config());
    let args = json!({"replicas": 3});
    let body = jsonrpc_call(1, "deploy.apply", args);
    let body_text = body.to_string();
    let request = UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("content-length", body_text.len().to_string())
        .with_header("client_id", EXECUTOR)
        .with_body(body_text)
        .with_authentication_data(auth_of(EXECUTOR));
    let response = tester.request(request);
    assert!(response
        .header("x-approval-binding")
        .unwrap_or_default()
        .starts_with("denied"));
    assert!(backend.next().is_none());
}

#[test]
fn malformed_approval_header_fails_closed() {
    let (backend, mut tester) = harness!(block_config());
    let args = json!({"replicas": 3});
    let body = jsonrpc_call(1, "deploy.apply", args);
    let body_text = body.to_string();
    let request = UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("content-length", body_text.len().to_string())
        .with_header("x-approval", "{not valid json")
        .with_header("client_id", EXECUTOR)
        .with_body(body_text)
        .with_authentication_data(auth_of(EXECUTOR));
    let response = tester.request(request);
    assert!(response
        .header("x-approval-binding")
        .unwrap_or_default()
        .starts_with("denied"));
    assert!(backend.next().is_none());
}

#[test]
fn non_jsonrpc_body_empty_403_in_block_mode() {
    let (backend, mut tester) = harness!(block_config());
    let envelope = approval_envelope("x", "x", &far_future(), "n-nonrpc", json!([]));
    let response = tester.request(raw_request(&envelope, EXECUTOR, "not json at all"));
    assert_eq!(response.status_code(), 403);
    assert!(response.body().is_empty());
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=malformed")
    );
    assert!(backend.next().is_none());
}

#[test]
fn non_jsonrpc_body_forwarded_in_monitor_mode() {
    let (backend, mut tester) = harness!(monitor_config());
    let envelope = approval_envelope("x", "x", &far_future(), "n-nonrpc-m", json!([]));
    let response = tester.request(raw_request(&envelope, EXECUTOR, "not json at all"));
    assert_eq!(response.status_code(), 200);
    let forwarded = backend.next().expect("monitor mode forwards");
    assert_eq!(
        forwarded.header("x-approval-binding"),
        Some("monitor;predicate=malformed")
    );
}

#[test]
fn forged_short_content_length_fails_closed() {
    let (backend, mut tester) = harness!(block_config());
    let envelope = approval_envelope("x", "x", &far_future(), "n-short", json!([]));
    let body = jsonrpc_call(1, "deploy.apply", json!({})).to_string();
    let request = UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("content-length", "3")
        .with_header("x-approval", envelope.to_string())
        .with_header("client_id", EXECUTOR)
        .with_body(body)
        .with_authentication_data(auth_of(EXECUTOR));
    let response = tester.request(request);
    assert_eq!(response.status_code(), 403);
    assert!(backend.next().is_none());
}

#[test]
fn oversized_declared_length_fails_closed() {
    let (backend, mut tester) = harness!(block_config());
    let envelope = approval_envelope("x", "x", &far_future(), "n-big", json!([]));
    let body = jsonrpc_call(1, "deploy.apply", json!({})).to_string();
    let request = UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("content-length", (super::MAX_BODY_BYTES + 1).to_string())
        .with_header("x-approval", envelope.to_string())
        .with_header("client_id", EXECUTOR)
        .with_body(body)
        .with_authentication_data(auth_of(EXECUTOR));
    let response = tester.request(request);
    assert_eq!(response.status_code(), 403);
    assert!(backend.next().is_none());
}

#[test]
fn no_body_at_all_fails_closed() {
    let (backend, mut tester) = harness!(block_config());
    let response = tester.request(UnitHttpRequest::get());
    assert_eq!(response.status_code(), 403);
    assert!(backend.next().is_none());
}

#[test]
fn duplicate_json_members_fail_closed() {
    let (backend, mut tester) = harness!(block_config());
    let envelope = approval_envelope("deploy.apply", "x", &far_future(), "n-dup", json!([]));
    let raw_body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\
\"params\":{\"name\":\"deploy.apply\",\"arguments\":{\"a\":1,\"a\":2}}}";
    let response = tester.request(raw_request(&envelope, EXECUTOR, raw_body));
    assert_eq!(response.status_code(), 403);
    assert!(backend.next().is_none());
}

#[test]
fn tools_call_without_name_fails_closed() {
    let (backend, mut tester) = harness!(block_config());
    let envelope = approval_envelope("deploy.apply", "x", &far_future(), "n-noname", json!([]));
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"arguments": {}}
    });
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 403);
    assert!(backend.next().is_none());
}

#[test]
fn numeric_overflow_in_body_fails_closed() {
    let (backend, mut tester) = harness!(block_config());
    let envelope = approval_envelope("deploy.apply", "x", &far_future(), "n-ovf", json!([]));
    let raw_body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\
\"params\":{\"name\":\"deploy.apply\",\"arguments\":{\"n\":1e400}}}";
    let response = tester.request(raw_request(&envelope, EXECUTOR, raw_body));
    assert_eq!(response.status_code(), 403);
    assert!(backend.next().is_none());
}

// ===========================================================================
// J. Stamping, monitor would-deny, and PDK policy-violation registration
// ===========================================================================

#[test]
fn allowed_request_is_stamped_and_forwarded() {
    let (backend, mut tester) = harness!(block_config());
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-stamp", &far_future());
    let body = jsonrpc_call(1, "deploy.apply", args);
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 200);
    let forwarded = backend.next().expect("allowed request forwards");
    assert_eq!(forwarded.header("x-approval-binding"), Some("allowed"));
}

#[test]
fn monitor_mode_would_deny_is_stamped_and_forwarded() {
    let (backend, mut tester) = harness!(config_with(
        json!({"mode": "monitor", "requiredPredicates": ["P1"]})
    ));
    let envelope = approval_envelope("deploy.apply", "x", &far_future(), "n-wd", json!([]));
    let body = jsonrpc_call(1, "deploy.destroy", json!({}));
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 200);
    assert_eq!(
        response.body(),
        OK_BODY,
        "monitor mode forwards to upstream"
    );
    let forwarded = backend.next().expect("monitor mode forwards");
    assert_eq!(
        forwarded.header("x-approval-binding"),
        Some("would-deny;predicate=P1")
    );
}

#[test]
fn block_mode_denial_sets_policy_violation_without_forwarding() {
    let (backend, mut tester) = harness!(config_with(json!({"requiredPredicates": ["P1"]})));
    let envelope = approval_envelope("deploy.apply", "x", &far_future(), "n-viol", json!([]));
    let body = jsonrpc_call(1, "deploy.destroy", json!({}));
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert!(
        response.violation().is_some(),
        "a block-mode predicate-failure denial must signal a violation"
    );
    assert!(backend.next().is_none());
}

#[test]
fn allowed_request_registers_no_violation() {
    let (_backend, mut tester) = harness!(block_config());
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-noviol", &far_future());
    let body = jsonrpc_call(1, "deploy.apply", args);
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert!(
        response.violation().is_none(),
        "an allowed request must not register a policy violation"
    );
}

#[test]
fn notification_denial_returns_202_without_body() {
    let (backend, mut tester) = harness!(config_with(json!({"requiredPredicates": ["P1"]})));
    let envelope = approval_envelope("deploy.apply", "x", &far_future(), "n-notif", json!([]));
    let body = jsonrpc_notification("deploy.destroy", json!({}));
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 202);
    assert!(response.body().is_empty());
    assert!(backend.next().is_none());
}

#[test]
fn empty_403_deny_never_echoes_the_request_id() {
    let (_backend, mut tester) = harness!(config_with(json!({
        "requiredPredicates": ["P1"],
        "onDeny": "empty-403"
    })));
    let envelope = approval_envelope("deploy.apply", "x", &far_future(), "n-403", json!([]));
    let body = jsonrpc_call(4242, "deploy.destroy", json!({}));
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 403);
    assert!(response.body().is_empty(), "empty-403 must not echo the id");
}

// ===========================================================================
// K. Config validation (belt-and-suspenders; GCL schema also enforces these)
// ===========================================================================

fn base_config_json(overrides: Value) -> Value {
    let mut base = json!({
        "approvalSource": "header", "approvalHeader": "x-approval",
        "approvalRpcField": "approvalBinding", "executorHeader": "client_id",
        "requiredPredicates": ["P1"], "attesterKeys": [],
        "clockSkewSeconds": 60, "mode": "block", "onDeny": "rpc-error",
        "resultHeader": "x-approval-binding"
    });
    for (key, value) in overrides.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

#[test]
fn empty_required_predicates_is_rejected() {
    let config = parse_config(base_config_json(json!({"requiredPredicates": []}))).unwrap();
    assert!(Binding::from_config(&config).is_err());
}

#[test]
fn sidecar_approval_source_is_rejected() {
    let config = parse_config(base_config_json(json!({"approvalSource": "sidecar"}))).unwrap();
    match Binding::from_config(&config) {
        Ok(_) => panic!("expected approvalSource=sidecar to be rejected"),
        Err(err) => assert!(err.to_string().contains("not implemented")),
    }
}

#[test]
fn unknown_predicate_is_rejected() {
    let config = parse_config(base_config_json(json!({"requiredPredicates": ["P9"]}))).unwrap();
    assert!(Binding::from_config(&config).is_err());
}

#[test]
fn unknown_mode_is_rejected() {
    let config = parse_config(base_config_json(json!({"mode": "audit"}))).unwrap();
    assert!(Binding::from_config(&config).is_err());
}

#[test]
fn unknown_on_deny_is_rejected() {
    let config = parse_config(base_config_json(json!({"onDeny": "explode"}))).unwrap();
    assert!(Binding::from_config(&config).is_err());
}

#[test]
fn duplicate_attester_kid_is_rejected() {
    let config = parse_config(base_config_json(json!({
        "attesterKeys": [attester("dup.kid", APPROVER_KEY), attester("dup.kid", EXECUTOR_KEY)]
    })))
    .unwrap();
    assert!(Binding::from_config(&config).is_err());
}

#[test]
fn blank_attester_kid_is_rejected() {
    let config = parse_config(base_config_json(json!({
        "attesterKeys": [attester("  ", APPROVER_KEY)]
    })))
    .unwrap();
    assert!(Binding::from_config(&config).is_err());
}

#[test]
fn attester_key_below_minimum_strength_is_rejected() {
    // Finding #1: an attester key shorter than the 32-byte minimum is refused.
    let config = parse_config(base_config_json(json!({
        "attesterKeys": [attester("weak.kid", "too-short")]
    })))
    .unwrap();
    match Binding::from_config(&config) {
        Ok(_) => panic!("short key must be rejected"),
        Err(err) => assert!(err.to_string().contains("minimum")),
    }
}

#[test]
fn expected_audience_is_required_when_p5_is_required() {
    // Finding #4: the mcp-v1 identity binding is vacuous without a deployment
    // identity, so empty expectedAudience is rejected when P5 is required.
    let config = parse_config(base_config_json(json!({
        "requiredPredicates": ["P1", "P5"],
        "attesterKeys": [attester(APPROVER, APPROVER_KEY), attester(EXECUTOR, EXECUTOR_KEY)],
        "expectedTenant": TENANT,
        "expectedEnvironment": ENVIRONMENT
    })))
    .unwrap();
    match Binding::from_config(&config) {
        Ok(_) => panic!("empty expectedAudience must be rejected"),
        Err(err) => assert!(err.to_string().contains("expectedAudience")),
    }
}

// ===========================================================================
// L. ABV corpus — FUNCTION-LEVEL interop conformance harness
// ===========================================================================

#[test]
fn abv_corpus_is_self_consistent_at_function_level() {
    // Conformance ONLY: the corpus authenticates {action, arguments_digest}
    // under SHORT demo keys — deliberately NOT the >=32-byte from_config gate
    // nor the production mcp-v1 payload. This proves canonical_json/digest_value
    // and our HMAC reproduce the independently-generated Python corpus byte for
    // byte. Expect 11 approval-claim MACs and 3 ref-free digest vectors.
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/abv");
    let demo_key = |authority: &str| -> &'static [u8] {
        match authority {
            "approver.example" => &b"abv/approver"[..],
            "executor.example" => &b"abv/executor"[..],
            other => panic!("unknown corpus authority {}", other),
        }
    };
    let mut mac_checks = 0usize;
    let mut digest_checks = 0usize;
    for entry in std::fs::read_dir(dir).expect("read abv fixtures dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read fixture");
        let fixture: Value = serde_json::from_str(&text).expect("valid fixture json");
        let scope = &fixture["approval"]["scope"];
        let action = scope["action"].as_str().expect("scope action");
        let digest = scope["arguments_digest"].as_str().expect("scope digest");
        let mac_scope = json!({"action": action, "arguments_digest": digest});
        for att in fixture["attestations"]
            .as_array()
            .expect("attestations array")
        {
            if att["claim"].as_str() == Some("approval") {
                let authority = att["authority"].as_str().expect("attestation authority");
                let expected = hmac_over_canonical(demo_key(authority), &mac_scope);
                assert_eq!(
                    att["mac"].as_str().expect("attestation mac"),
                    expected,
                    "corpus MAC mismatch in {}",
                    path.display()
                );
                mac_checks += 1;
            }
        }
        let request_args = &fixture["request"]["arguments"];
        if !super::contains_ref_object(request_args) {
            assert_eq!(
                super::digest_value(request_args).expect("ref-free args canonicalize"),
                digest,
                "corpus digest mismatch in {}",
                path.display()
            );
            digest_checks += 1;
        }
    }
    assert_eq!(
        mac_checks, 11,
        "expected 11 approval-claim MACs in the corpus"
    );
    assert_eq!(digest_checks, 3, "expected 3 ref-free digest vectors");
}
