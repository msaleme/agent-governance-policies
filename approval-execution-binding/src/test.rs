// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Unit tests for the Approval-to-Execution Binding policy.
//!
//! Scope after the #1–#7 reviewer findings:
//!   * The policy binds ONLY MCP `tools/call` requests; any other JSON-RPC
//!     method is forwarded out-of-scope (finding #7), and so is a well-formed
//!     JSON-RPC response a client POSTs back (finding #57); an ambiguous or
//!     malformed response fails closed.
//!   * Canonicalization is versioned and fail-closed — non-integer numbers and
//!     `$ref`-shaped arguments are rejected, never coerced (findings #5, #2).
//!   * P5 authenticates the versioned, domain-separated `mcp-v1` payload; the
//!     executor `sub` is taken from VERIFIED `AuthenticationData`, never a
//!     caller-asserted header (findings #4, #6).
//!   * P6 single-use is enforced atomically through LOCAL DataStorage in block
//!     mode only — per gateway replica, until restart — with a bounded store;
//!     monitor mode never consumes a nonce (findings #3, #51).
//!   * Only HTTP POST is bound; bodyless GET/DELETE/OPTIONS/HEAD transport
//!     requests forward out-of-scope, and a POST without a valid declared
//!     content-length is a framing denial (finding #50).
//!   * Only an absent or `utf-8` charset is inspectable; any other charset and
//!     any body serde rejects fail closed, never out-of-scope.
//!   * Integers beyond ±(2^53 − 1) and UTF-8/UTF-16 key-order disagreements
//!     fail closed in canonicalization (finding #52).
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
        "requiredPredicates": ["P1", "P2", "P4", "P5", "P6"],
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
    serde_json::from_value(json).map_err(|err| anyhow!("{}", err))
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
fn integers_beyond_double_precision_fail_closed() {
    // #52: RFC 8785 serializes numbers as IEEE-754 doubles, so 2^53 and beyond
    // would canonicalize differently in a conforming JCS implementation.
    for safe in ["9007199254740991", "-9007199254740991", "0"] {
        let value: Value = serde_json::from_str(safe).expect("valid json number");
        assert!(
            super::digest_value(&value).is_ok(),
            "{} is inside ±(2^53 − 1) and must canonicalize",
            safe
        );
    }
    for unsafe_int in [
        "9007199254740992",
        "9007199254740993",
        "-9007199254740992",
        "18446744073709551615",
    ] {
        let value: Value = serde_json::from_str(unsafe_int).expect("valid json number");
        assert!(
            super::digest_value(&json!({ "n": value })).is_err(),
            "{} is outside ±(2^53 − 1) and must fail closed",
            unsafe_int
        );
    }
}

#[test]
fn key_order_that_differs_between_utf8_and_utf16_fails_closed() {
    // #52: U+FF61 sorts before U+1F600 by UTF-8 bytes (EF.. < F0..) but after it
    // by UTF-16 code units (FF61 > D83D), so the ABV reference form and JCS
    // disagree on this object's member order.
    let mixed = json!({"\u{FF61}": 1, "\u{1F600}": 2});
    assert!(super::digest_value(&mixed).is_err());
    let nested = json!({"outer": [{"\u{FF61}": 1, "\u{1F600}": 2}]});
    assert!(super::digest_value(&nested).is_err());
    // Orders that agree under both sortings still canonicalize.
    assert!(super::digest_value(&json!({"a": 1, "\u{1F600}": 2})).is_ok());
    assert!(super::digest_value(&json!({"\u{FF61}": 1, "\u{4E00}": 2})).is_ok());
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

/// Well-formed JSON-RPC responses a client POSTs back to server-initiated
/// requests (#57): success (string and numeric id) and error (incl. null id).
fn wellformed_client_responses() -> Vec<(&'static str, String)> {
    vec![
        (
            "roots/list result, numeric id",
            json!({"jsonrpc": "2.0", "id": 3, "result": {"roots": [{"uri": "file:///repo", "name": "repo"}]}})
                .to_string(),
        ),
        (
            "sampling result, string id",
            json!({"jsonrpc": "2.0", "id": "s-1", "result": {"role": "assistant", "content": {"type": "text", "text": "ok"}, "model": "m"}})
                .to_string(),
        ),
        (
            "elicitation decline as error",
            json!({"jsonrpc": "2.0", "id": 9, "error": {"code": -32600, "message": "declined", "data": {"why": "user"}}})
                .to_string(),
        ),
        (
            "error with null id",
            json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}})
                .to_string(),
        ),
        (
            "null result",
            json!({"jsonrpc": "2.0", "id": 4, "result": null}).to_string(),
        ),
    ]
}

#[test]
fn client_jsonrpc_responses_are_forwarded_untouched_in_block_mode() {
    let (backend, mut tester) = harness!(block_config());
    for (label, body) in wellformed_client_responses() {
        let response = tester.request(typed_request("application/json", &json!({}), &body));
        assert_eq!(response.status_code(), 200, "{}", label);
        let forwarded = backend.next().expect(label);
        assert_eq!(
            forwarded.header("x-approval-binding"),
            Some("out-of-scope"),
            "{}",
            label
        );
        assert_eq!(
            forwarded.body(),
            body.as_bytes(),
            "{} body unchanged",
            label
        );
    }
}

#[test]
fn client_jsonrpc_responses_are_out_of_scope_in_monitor_mode() {
    let (backend, mut tester) = harness!(monitor_config());
    for (label, body) in wellformed_client_responses() {
        tester.request(typed_request("application/json", &json!({}), &body));
        let forwarded = backend.next().expect(label);
        assert_eq!(
            forwarded.header("x-approval-binding"),
            Some("out-of-scope"),
            "{} is out of scope, not malformed",
            label
        );
        assert_eq!(forwarded.body(), body.as_bytes(), "{}", label);
    }
}

#[test]
fn client_responses_forward_is_explicit_and_matches_the_default() {
    for config in [
        config_with(json!({"clientResponses": "forward"})),
        config_with(json!({"mode": "monitor", "clientResponses": "forward"})),
    ] {
        let (backend, mut tester) = harness!(config);
        for (label, body) in wellformed_client_responses() {
            tester.request(typed_request("application/json", &json!({}), &body));
            let forwarded = backend.next().expect(label);
            assert_eq!(
                forwarded.header("x-approval-binding"),
                Some("out-of-scope"),
                "{}",
                label
            );
            assert_eq!(forwarded.body(), body.as_bytes(), "{}", label);
        }
    }
}

#[test]
fn client_responses_deny_refuses_them_in_block_mode() {
    let (backend, mut tester) = harness!(config_with(json!({"clientResponses": "deny"})));
    for (label, body) in wellformed_client_responses() {
        let response = tester.request(typed_request("application/json", &json!({}), &body));
        assert_eq!(response.status_code(), 403, "{}", label);
        assert_eq!(
            response.header("x-approval-binding"),
            Some("denied;predicate=malformed"),
            "{}",
            label
        );
        assert!(response.body().is_empty(), "{} gets an empty 403", label);
        assert!(backend.next().is_none(), "{} is not forwarded", label);
    }
}

#[test]
fn client_responses_deny_flags_them_in_monitor_mode() {
    let (backend, mut tester) = harness!(config_with(
        json!({"mode": "monitor", "clientResponses": "deny"})
    ));
    for (label, body) in wellformed_client_responses() {
        tester.request(typed_request("application/json", &json!({}), &body));
        let forwarded = backend.next().expect(label);
        assert_eq!(
            forwarded.header("x-approval-binding"),
            Some("monitor;predicate=malformed"),
            "{}",
            label
        );
        assert_eq!(forwarded.body(), body.as_bytes(), "{}", label);
    }
}

#[test]
fn ambiguous_or_malformed_jsonrpc_responses_fail_closed() {
    let (backend, mut tester) = harness!(block_config());
    let cases = [
        (
            "both result and error",
            json!({"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": 1, "message": "x"}})
                .to_string(),
        ),
        (
            "neither result nor error",
            json!({"jsonrpc": "2.0", "id": 1}).to_string(),
        ),
        (
            "a request that also carries result",
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "result": {}}).to_string(),
        ),
        (
            "a tools/call that also carries error",
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t"}, "error": {"code": 1, "message": "x"}})
                .to_string(),
        ),
        (
            "duplicate result member",
            r#"{"jsonrpc":"2.0","id":1,"result":{},"result":{"x":1}}"#.to_string(),
        ),
        (
            "duplicate id member",
            r#"{"jsonrpc":"2.0","id":1,"id":2,"result":{}}"#.to_string(),
        ),
        (
            "missing jsonrpc",
            json!({"id": 1, "result": {}}).to_string(),
        ),
        (
            "wrong jsonrpc version",
            json!({"jsonrpc": "1.0", "id": 1, "result": {}}).to_string(),
        ),
        (
            "missing id",
            json!({"jsonrpc": "2.0", "result": {}}).to_string(),
        ),
        (
            "null id on a success response",
            json!({"jsonrpc": "2.0", "id": null, "result": {}}).to_string(),
        ),
        (
            "object id",
            json!({"jsonrpc": "2.0", "id": {"a": 1}, "result": {}}).to_string(),
        ),
        (
            "extra top-level member",
            json!({"jsonrpc": "2.0", "id": 1, "result": {}, "params": {"name": "t"}}).to_string(),
        ),
        (
            "error is not an object",
            json!({"jsonrpc": "2.0", "id": 1, "error": "boom"}).to_string(),
        ),
        (
            "error.code is not an integer",
            json!({"jsonrpc": "2.0", "id": 1, "error": {"code": 1.5, "message": "x"}}).to_string(),
        ),
        (
            "error.code missing",
            json!({"jsonrpc": "2.0", "id": 1, "error": {"message": "x"}}).to_string(),
        ),
        (
            "error.message is not a string",
            json!({"jsonrpc": "2.0", "id": 1, "error": {"code": 1, "message": 7}}).to_string(),
        ),
        (
            "non-string method",
            json!({"jsonrpc": "2.0", "id": 1, "method": 5}).to_string(),
        ),
    ];
    for (label, body) in cases {
        let response = tester.request(typed_request("application/json", &json!({}), &body));
        assert_eq!(response.status_code(), 403, "{}", label);
        assert_eq!(
            response.header("x-approval-binding"),
            Some("denied;predicate=malformed"),
            "{}",
            label
        );
        assert!(backend.next().is_none(), "{}", label);
    }
}

#[test]
fn batches_of_responses_still_fail_closed() {
    let (backend, mut tester) = harness!(block_config());
    let body = json!([{"jsonrpc": "2.0", "id": 1, "result": {}}]).to_string();
    let response = tester.request(typed_request("application/json", &json!({}), &body));
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=malformed"),
        "batch handling is unchanged by #57"
    );
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
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;framing=content-length")
    );
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
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;framing=content-length")
    );
    assert!(backend.next().is_none());
}

#[test]
fn no_body_at_all_fails_closed() {
    // A bodyless POST is the method a tools/call rides on, so it still fails
    // closed. (A bodyless GET is MCP transport traffic — see section L, #50.)
    let (backend, mut tester) = harness!(block_config());
    let response = tester.request(UnitHttpRequest::post());
    assert_eq!(response.status_code(), 403);
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=malformed")
    );
    assert!(backend.next().is_none());
}

#[test]
fn bodyless_lowercase_post_still_fails_closed() {
    let (backend, mut tester) = harness!(block_config());
    let response = tester.request(UnitHttpRequest::custom("post"));
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
// L. #50 — only POST is bound; MCP transport requests pass through
// ===========================================================================

#[test]
fn get_sse_stream_is_forwarded_out_of_scope_in_block_mode() {
    let (backend, mut tester) = harness!(block_config());
    let request = UnitHttpRequest::get()
        .with_header("accept", "text/event-stream")
        .with_header("mcp-session-id", "session-1")
        .with_authentication_data(auth_of(EXECUTOR));
    let response = tester.request(request);
    assert_eq!(response.status_code(), 200);
    let forwarded = backend.next().expect("GET SSE stream must reach upstream");
    assert_eq!(forwarded.header("x-approval-binding"), Some("out-of-scope"));
}

#[test]
fn delete_session_is_forwarded_out_of_scope_in_block_mode() {
    let (backend, mut tester) = harness!(block_config());
    let request = UnitHttpRequest::delete()
        .with_header("mcp-session-id", "session-1")
        .with_authentication_data(auth_of(EXECUTOR));
    let response = tester.request(request);
    assert_eq!(response.status_code(), 200);
    let forwarded = backend.next().expect("DELETE session must reach upstream");
    assert_eq!(forwarded.header("x-approval-binding"), Some("out-of-scope"));
}

#[test]
fn options_and_head_are_forwarded_out_of_scope_in_block_mode() {
    for request in [UnitHttpRequest::options(), UnitHttpRequest::head()] {
        let (backend, mut tester) = harness!(block_config());
        let response = tester.request(request);
        assert_eq!(response.status_code(), 200);
        let forwarded = backend
            .next()
            .expect("bodyless non-POST must reach upstream");
        assert_eq!(forwarded.header("x-approval-binding"), Some("out-of-scope"));
    }
}

#[test]
fn get_sse_stream_is_out_of_scope_not_malformed_in_monitor_mode() {
    let (backend, mut tester) = harness!(monitor_config());
    let response =
        tester.request(UnitHttpRequest::get().with_header("accept", "text/event-stream"));
    assert_eq!(response.status_code(), 200);
    let forwarded = backend.next().expect("monitor mode forwards");
    assert_eq!(forwarded.header("x-approval-binding"), Some("out-of-scope"));
}

#[test]
fn non_post_carrying_a_tools_call_body_is_still_bound() {
    // A non-POST that carries a body is inspected like a POST: if it is a
    // tools/call with no approval, it is still denied (fail closed).
    let (backend, mut tester) = harness!(block_config());
    let body_text = jsonrpc_call(1, "deploy.apply", json!({"replicas": 3})).to_string();
    let request = UnitHttpRequest::put()
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
fn post_without_content_length_is_a_framing_denial() {
    // Chunked / HTTP/2 POST with no declared length: not buffered, so denied —
    // stamped as framing, not as a malformed or non-tools/call request.
    let (backend, mut tester) = harness!(block_config());
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-nocl", &far_future());
    let request = UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("x-approval", envelope.to_string())
        .with_header("client_id", EXECUTOR)
        .with_body(jsonrpc_call(1, "deploy.apply", args).to_string())
        .with_authentication_data(auth_of(EXECUTOR));
    let response = tester.request(request);
    assert_eq!(response.status_code(), 403);
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;framing=content-length")
    );
    assert!(backend.next().is_none());
}

#[test]
fn post_without_content_length_is_stamped_framing_in_monitor_mode() {
    let (backend, mut tester) = harness!(monitor_config());
    let request = UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_body(jsonrpc_call(1, "deploy.apply", json!({})).to_string())
        .with_authentication_data(auth_of(EXECUTOR));
    let response = tester.request(request);
    assert_eq!(response.status_code(), 200);
    let forwarded = backend.next().expect("monitor mode forwards");
    assert_eq!(
        forwarded.header("x-approval-binding"),
        Some("monitor;framing=content-length")
    );
}

// ===========================================================================
// M. #51 — P6 nonce storage is bounded (cap = 3 under cfg(test))
// ===========================================================================

#[test]
fn nonce_store_at_capacity_fails_closed_for_p6() {
    // The P4-bounded approvals remain fresh throughout this test: once the cap
    // is reached, a fresh nonce is refused rather than growing the store.
    let (backend, mut tester) = harness!(block_config());
    let args = json!({"replicas": 3});
    let body = jsonrpc_call(1, "deploy.apply", args.clone());
    for i in 0..super::MAX_RESERVED_NONCES {
        let envelope = sound_approval("deploy.apply", &args, &format!("n-cap-{i}"), &far_future());
        let response = tester.request(request_with(&envelope, EXECUTOR, &body));
        assert_eq!(response.body(), OK_BODY, "reservation {i} is under the cap");
        assert!(backend.next().is_some());
    }
    let envelope = sound_approval("deploy.apply", &args, "n-cap-over", &far_future());
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=P6")
    );
    assert!(
        backend.next().is_none(),
        "a full nonce store must fail closed"
    );
}

#[test]
fn expired_nonces_are_swept_at_capacity() {
    // With P4 required, a nonce whose approval has expired under P4 may be
    // forgotten (replaying it is still a P4 denial), freeing room at the cap.
    let (backend, mut tester) = harness!(config_with(json!({
        "requiredPredicates": ["P1", "P2", "P4", "P5", "P6"],
        "clockSkewSeconds": 0
    })));
    let args = json!({"replicas": 3});
    let body = jsonrpc_call(1, "deploy.apply", args.clone());
    let short_lived = (chrono::Utc::now() + chrono::Duration::seconds(2))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut expiring = Vec::new();
    for i in 0..super::MAX_RESERVED_NONCES {
        let envelope = sound_approval("deploy.apply", &args, &format!("n-sweep-{i}"), &short_lived);
        let response = tester.request(request_with(&envelope, EXECUTOR, &body));
        assert_eq!(response.body(), OK_BODY, "short-lived reservation {i}");
        assert!(backend.next().is_some());
        expiring.push(envelope);
    }
    std::thread::sleep(std::time::Duration::from_millis(4100));

    let fresh = sound_approval("deploy.apply", &args, "n-sweep-fresh", &far_future());
    let response = tester.request(request_with(&fresh, EXECUTOR, &body));
    assert_eq!(response.body(), OK_BODY, "expired nonces were swept");
    assert!(backend.next().is_some());

    // A swept nonce's approval is past its deadline, so replaying it is denied
    // under P4 — the sweep never reopens a replay.
    let replay = tester.request(request_with(&expiring[0], EXECUTOR, &body));
    assert_eq!(
        replay.header("x-approval-binding"),
        Some("denied;predicate=P4")
    );
    assert!(backend.next().is_none());
}

// ===========================================================================
// N. Charset bypass — only an absent or UTF-8 charset is inspectable
// ===========================================================================

fn typed_request(content_type: &str, envelope: &Value, body_text: &str) -> UnitHttpRequest {
    UnitHttpRequest::post()
        .with_header("content-type", content_type)
        .with_header("content-length", body_text.len().to_string())
        .with_header("x-approval", envelope.to_string())
        .with_header("client_id", EXECUTOR)
        .with_body(body_text.to_string())
        .with_authentication_data(auth_of(EXECUTOR))
}

/// UTF-7 for `tools/call`: `/` is `+AC8-`. Parsed as UTF-8 this is an unknown,
/// out-of-scope method; an upstream decoding by charset reads `tools/call`.
const UTF7_TOOLS_CALL: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools+AC8-call","params":{"name":"deploy.apply","arguments":{}}}"#;

#[test]
fn utf7_charset_tools_call_is_denied_not_forwarded_out_of_scope() {
    let (backend, mut tester) = harness!(block_config());
    let response = tester.request(typed_request(
        "application/json; charset=utf-7",
        &json!({}),
        UTF7_TOOLS_CALL,
    ));
    assert_eq!(response.status_code(), 403);
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=malformed")
    );
    assert!(
        backend.next().is_none(),
        "a non-UTF-8 body must never reach upstream unapproved"
    );
}

#[test]
fn utf7_charset_is_flagged_in_monitor_mode() {
    let (backend, mut tester) = harness!(monitor_config());
    let response = tester.request(typed_request(
        "application/json; charset=UTF-7",
        &json!({}),
        UTF7_TOOLS_CALL,
    ));
    assert_eq!(response.status_code(), 200);
    let forwarded = backend.next().expect("monitor mode forwards");
    assert_eq!(
        forwarded.header("x-approval-binding"),
        Some("monitor;predicate=malformed")
    );
}

#[test]
fn any_non_utf8_charset_fails_closed() {
    let (backend, mut tester) = harness!(block_config());
    let body = jsonrpc_call(1, "deploy.apply", json!({})).to_string();
    for content_type in [
        "application/json; charset=utf-16",
        "application/json; charset=iso-8859-1",
        "application/json; charset=utf8",
        "application/json; charset=\"utf-7\"",
        "application/json; charset=",
        "application/json; charset=utf-8; charset=utf-7",
        "application/vnd.api+json; charset=us-ascii",
    ] {
        let response = tester.request(typed_request(content_type, &json!({}), &body));
        assert_eq!(
            response.header("x-approval-binding"),
            Some("denied;predicate=malformed"),
            "{}",
            content_type
        );
        assert!(backend.next().is_none(), "{}", content_type);
    }
}

#[test]
fn utf8_charset_spellings_are_inspected_and_allowed() {
    let args = json!({"replicas": 3});
    let body = jsonrpc_call(1, "deploy.apply", args.clone()).to_string();
    for (i, content_type) in [
        "application/json",
        "application/json; charset=utf-8",
        "application/json;charset=UTF-8",
        "application/json; charset = \"Utf-8\" ",
        "Application/JSON; Charset=utf-8; profile=x",
    ]
    .iter()
    .enumerate()
    {
        // Fresh harness per spelling: the test-build P6 cap is 3.
        let (backend, mut tester) = harness!(block_config());
        let envelope = sound_approval("deploy.apply", &args, &format!("n-cs-{i}"), &far_future());
        let response = tester.request(typed_request(content_type, &envelope, &body));
        assert_eq!(response.body(), OK_BODY, "{}", content_type);
        assert!(backend.next().is_some(), "{}", content_type);
    }
}

#[test]
fn bodies_serde_cannot_parse_fail_closed_not_out_of_scope() {
    // None of these may be read as an out-of-scope method and forwarded.
    let (backend, mut tester) = harness!(block_config());
    let deep = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"x","arguments":{{"a":{}1{}}}}}}}"#,
        "[".repeat(200),
        "]".repeat(200)
    );
    let cases = [
        (
            "lone surrogate",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools\ud800/call","params":{}}"#.to_string(),
        ),
        (
            "leading BOM",
            format!("\u{feff}{}", jsonrpc_call(1, "deploy.apply", json!({}))),
        ),
        ("nesting > 128", deep),
    ];
    for (label, body) in cases {
        let response = tester.request(typed_request("application/json", &json!({}), &body));
        assert_eq!(
            response.header("x-approval-binding"),
            Some("denied;predicate=malformed"),
            "{}",
            label
        );
        assert!(backend.next().is_none(), "{}", label);
    }
}

/// In-memory `DataStorage` that counts `get_keys` calls, so the tests can
/// assert the normal P6 path never lists the store (only the sweep does).
/// `unreadable` keys fail `get` with a decode error (the only `get` error
/// PDK's local storage surfaces); `hidden` keys read as absent while still
/// stored, modelling a reservation that lands between `get` and `store`.
#[derive(Default)]
struct CountingStore {
    items: std::cell::RefCell<BTreeMap<String, Value>>,
    get_keys_calls: Cell<usize>,
    fail_get_keys: bool,
    unreadable: std::cell::RefCell<std::collections::BTreeSet<String>>,
    hidden: std::cell::RefCell<std::collections::BTreeSet<String>>,
}

impl DataStorage for CountingStore {
    async fn get_keys(&self) -> Result<Vec<String>, DataStorageError> {
        self.get_keys_calls.set(self.get_keys_calls.get() + 1);
        if self.fail_get_keys {
            return Err(DataStorageError::Timeout);
        }
        Ok(self.items.borrow().keys().cloned().collect())
    }

    async fn store<T: serde::Serialize>(
        &self,
        key: &str,
        mode: &StoreMode,
        item: &T,
    ) -> Result<(), DataStorageError> {
        let mut items = self.items.borrow_mut();
        if matches!(mode, StoreMode::Absent) && items.contains_key(key) {
            return Err(DataStorageError::CasMismatch);
        }
        items.insert(key.to_string(), serde_json::to_value(item).unwrap());
        Ok(())
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<(T, String)>, DataStorageError> {
        if self.unreadable.borrow().contains(key) {
            return Err(DataStorageError::Unexpected(
                "undecodable value".to_string(),
            ));
        }
        if self.hidden.borrow().contains(key) {
            return Ok(None);
        }
        Ok(self.items.borrow().get(key).map(|value| {
            (
                serde_json::from_value(value.clone()).unwrap(),
                "0".to_string(),
            )
        }))
    }

    async fn delete(&self, key: &str) -> Result<(), DataStorageError> {
        self.items.borrow_mut().remove(key);
        Ok(())
    }

    async fn delete_all(&self) -> Result<(), DataStorageError> {
        self.items.borrow_mut().clear();
        Ok(())
    }
}

/// Drives a future whose awaits all resolve immediately (`CountingStore`).
fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("CountingStore futures never pend"),
    }
}

fn reserve(store: &CountingStore, cap: &NonceCap, nonce: &str, expiry: i64) -> &'static str {
    match ready(super::reserve_nonce(store, cap, nonce, expiry)) {
        Ok(()) => "ok",
        Err(ReserveRefusal::Replay) => "replay",
        Err(ReserveRefusal::AtCapacity) => "at-capacity",
        Err(ReserveRefusal::Unavailable) => "unavailable",
    }
}

#[test]
fn reservations_below_the_cap_never_list_keys() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    assert_eq!(reserve(&store, &cap, "n-0", NONCE_NEVER_EXPIRES), "ok");
    assert_eq!(reserve(&store, &cap, "n-0", NONCE_NEVER_EXPIRES), "replay");
    for i in 1..super::MAX_RESERVED_NONCES {
        assert_eq!(
            reserve(&store, &cap, &format!("n-{i}"), NONCE_NEVER_EXPIRES),
            "ok"
        );
    }
    assert_eq!(
        store.get_keys_calls.get(),
        0,
        "the normal path is get + store(Absent), never a listing"
    );
    assert_eq!(
        cap.since_sweep.get(),
        super::MAX_RESERVED_NONCES,
        "a replay does not count as a reservation"
    );
}

#[test]
fn sweep_runs_only_at_the_cap_and_reclaims_expired_nonces() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    let past = chrono::Utc::now().timestamp() - 10;
    // One unexpired nonce, the rest already past their P4 deadline.
    assert_eq!(reserve(&store, &cap, "keep", NONCE_NEVER_EXPIRES), "ok");
    for i in 1..super::MAX_RESERVED_NONCES {
        assert_eq!(reserve(&store, &cap, &format!("old-{i}"), past), "ok");
    }
    assert_eq!(store.get_keys_calls.get(), 0);

    assert_eq!(reserve(&store, &cap, "fresh", NONCE_NEVER_EXPIRES), "ok");
    assert_eq!(
        store.get_keys_calls.get(),
        1,
        "the cap triggers exactly one sweep"
    );
    let keys: Vec<String> = store.items.borrow().keys().cloned().collect();
    assert_eq!(keys, vec!["fresh".to_string(), "keep".to_string()]);
    assert_eq!(
        cap.since_sweep.get(),
        2,
        "the counter restarts from what remains"
    );
    assert_eq!(
        cap.full_until.get(),
        i64::MIN,
        "a sweep that leaves at least the low-water mark of headroom clears the bound"
    );
}

#[test]
fn sweep_that_frees_nothing_refuses_at_capacity() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    for i in 0..super::MAX_RESERVED_NONCES {
        assert_eq!(
            reserve(&store, &cap, &format!("n-{i}"), NONCE_NEVER_EXPIRES),
            "ok"
        );
    }
    assert_eq!(
        reserve(&store, &cap, "over", NONCE_NEVER_EXPIRES),
        "at-capacity"
    );
    assert_eq!(store.get_keys_calls.get(), 1);
    assert!(
        !store.items.borrow().contains_key("over"),
        "a refused nonce is not stored"
    );
    // Still full, and without P4 nothing ever expires: further attempts refuse
    // in O(1) without rescanning (#58).
    assert_eq!(
        reserve(&store, &cap, "over-2", NONCE_NEVER_EXPIRES),
        "at-capacity"
    );
    assert_eq!(store.get_keys_calls.get(), 1, "no P4 means no rescan");
}

#[test]
fn sweep_storage_error_fails_closed() {
    let store = CountingStore {
        fail_get_keys: true,
        ..CountingStore::default()
    };
    let cap = NonceCap::new();
    for i in 0..super::MAX_RESERVED_NONCES {
        assert_eq!(
            reserve(&store, &cap, &format!("n-{i}"), NONCE_NEVER_EXPIRES),
            "ok",
            "a failing get_keys is never reached below the cap"
        );
    }
    assert_eq!(
        reserve(&store, &cap, "over", NONCE_NEVER_EXPIRES),
        "unavailable"
    );
    assert!(!store.items.borrow().contains_key("over"));
}

/// Fills the store to the cap with nonces `n-0..` that expire at `expiry`.
fn fill_to_cap(store: &CountingStore, cap: &NonceCap, expiry: i64) {
    for i in 0..super::MAX_RESERVED_NONCES {
        assert_eq!(reserve(store, cap, &format!("n-{i}"), expiry), "ok");
    }
}

#[test]
fn replay_at_capacity_is_denied_as_replay_without_a_scan() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    fill_to_cap(&store, &cap, NONCE_NEVER_EXPIRES);
    assert_eq!(
        reserve(&store, &cap, "n-0", NONCE_NEVER_EXPIRES),
        "replay",
        "a reserved nonce is a replay, not a capacity refusal (#58)"
    );
    assert_eq!(
        store.get_keys_calls.get(),
        0,
        "the replay check is O(1): the store is never listed"
    );
}

#[test]
fn repeated_at_capacity_refusals_do_not_rescan_before_the_earliest_expiry() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    let now = chrono::Utc::now().timestamp();
    // P4-bounded nonces, none expired yet; "n-1" expires first.
    fill_to_cap(&store, &cap, now + 600);
    store
        .items
        .borrow_mut()
        .insert("n-1".to_string(), json!(now + 120));
    assert_eq!(reserve(&store, &cap, "over", now + 600), "at-capacity");
    assert_eq!(store.get_keys_calls.get(), 1);
    assert_eq!(
        cap.full_until.get(),
        now + 120,
        "the sweep remembers the earliest kept expiry"
    );
    for i in 0..10 {
        assert_eq!(
            reserve(&store, &cap, &format!("over-{i}"), now + 600),
            "at-capacity"
        );
    }
    assert_eq!(
        store.get_keys_calls.get(),
        1,
        "refusals before the earliest expiry are O(1), with no rescan"
    );
}

#[test]
fn rescan_frees_space_once_the_earliest_expiry_passes() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    let now = chrono::Utc::now().timestamp();
    fill_to_cap(&store, &cap, now + 600);
    store
        .items
        .borrow_mut()
        .insert("n-1".to_string(), json!(now + 120));
    assert_eq!(reserve(&store, &cap, "over", now + 600), "at-capacity");
    assert_eq!(store.get_keys_calls.get(), 1);

    // Advance time by 300s: shift every stored timestamp, and the remembered
    // expiry, back by the same amount, so "n-1" is now past its deadline.
    for value in store.items.borrow_mut().values_mut() {
        *value = json!(value.as_i64().unwrap() - 300);
    }
    cap.full_until.set(cap.full_until.get() - 300);

    assert_eq!(
        reserve(&store, &cap, "over", now + 600),
        "ok",
        "once the earliest expiry passes, the rescan frees space"
    );
    assert_eq!(store.get_keys_calls.get(), 2, "exactly one rescan");
    assert!(!store.items.borrow().contains_key("n-1"));
    assert_eq!(
        cap.full_until.get(),
        now + 300,
        "a sweep that leaves less than the low-water mark of headroom keeps the \
         earliest remaining expiry as the rescan bound"
    );
}

#[test]
fn sweep_below_low_water_refuses_at_the_next_cap_without_a_rescan() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    let now = chrono::Utc::now().timestamp();
    // One nonce already expired, the rest unexpired: the sweep frees one,
    // below the low-water mark.
    fill_to_cap(&store, &cap, now + 600);
    store
        .items
        .borrow_mut()
        .insert("n-1".to_string(), json!(now - 10));
    assert_eq!(reserve(&store, &cap, "a", now + 600), "ok");
    assert_eq!(store.get_keys_calls.get(), 1);
    assert_eq!(cap.full_until.get(), now + 600);
    // Back at the cap: refused in O(1) until the earliest remaining expiry.
    assert_eq!(reserve(&store, &cap, "b", now + 600), "at-capacity");
    assert_eq!(
        store.get_keys_calls.get(),
        1,
        "low-water hysteresis: no rescan after a sweep that left one slot"
    );
}

#[test]
fn low_water_is_keyed_on_headroom_not_on_slots_freed() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    let now = chrono::Utc::now().timestamp();
    // Other workers overfilled the store with expired nonces: the sweep frees
    // three (at least the low-water mark) but leaves only one slot of headroom.
    fill_to_cap(&store, &cap, now + 600);
    {
        let mut items = store.items.borrow_mut();
        items.insert("n-0".to_string(), json!(now - 10));
        items.insert("other-1".to_string(), json!(now - 10));
        items.insert("other-2".to_string(), json!(now - 10));
    }
    assert_eq!(reserve(&store, &cap, "a", now + 600), "ok");
    assert_eq!(store.get_keys_calls.get(), 1);
    assert_eq!(
        cap.full_until.get(),
        now + 600,
        "little headroom keeps the bound even though many slots were freed"
    );
    assert_eq!(reserve(&store, &cap, "b", now + 600), "at-capacity");
    assert_eq!(store.get_keys_calls.get(), 1, "no rescan for one slot");
}

#[test]
fn own_sooner_expiring_reservation_lowers_the_rescan_bound() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    let now = chrono::Utc::now().timestamp();
    fill_to_cap(&store, &cap, now + 600);
    store
        .items
        .borrow_mut()
        .insert("n-1".to_string(), json!(now - 10));
    assert_eq!(reserve(&store, &cap, "soon", now + 30), "ok");
    assert_eq!(
        cap.full_until.get(),
        now + 30,
        "the bound never outlives a nonce this worker reserved"
    );
}

#[test]
fn get_error_on_the_nonce_fails_closed() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    store.unreadable.borrow_mut().insert("n".to_string());
    assert_eq!(
        reserve(&store, &cap, "n", NONCE_NEVER_EXPIRES),
        "unavailable"
    );
    assert!(
        !store.items.borrow().contains_key("n"),
        "an unreadable nonce is not reserved"
    );
    assert_eq!(store.get_keys_calls.get(), 0);
}

#[test]
fn unreadable_kept_key_bounds_the_rescan_by_the_backoff() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    fill_to_cap(&store, &cap, NONCE_NEVER_EXPIRES);
    store.unreadable.borrow_mut().insert("n-1".to_string());
    let before = chrono::Utc::now().timestamp();
    assert_eq!(
        reserve(&store, &cap, "over", NONCE_NEVER_EXPIRES),
        "at-capacity"
    );
    let after = chrono::Utc::now().timestamp();
    assert!(
        store.items.borrow().contains_key("n-1"),
        "an unreadable key is kept and still counts"
    );
    let bound = cap.full_until.get();
    assert!(
        (before + super::UNREADABLE_RESCAN_BACKOFF_SECONDS
            ..=after + super::UNREADABLE_RESCAN_BACKOFF_SECONDS)
            .contains(&bound),
        "an unreadable key caps the bound at now + backoff, not never: {}",
        bound
    );
    // Before the backoff elapses: O(1) refusal.
    assert_eq!(
        reserve(&store, &cap, "over-2", NONCE_NEVER_EXPIRES),
        "at-capacity"
    );
    assert_eq!(store.get_keys_calls.get(), 1);
    // Once it elapses, the store is rescanned.
    cap.full_until.set(before - 1);
    assert_eq!(
        reserve(&store, &cap, "over-3", NONCE_NEVER_EXPIRES),
        "at-capacity"
    );
    assert_eq!(store.get_keys_calls.get(), 2, "rescanned after the backoff");
}

#[test]
fn reservation_racing_between_get_and_store_is_a_replay() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    // Another worker reserved "n" after our get saw it absent.
    store
        .items
        .borrow_mut()
        .insert("n".to_string(), json!(NONCE_NEVER_EXPIRES));
    store.hidden.borrow_mut().insert("n".to_string());
    assert_eq!(
        reserve(&store, &cap, "n", NONCE_NEVER_EXPIRES),
        "replay",
        "store(Absent) is authoritative: CasMismatch is a replay"
    );
    assert_eq!(cap.since_sweep.get(), 0, "a replay is not a reservation");
}

#[test]
fn without_p4_a_full_store_is_never_rescanned() {
    let store = CountingStore::default();
    let cap = NonceCap::new();
    fill_to_cap(&store, &cap, NONCE_NEVER_EXPIRES);
    for i in 0..10 {
        assert_eq!(
            reserve(&store, &cap, &format!("over-{i}"), NONCE_NEVER_EXPIRES),
            "at-capacity"
        );
    }
    assert_eq!(store.get_keys_calls.get(), 1, "one sweep, then never again");
    assert_eq!(cap.full_until.get(), NONCE_NEVER_EXPIRES);
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
fn client_responses_values_are_validated() {
    for value in ["forward", "deny", "DENY"] {
        let config = parse_config(base_config_json(json!({"clientResponses": value}))).unwrap();
        assert!(Binding::from_config(&config).is_ok(), "{}", value);
    }
    let config = parse_config(base_config_json(json!({"clientResponses": "allow"}))).unwrap();
    match Binding::from_config(&config) {
        Ok(_) => panic!("expected an unknown clientResponses to be rejected"),
        Err(err) => assert!(err.to_string().contains("clientResponses")),
    }
}

#[test]
fn jsonrpc_member_names_are_rejected_as_approval_rpc_field() {
    for field in ["jsonrpc", "id", "method", "params", "result", "error"] {
        let config = parse_config(base_config_json(
            json!({"approvalSource": "rpc-param", "approvalRpcField": field}),
        ))
        .unwrap();
        match Binding::from_config(&config) {
            Ok(_) => panic!("expected approvalRpcField={} to be rejected", field),
            Err(err) => assert!(err.to_string().contains("approvalRpcField"), "{}", field),
        }
    }
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

// ===========================================================================
// M. #52 — maximum approval lifetime (P4)
// ===========================================================================

fn approval_with_not_after(not_after: &str) -> ApprovalRecord {
    serde_json::from_value(json!({
        "scope": {"action": "deploy.apply", "arguments_digest": "d"},
        "not_after": not_after
    }))
    .expect("approval record")
}

fn at(raw: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .expect("rfc3339")
        .with_timezone(&chrono::Utc)
}

#[test]
fn max_lifetime_allows_not_after_exactly_at_the_bound() {
    // now + 3600 lifetime + 60 skew = 13:01:00; not_after equal to it is allowed.
    let approval = approval_with_not_after("2026-10-04T13:01:00Z");
    assert!(check_freshness_at(&approval, 60, Some(3600), at("2026-10-04T12:00:00Z")).is_ok());
}

#[test]
fn max_lifetime_denies_not_after_one_second_past_the_bound() {
    let approval = approval_with_not_after("2026-10-04T13:01:01Z");
    let err = check_freshness_at(&approval, 60, Some(3600), at("2026-10-04T12:00:00Z"))
        .expect_err("one second past the bound must be denied");
    assert!(err.contains("maximum lifetime"), "{}", err);
}

#[test]
fn max_lifetime_denies_sub_second_overshoot() {
    let approval = approval_with_not_after("2026-10-04T13:01:00.001Z");
    assert!(check_freshness_at(&approval, 60, Some(3600), at("2026-10-04T12:00:00Z")).is_err());
}

#[test]
fn max_lifetime_off_accepts_far_future_not_after() {
    let approval = approval_with_not_after("2036-10-04T12:00:00Z");
    assert!(check_freshness_at(&approval, 60, None, at("2026-10-04T12:00:00Z")).is_ok());
}

#[test]
fn max_lifetime_does_not_relax_expiry() {
    // The lifetime bound only adds a ceiling; an expired approval stays expired.
    let approval = approval_with_not_after("2026-10-04T11:58:59Z");
    let err = check_freshness_at(&approval, 60, Some(3600), at("2026-10-04T12:00:00Z"))
        .expect_err("expired approval");
    assert!(err.contains("expired"), "{}", err);
}

#[test]
fn far_future_approval_is_denied_for_p4_when_lifetime_is_bounded() {
    let (backend, mut tester) = harness!(config_with(json!({
        "requiredPredicates": ["P1", "P2", "P4", "P5"],
        "maxApprovalLifetimeSeconds": 300
    })));
    let args = json!({"replicas": 3});
    // far_future() is one hour out: past the 300 s + 60 s skew ceiling.
    let envelope = sound_approval("deploy.apply", &args, "n-lifetime", &far_future());
    let body = jsonrpc_call(1, "deploy.apply", args);
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(
        response.header("x-approval-binding"),
        Some("denied;predicate=P4")
    );
    assert!(backend.next().is_none());
}

#[test]
fn approval_within_lifetime_is_allowed() {
    let (backend, mut tester) = harness!(config_with(json!({
        "requiredPredicates": ["P1", "P2", "P4", "P5"],
        "maxApprovalLifetimeSeconds": 7200
    })));
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-within", &far_future());
    let body = jsonrpc_call(1, "deploy.apply", args);
    let response = tester.request(request_with(&envelope, EXECUTOR, &body));
    assert_eq!(response.status_code(), 200);
    let forwarded = backend.next().expect("within-lifetime approval forwards");
    assert_eq!(forwarded.header("x-approval-binding"), Some("allowed"));
}

#[test]
fn max_lifetime_without_p4_is_rejected() {
    let config = parse_config(base_config_json(json!({
        "requiredPredicates": ["P1"], "maxApprovalLifetimeSeconds": 300
    })))
    .unwrap();
    match Binding::from_config(&config) {
        Ok(_) => panic!("maxApprovalLifetimeSeconds without P4 must be rejected"),
        Err(err) => assert!(err.to_string().contains("P4"), "{}", err),
    }
}

#[test]
fn max_lifetime_range_is_validated() {
    for bad in [-1, MAX_APPROVAL_LIFETIME_LIMIT_SECONDS + 1] {
        let config = parse_config(base_config_json(json!({
            "requiredPredicates": ["P1", "P4"], "maxApprovalLifetimeSeconds": bad
        })))
        .unwrap();
        assert!(
            Binding::from_config(&config).is_err(),
            "{} must be rejected",
            bad
        );
    }
    for (good, expected) in [
        (0, None),
        (1, Some(1)),
        (
            MAX_APPROVAL_LIFETIME_LIMIT_SECONDS,
            Some(MAX_APPROVAL_LIFETIME_LIMIT_SECONDS),
        ),
    ] {
        let config = parse_config(base_config_json(json!({
            "requiredPredicates": ["P1", "P4"], "maxApprovalLifetimeSeconds": good
        })))
        .unwrap();
        let binding = Binding::from_config(&config).expect("in range");
        assert_eq!(binding.max_approval_lifetime_seconds, expected);
    }
    // Absent means off, and 0 is accepted without P4.
    let config = parse_config(base_config_json(json!({"maxApprovalLifetimeSeconds": 0}))).unwrap();
    assert_eq!(
        Binding::from_config(&config)
            .unwrap()
            .max_approval_lifetime_seconds,
        None
    );
    let config = parse_config(base_config_json(json!({}))).unwrap();
    assert_eq!(
        Binding::from_config(&config)
            .unwrap()
            .max_approval_lifetime_seconds,
        None
    );
}

// ===========================================================================
// N. #52 — rpc-param envelope removed before forwarding
// ===========================================================================

fn strip(body: &str) -> Option<String> {
    let root = parse_strict_json(body.as_bytes()).expect("test body must parse");
    strip_top_level_member(body.as_bytes(), &root, "approvalBinding")
        .expect("strip must succeed")
        .map(|bytes| String::from_utf8(bytes).expect("utf-8"))
}

#[test]
fn strip_removes_first_member_with_its_comma() {
    assert_eq!(
        strip(r#"{"approvalBinding":{"a":[1,"}"]},"jsonrpc":"2.0","id":1}"#).as_deref(),
        Some(r#"{"jsonrpc":"2.0","id":1}"#)
    );
}

#[test]
fn strip_removes_middle_member_with_its_comma() {
    assert_eq!(
        strip(r#"{"jsonrpc":"2.0","approvalBinding":{"x":"\"{"},"id":1}"#).as_deref(),
        Some(r#"{"jsonrpc":"2.0","id":1}"#)
    );
}

#[test]
fn strip_removes_last_member_with_the_preceding_comma() {
    assert_eq!(
        strip(r#"{"jsonrpc":"2.0","id":1,"approvalBinding":{}}"#).as_deref(),
        Some(r#"{"jsonrpc":"2.0","id":1}"#)
    );
}

#[test]
fn strip_removes_the_only_member() {
    assert_eq!(strip(r#"{"approvalBinding":null}"#).as_deref(), Some("{}"));
    assert_eq!(
        strip(" { \"approvalBinding\" : 1 } ").as_deref(),
        Some(" {  } ")
    );
}

#[test]
fn strip_handles_whitespace_around_members() {
    let body = "{\n  \"jsonrpc\" : \"2.0\" ,\n  \"approvalBinding\" : { \"k\" : [ 1 , 2 ] } ,\n  \"id\" : 1\n}";
    assert_eq!(
        strip(body).as_deref(),
        Some("{\n  \"jsonrpc\" : \"2.0\" ,\n  \"id\" : 1\n}")
    );
    let last = "{ \"id\" : 1 ,\t\"approvalBinding\" : true \n}";
    assert_eq!(strip(last).as_deref(), Some("{ \"id\" : 1 \n}"));
}

#[test]
fn strip_matches_an_escaped_key() {
    assert_eq!(
        strip(r#"{"id":1,"approval\u0042inding":{"n":1}}"#).as_deref(),
        Some(r#"{"id":1}"#)
    );
}

#[test]
fn strip_keeps_the_rest_byte_exact() {
    // Non-canonical spellings (exponent, escapes, key order) survive untouched,
    // so upstream receives exactly the argument bytes P2 checked.
    let body = r#"{"params":{"arguments":{"b":"\u00e9","a":1e2}},"approvalBinding":{},"method":"tools/call"}"#;
    assert_eq!(
        strip(body).as_deref(),
        Some(r#"{"params":{"arguments":{"b":"\u00e9","a":1e2}},"method":"tools/call"}"#)
    );
}

#[test]
fn strip_ignores_nested_members_of_the_same_name() {
    assert_eq!(
        strip(r#"{"params":{"approvalBinding":1},"id":1}"#),
        None,
        "only the top-level member is the envelope"
    );
}

#[test]
fn strip_returns_none_when_the_member_is_absent() {
    assert_eq!(strip(r#"{"jsonrpc":"2.0","id":1}"#), None);
    assert_eq!(strip("{}"), None);
}

#[test]
fn strip_refuses_a_non_object_body() {
    let root = parse_strict_json(b"[1]").unwrap();
    assert!(strip_top_level_member(b"[1]", &root, "approvalBinding").is_err());
}

#[test]
fn duplicate_envelope_members_fail_closed_before_strip() {
    // parse_strict_json rejects a duplicate member, so a body with two
    // envelopes never reaches the strip, and at most one member can match.
    let body = br#"{"approvalBinding":{},"approvalBinding":{},"id":1}"#;
    assert!(parse_strict_json(body).is_err());
}

fn rpc_param_request(body_text: &str) -> UnitHttpRequest {
    UnitHttpRequest::post()
        .with_header("content-type", "application/json")
        .with_header("content-length", body_text.len().to_string())
        .with_header("client_id", EXECUTOR)
        .with_body(body_text.to_string())
        .with_authentication_data(auth_of(EXECUTOR))
}

fn rpc_param_body(envelope: &Value, args: &Value) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","approvalBinding":{envelope},"id":1,"method":"tools/call","params":{{"name":"deploy.apply","arguments":{args}}}}}"#
    )
}

#[test]
fn allowed_rpc_param_call_forwards_without_the_envelope() {
    let (backend, mut tester) = harness!(config_with(json!({"approvalSource": "rpc-param"})));
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-strip", &far_future());
    let body = rpc_param_body(&envelope, &args);
    let response = tester.request(rpc_param_request(&body));
    assert_eq!(response.status_code(), 200);
    let forwarded = backend.next().expect("allowed call forwards");
    assert_eq!(forwarded.header("x-approval-binding"), Some("allowed"));
    let expected = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"deploy.apply","arguments":{args}}}}}"#
    );
    assert_eq!(forwarded.body(), expected.as_bytes());
    assert_eq!(forwarded.header("content-length"), None);
}

#[test]
fn monitor_forward_of_a_would_deny_also_strips_the_envelope() {
    let (backend, mut tester) = harness!(config_with(json!({
        "approvalSource": "rpc-param", "mode": "monitor"
    })));
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-strip-mon", &far_future());
    let body = rpc_param_body(&envelope, &json!({"replicas": 9}));
    tester.request(rpc_param_request(&body));
    let forwarded = backend.next().expect("monitor forwards");
    assert_eq!(
        forwarded.header("x-approval-binding"),
        Some("would-deny;predicate=P2")
    );
    let forwarded_body: Value = serde_json::from_slice(forwarded.body()).unwrap();
    assert!(forwarded_body.get("approvalBinding").is_none());
}

#[test]
fn strip_can_be_disabled() {
    let (backend, mut tester) = harness!(config_with(json!({
        "approvalSource": "rpc-param", "stripApprovalEnvelope": false
    })));
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-keep", &far_future());
    let body = rpc_param_body(&envelope, &args);
    tester.request(rpc_param_request(&body));
    let forwarded = backend.next().expect("allowed call forwards");
    assert_eq!(forwarded.body(), body.as_bytes());
}

#[test]
fn header_mode_body_is_forwarded_unchanged() {
    // approvalSource=header: a top-level member that happens to share the
    // rpc-field name is not an envelope and is not touched.
    let (backend, mut tester) = harness!(block_config());
    let args = json!({"replicas": 3});
    let envelope = sound_approval("deploy.apply", &args, "n-hdr", &far_future());
    let body = rpc_param_body(&json!({"unrelated": true}), &args);
    tester.request(raw_request(&envelope, EXECUTOR, &body));
    let forwarded = backend.next().expect("allowed call forwards");
    assert_eq!(forwarded.body(), body.as_bytes());
}

// ===========================================================================
// O. clockSkewSeconds bounded; deadlines cannot wrap; monitor strip stamp
// ===========================================================================

#[test]
fn clock_skew_outside_zero_to_one_hour_is_rejected_at_startup() {
    for bad in [-1_i64, 3_601, i64::MAX, i64::MIN] {
        let config = parse_config(base_config_json(json!({ "clockSkewSeconds": bad }))).unwrap();
        assert!(
            Binding::from_config(&config).is_err(),
            "{} must be rejected",
            bad
        );
    }
    for good in [0_i64, 1, 3_600] {
        let config = parse_config(base_config_json(json!({ "clockSkewSeconds": good }))).unwrap();
        assert_eq!(
            Binding::from_config(&config).unwrap().clock_skew_seconds,
            good
        );
    }
}

#[test]
fn clock_skew_of_one_hour_is_the_widest_p4_window() {
    let approval = approval_with_not_after("2026-10-04T12:00:00Z");
    assert!(check_freshness_at(&approval, 3_600, None, at("2026-10-04T13:00:00Z")).is_ok());
    assert!(check_freshness_at(&approval, 3_600, None, at("2026-10-04T13:00:01Z")).is_err());
}

#[test]
fn out_of_range_skew_fails_p4_closed_instead_of_disabling_it() {
    // Unreachable through from_config; pins that the arithmetic cannot be
    // pushed into "no limit" by a skew that slips past validation.
    let expired = approval_with_not_after("2000-01-01T00:00:00Z");
    for bad in [-1_i64, 3_601, i64::MAX] {
        assert!(check_freshness_at(&expired, bad, None, at("2026-10-04T12:00:00Z")).is_err());
        assert!(check_freshness_at(&expired, bad, Some(60), at("2026-10-04T12:00:00Z")).is_err());
    }
}

#[test]
fn nonce_expiry_is_not_after_plus_skew() {
    let config = parse_config(base_config_json(json!({
        "clockSkewSeconds": 60, "requiredPredicates": ["P1", "P4"]
    })))
    .unwrap();
    let binding = Binding::from_config(&config).unwrap();
    let not_after = "2026-10-04T12:00:00Z";
    assert_eq!(
        nonce_expiry(&binding, Some(not_after)),
        at(not_after).timestamp() + 60
    );
}

#[test]
fn nonce_expiry_never_wraps_into_the_past() {
    // A wrapped (negative) expiry would let the cap sweep delete a live nonce
    // and reopen a P6 replay. An unrepresentable deadline is never swept.
    let config = parse_config(base_config_json(
        json!({ "requiredPredicates": ["P1", "P4"] }),
    ))
    .unwrap();
    let mut binding = Binding::from_config(&config).unwrap();
    binding.clock_skew_seconds = i64::MAX;
    assert_eq!(
        nonce_expiry(&binding, Some("2026-10-04T12:00:00Z")),
        NONCE_NEVER_EXPIRES
    );
}

#[test]
fn monitor_strip_failure_never_claims_allowed() {
    assert_eq!(forwarded_result(None, false), "allowed");
    assert_eq!(forwarded_result(None, true), "monitor;envelope=unstripped");
    assert_eq!(
        forwarded_result(Some("P2"), false),
        "would-deny;predicate=P2"
    );
    assert_eq!(
        forwarded_result(Some("P2"), true),
        "would-deny;predicate=P2;envelope=unstripped"
    );
}

#[test]
fn rc4_p6_requires_p4_but_not_p5() {
    let invalid: Config =
        serde_json::from_str(&config_with(json!({"requiredPredicates":["P6"]}))).unwrap();
    assert!(Binding::from_config(&invalid).is_err());
    let valid: Config =
        serde_json::from_str(&config_with(json!({"requiredPredicates":["P4","P6"]}))).unwrap();
    assert!(Binding::from_config(&valid).is_ok());
}
#[test]
fn rc4_p6_without_p5_warns_at_startup() {
    let (_, mut tester) = harness!(config_with(json!({"requiredPredicates":["P4","P6"]})));
    let args = json!({"replicas":3});
    let envelope = sound_approval("deploy.apply", &args, "startup-warning", &far_future());
    assert_eq!(
        tester
            .request(request_with(
                &envelope,
                EXECUTOR,
                &jsonrpc_call(1, "deploy.apply", args)
            ))
            .status_code(),
        200
    );
    assert!(tester
        .logs()
        .iter()
        .any(|line| line.contains("Warn:") && line.contains("P6 without P5")));
}
#[test]
fn rc4_nonce_is_bounded_in_bytes_and_malformed_above_limit() {
    for nonce in ["a".repeat(128), "a".repeat(129), "é".repeat(65)] {
        let (backend, mut tester) = harness!(config_with(
            json!({"requiredPredicates":["P1","P2","P4","P5","P6"]})
        ));
        let args = json!({"replicas":3});
        let envelope = sound_approval("deploy.apply", &args, &nonce, &far_future());
        let response = tester.request(request_with(
            &envelope,
            EXECUTOR,
            &jsonrpc_call(1, "deploy.apply", args),
        ));
        if nonce.len() <= 128 {
            assert_eq!(response.body(), OK_BODY);
            assert!(backend.next().is_some());
        } else {
            assert_eq!(
                response.header("x-approval-binding"),
                Some("denied;predicate=malformed")
            );
            assert!(backend.next().is_none());
        }
    }
}
#[test]
fn rc4_nonce_namespaces_issuers_and_still_refuses_replay() {
    let other = "second-approver";
    let (backend, mut tester) = harness!(config_with(json!({
        "requiredPredicates":["P1","P2","P4","P5","P6"],
        "attesterKeys":[attester(APPROVER, APPROVER_KEY),attester(other, APPROVER_KEY)]
    })));
    let args = json!({"replicas":3});
    let body = jsonrpc_call(1, "deploy.apply", args.clone());
    let deadline = far_future();
    for (issuer, allowed) in [(APPROVER, true), (other, true), (APPROVER, false)] {
        let mut envelope = sound_approval("deploy.apply", &args, "same-nonce", &deadline);
        envelope["attestations"][0]["authority"] = json!(issuer);
        envelope["attestations"][0]["mac"] = json!(mcp_v1_mac(
            APPROVER_KEY.as_bytes(),
            issuer,
            EXECUTOR,
            "deploy.apply",
            &digest_value(&args).unwrap(),
            &deadline,
            "same-nonce"
        ));
        let response = tester.request(request_with(&envelope, EXECUTOR, &body));
        if allowed {
            assert_eq!(response.body(), OK_BODY);
            assert!(backend.next().is_some());
        } else {
            assert_eq!(
                response.header("x-approval-binding"),
                Some("denied;predicate=P6")
            );
            assert!(backend.next().is_none());
        }
    }
}
#[test]
fn rc4_header_envelope_stripping_respects_flag_in_both_modes() {
    for mode in ["block", "monitor"] {
        for strip in [true, false] {
            let (backend, mut tester) = harness!(config_with(
                json!({"requiredPredicates":["P1","P2","P4","P5","P6"],"mode":mode,"stripApprovalEnvelope":strip})
            ));
            let args = json!({"replicas":3});
            let envelope = sound_approval("deploy.apply", &args, "header-strip", &far_future());
            assert_eq!(
                tester
                    .request(request_with(
                        &envelope,
                        EXECUTOR,
                        &jsonrpc_call(1, "deploy.apply", args)
                    ))
                    .body(),
                OK_BODY
            );
            assert_eq!(
                backend.next().unwrap().header("x-approval").is_none(),
                strip
            );
        }
    }
}
#[test]
fn rc4_monitor_denial_also_strips_the_header() {
    let (backend, mut tester) = harness!(config_with(
        json!({"requiredPredicates":["P1","P2","P4","P5","P6"],"mode":"monitor"})
    ));
    let args = json!({"replicas":3});
    let envelope = sound_approval("deploy.apply", &args, "header-monitor-deny", &far_future());
    tester.request(request_with(
        &envelope,
        EXECUTOR,
        &jsonrpc_call(1, "other.action", args),
    ));
    let forwarded = backend.next().unwrap();
    assert!(forwarded
        .header("x-approval-binding")
        .unwrap()
        .contains("would-deny"));
    assert_eq!(forwarded.header("x-approval"), None);
}
#[test]
fn rc4_rewritten_body_uses_host_framing() {
    let (backend, mut tester) = harness!(config_with(
        json!({"requiredPredicates":["P1","P2","P4","P5","P6"],"approvalSource":"rpc-param"})
    ));
    let args = json!({"replicas":3});
    let envelope = sound_approval("deploy.apply", &args, "host-framing", &far_future());
    tester.request(rpc_param_request(&rpc_param_body(&envelope, &args)));
    let forwarded = backend.next().unwrap();
    assert_eq!(forwarded.header("content-length"), None);
    let body: Value = serde_json::from_slice(forwarded.body()).unwrap();
    assert!(body.get("approvalBinding").is_none());
    assert_eq!(body["params"]["arguments"], args);
}

#[test]
fn rc4_sweep_waits_through_the_boundary_second() {
    assert!(!nonce_sweep_due(100, 100));
    assert!(!nonce_sweep_due(101, 100));
    assert!(nonce_sweep_due(102, 100));
    assert!(!nonce_sweep_due(i64::MAX, i64::MAX));
}
#[test]
fn rc4_missing_admitted_length_denies_instead_of_panicking() {
    assert_eq!(
        admitted_length(None),
        Err("request body has no valid, admissible declared content-length")
    );
}
