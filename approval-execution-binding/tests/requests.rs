// Copyright 2026 Salesforce, Inc. All rights reserved.
// Modifications Copyright (c) 2026 msaleme. Licensed under the MIT License.
//
// Docker/pdk_test end-to-end coverage for Approval-to-Execution Binding.
//
// Honesty note: this file is deliberately smaller than the sibling Honeytoken
// Tripwire policy's integration suite. Tripwire's suite earns its size testing
// gateway-level framing/buffering/timeout behavior (its threat model is about
// bytes arriving at all) — none of that is specific to approval binding, whose
// threat model is "is this record proof of this execution," already covered
// exhaustively by the `#[cfg(test)]` unit tests in `src/test.rs` (driven by the
// vendored ABV vectors plus hand-written edge cases) using the in-process
// `pdk_unit` harness. This file adds only what a unit-test harness cannot
// exercise: the request actually traveling through a real Flex Gateway
// container to a real upstream, end to end, in an allow (P1+P2) and a block-mode
// P1-deny path. It intentionally does not repeat the unit tests' predicate-by-
// predicate coverage.
//
// SCOPE: these two e2e tests exercise ONLY P1 (action) and P2 (canonical
// argument match) — the predicates that need no external prerequisite. P5
// (separate-attester mcp-v1 MAC over the versioned payload) requires a verified
// AuthenticationData subject from an upstream identity policy, and P6 (atomic
// single-use) requires gateway data storage; both are exercised by the in-
// process unit tests, and their FULL end-to-end validation on a real Flex
// container is handed off to Astra — see `docs/ASTRA-TASK-approval-p6-replay.md`.
//
// Running this suite requires Docker and a working `pdk-test` runtime image
// pull, and was not part of the mandated `cargo test --lib` verification gate
// for this deliverable — it is not included in the exact pass counts reported
// alongside this file.

mod common;

use httpmock::MockServer;
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};

use common::*;

const FLEX_PORT: Port = 8081;

/// A real, freshly computed (not hand-typed) digest for `{"confirm": true}` and
/// a real HMAC-SHA256 over the approval scope, using the exact same JCS +
/// SHA-256 / HMAC-SHA256 construction `src/lib.rs` uses in production. This
/// mirrors `check.py`'s reference algorithm; see `SEMANTIC-ROUTING-PLAN.md`-
/// style cross-verification notes in `README.md`.
fn compute_digest(value: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    fn canonical(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let members: Vec<String> = keys
                    .into_iter()
                    .map(|k| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(k).unwrap(),
                            canonical(&map[k])
                        )
                    })
                    .collect();
                format!("{{{}}}", members.join(","))
            }
            serde_json::Value::Array(items) => {
                format!(
                    "[{}]",
                    items.iter().map(canonical).collect::<Vec<_>>().join(",")
                )
            }
            other => serde_json::to_string(other).unwrap(),
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(canonical(value).into_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn approval_policy_config(required_predicates: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "approvalSource": "header",
        "approvalHeader": "x-approval",
        "approvalRpcField": "approvalBinding",
        "executorHeader": "client_id",
        "requiredPredicates": required_predicates,
        "attesterKeys": [],
        "clockSkewSeconds": 60,
        // Non-empty placeholders: from_config only enforces non-empty when P5 is
        // required (these e2e tests bind P1+P2 only), but the GCL marks them
        // required, so a real instance always carries them.
        "expectedAudience": "e2e-gateway",
        "expectedTenant": "e2e-tenant",
        "expectedEnvironment": "e2e",
        "mode": "block",
        "onDeny": "rpc-error",
        "resultHeader": "x-approval-binding"
    })
}

#[pdk_test]
async fn sound_approval_reaches_the_real_upstream_end_to_end() -> anyhow::Result<()> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();
    let policy_config = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(approval_policy_config(&["P1", "P2"]))
        .build();
    let api_config = ApiConfig::builder()
        .name("myApi")
        .upstream(&httpmock_config)
        .path("/mcp/")
        .port(FLEX_PORT)
        .policies([policy_config])
        .build();
    let flex_config = FlexConfig::builder()
        .version("1.14.0")
        .hostname("local-flex")
        .with_api(api_config)
        .config_mounts([
            (POLICY_DIR, "custom-policies"),
            (COMMON_CONFIG_DIR, "common"),
        ])
        .build();
    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    let flex: Flex = composite.service()?;
    let flex_url = flex.external_url(FLEX_PORT).unwrap();
    let httpmock: HttpMock = composite.service()?;
    let mock_server = MockServer::connect_async(httpmock.socket()).await;
    let upstream = mock_server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200)
                .header("content-type", "application/json")
                .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        })
        .await;

    let arguments = serde_json::json!({"confirm": true});
    let digest = compute_digest(&arguments);
    let envelope = serde_json::json!({
        "approval": {"scope": {"action": "deploy.apply", "arguments_digest": digest}, "nonce": "e2e-1"}
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let response = client
        .post(&flex_url)
        .header("content-type", "application/json")
        .header("x-approval", envelope.to_string())
        .header("client_id", "executor.example")
        .body(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "deploy.apply", "arguments": arguments}
            })
            .to_string(),
        )
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    upstream.assert_async().await;
    Ok(())
}

#[pdk_test]
async fn action_mismatch_is_denied_end_to_end_and_never_reaches_upstream() -> anyhow::Result<()> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();
    let policy_config = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(approval_policy_config(&["P1", "P2"]))
        .build();
    let api_config = ApiConfig::builder()
        .name("myApi")
        .upstream(&httpmock_config)
        .path("/mcp/")
        .port(FLEX_PORT)
        .policies([policy_config])
        .build();
    let flex_config = FlexConfig::builder()
        .version("1.14.0")
        .hostname("local-flex")
        .with_api(api_config)
        .config_mounts([
            (POLICY_DIR, "custom-policies"),
            (COMMON_CONFIG_DIR, "common"),
        ])
        .build();
    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    let flex: Flex = composite.service()?;
    let flex_url = flex.external_url(FLEX_PORT).unwrap();
    let httpmock: HttpMock = composite.service()?;
    let mock_server = MockServer::connect_async(httpmock.socket()).await;
    let upstream = mock_server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200)
                .header("content-type", "application/json")
                .body("{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}");
        })
        .await;

    let arguments = serde_json::json!({"confirm": true});
    let digest = compute_digest(&arguments);
    // Approved deploy.apply; executes deploy.destroy — a real P1 violation.
    let envelope = serde_json::json!({
        "approval": {"scope": {"action": "deploy.apply", "arguments_digest": digest}, "nonce": "e2e-2"}
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let response = client
        .post(&flex_url)
        .header("content-type", "application/json")
        .header("x-approval", envelope.to_string())
        .header("client_id", "executor.example")
        .body(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "deploy.destroy", "arguments": arguments}
            })
            .to_string(),
        )
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = serde_json::from_str(&response.text().await?)?;
    assert_eq!(body["error"]["code"], -32008);
    assert!(body["error"]["message"].as_str().unwrap().contains("P1"));
    assert_eq!(
        upstream.hits_async().await,
        0,
        "a P1-denied execution must never reach upstream"
    );
    Ok(())
}

// Connected extension; the original two composites above remain unchanged.
// Use a dedicated authorized Docker daemon: pdk-test purges its own labels.
// The fixture is private, contains fresh credentials, and must never be logged.
#[derive(serde::Deserialize)]
struct ConnectedFixture {
    registration_directory: String,
    route: String,
    client_id: String,
    client_secret: String,
    attester_key: String,
    attester: String,
    audience: String,
    tenant: String,
    environment: String,
    lifecycle_hook: String,
    evidence_path: String,
}
impl ConnectedFixture {
    fn hook(&self, action: &str, urls: &[String]) -> anyhow::Result<()> {
        let result = std::process::Command::new("python3")
            .arg(&self.lifecycle_hook)
            .arg(action)
            .args(urls)
            .output()?;
        anyhow::ensure!(result.status.success(), "private lifecycle hook failed");
        Ok(())
    }
    fn envelope(&self, nonce: &str, authority: &str, subject: &str) -> serde_json::Value {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let digest = compute_digest(&serde_json::json!({"confirm": true}));
        let expiry = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        // Default serde_json maps sort keys; these payload fields are strings.
        let payload = serde_json::json!({"v":"mcp-v1", "iss":authority,
            "aud":self.audience, "tenant":self.tenant, "env":self.environment,
            "sub":subject, "action":"deploy.apply", "arguments_digest":digest,
            "not_after":expiry, "nonce":nonce});
        let mut mac = Hmac::<Sha256>::new_from_slice(self.attester_key.as_bytes()).unwrap();
        mac.update(serde_json::to_string(&payload).unwrap().as_bytes());
        let signature: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        serde_json::json!({"approval":{"scope":{"action":"deploy.apply",
            "arguments_digest":digest}, "not_after":expiry, "nonce":nonce},
            "attestations":[{"claim":"approval", "authority":authority, "mac":signature}]})
    }
}
#[allow(clippy::too_many_arguments)]
async fn connected_probe(
    f: &ConnectedFixture,
    client: &reqwest::Client,
    mock: &MockServer,
    url: &str,
    name: &str,
    id: u64,
    envelope: &serde_json::Value,
    expected: &str,
) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::json!({"jsonrpc":"2.0", "id":id, "method":"tools/call",
        "params":{"name":"deploy.apply", "arguments":{"confirm":true}}});
    let upstream = mock
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).json_body(body.clone());
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!({"jsonrpc":"2.0", "id":id, "result":{}}));
        })
        .await;
    let at = chrono::Utc::now().to_rfc3339();
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("client_id", &f.client_id)
        .header("client_secret", &f.client_secret)
        .header("x-executor", "untrusted-header-subject")
        .header("x-approval", envelope.to_string())
        .body(body.to_string())
        .send()
        .await?;
    let status = response.status().as_u16();
    let tag = response
        .headers()
        .get("x-approval-binding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let parsed: serde_json::Value =
        serde_json::from_slice(&response.bytes().await?).unwrap_or(serde_json::Value::Null);
    let hits = upstream.hits_async().await;
    let allowed = status == 200 && parsed.get("result").is_some() && hits == 1;
    let denied = status == 200 && parsed["error"]["code"] == -32008 && hits == 0;
    let pass = if expected == "allow" {
        allowed
    } else {
        denied && tag == format!("denied;predicate={expected}")
    };
    // No response messages: self-attestation failures can contain client IDs.
    Ok(
        serde_json::json!({"case":name, "at":at, "http_status":status,
        "result_header":tag, "rpc_error_code":parsed["error"]["code"],
        "backend_hits":hits, "expected":expected, "matched_expectation":pass,
        "disposition":if allowed {"forwarded"} else if denied {"denied"} else {"unexpected"}}),
    )
}

#[pdk_test]
#[ignore = "requires authorized connected registration, deployed auth chain, and private fixture"]
async fn connected_p5_p6_identity_replay_replica_and_restart() -> anyhow::Result<()> {
    let path = std::env::var("APPROVAL_CONNECTED_FIXTURE")?;
    let f: ConnectedFixture = serde_json::from_slice(&std::fs::read(path)?)?;
    anyhow::ensure!(
        f.attester_key.len() >= 32,
        "attester key must be at least 32 bytes"
    );
    let backend = HttpMockConfig::builder()
        .hostname("backend")
        .port(80)
        .version("latest")
        .build();
    let replica = |name: &str| {
        FlexConfig::builder()
            .version("1.14.0")
            .hostname(name)
            .ports([FLEX_PORT])
            .config_mounts([(f.registration_directory.as_str(), "registration")])
            .build()
    };
    let composite = TestComposite::builder()
        .with_service(replica("approval-replica-a"))
        .with_service(replica("approval-replica-b"))
        .with_service(backend)
        .build()
        .await?;
    let a: Flex = composite.service_by_hostname("approval-replica-a")?;
    let b: Flex = composite.service_by_hostname("approval-replica-b")?;
    let urls = [
        a.external_url(FLEX_PORT).unwrap(),
        b.external_url(FLEX_PORT).unwrap(),
    ]
    .map(|url| format!("{}{}", url, f.route));
    // Hook confirms deployment push, loaded config and WASM before any assertion.
    f.hook("ready", &urls)?;
    let mock: HttpMock = composite.service()?;
    let mock = MockServer::connect_async(mock.socket()).await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let nonce = format!("connected-{}", chrono::Utc::now().timestamp_micros());
    let approval = f.envelope(&nonce, &f.attester, &f.client_id);
    let self_attested = f.envelope(&format!("{nonce}-self"), &f.client_id, &f.client_id);
    let spoofed = f.envelope(
        &format!("{nonce}-spoof"),
        &f.attester,
        "untrusted-header-subject",
    );
    let mut evidence = Vec::new();
    for (name, id, url, envelope, expected) in [
        (
            "p5_separate_attester_verified_subject",
            101,
            &urls[0],
            &approval,
            "allow",
        ),
        ("p6_same_replica_replay", 102, &urls[0], &approval, "P6"),
        // Allows below document local-store limits, not global single-use.
        // Select replicas explicitly so routing cannot mask a replay.
        (
            "p6_second_replica_replay_known_limitation",
            103,
            &urls[1],
            &approval,
            "allow",
        ),
        ("p6_second_replica_repeat", 104, &urls[1], &approval, "P6"),
        ("p5_self_attestation", 105, &urls[0], &self_attested, "P5"),
        ("p5_spoofed_header_subject", 106, &urls[0], &spoofed, "P5"),
    ] {
        evidence
            .push(connected_probe(&f, &client, &mock, url, name, id, envelope, expected).await?);
        std::fs::write(&f.evidence_path, serde_json::to_vec_pretty(&evidence)?)?;
    }
    f.hook("restart", &urls)?;
    evidence.push(
        connected_probe(
            &f,
            &client,
            &mock,
            &urls[0],
            "p6_restart_replay_known_limitation",
            107,
            &approval,
            "allow",
        )
        .await?,
    );
    std::fs::write(&f.evidence_path, serde_json::to_vec_pretty(&evidence)?)?;
    anyhow::ensure!(
        evidence.iter().all(|v| v["matched_expectation"] == true),
        "connected expectations failed; see sanitized per-case evidence"
    );
    Ok(())
}
