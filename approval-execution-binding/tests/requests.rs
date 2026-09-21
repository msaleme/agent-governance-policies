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
// exhaustively by the 25+ `#[cfg(test)]` unit tests in `src/lib.rs` (driven by
// the vendored ABV vectors plus hand-written edge cases) using the in-process
// `pdk_unit` harness. This file adds only what a unit-test harness cannot
// exercise: the request actually traveling through a real Flex Gateway
// container to a real upstream, end to end, in both an allow and a block-mode
// deny path. It intentionally does not repeat the unit tests' predicate-by-
// predicate coverage.
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

fn compute_mac(key: &str, scope: &serde_json::Value) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
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
            other => serde_json::to_string(other).unwrap(),
        }
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
    mac.update(&canonical(scope).into_bytes());
    mac.finalize()
        .into_bytes()
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
        "attesterKeys": [{"kid": "approver.example", "key": "abv/approver"}],
        "clockSkewSeconds": 60,
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
        .configuration(approval_policy_config(&["P1", "P2", "P5"]))
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
    let mac = compute_mac(
        "abv/approver",
        &serde_json::json!({"action": "deploy.apply", "arguments_digest": digest}),
    );
    let envelope = serde_json::json!({
        "approval": {"scope": {"action": "deploy.apply", "arguments_digest": digest}, "nonce": "e2e-1"},
        "attestations": [{"claim": "approval", "authority": "approver.example", "mac": mac}],
        "dereferenced": {}
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
        .configuration(approval_policy_config(&["P1", "P2", "P5"]))
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
    let mac = compute_mac(
        "abv/approver",
        &serde_json::json!({"action": "deploy.apply", "arguments_digest": digest}),
    );
    // Approved deploy.apply; executes deploy.destroy — a real P1 violation.
    let envelope = serde_json::json!({
        "approval": {"scope": {"action": "deploy.apply", "arguments_digest": digest}, "nonce": "e2e-2"},
        "attestations": [{"claim": "approval", "authority": "approver.example", "mac": mac}],
        "dereferenced": {}
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
