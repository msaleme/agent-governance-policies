// Copyright 2026 Salesforce, Inc. All rights reserved.
// Modifications Copyright (c) 2026 msaleme. Licensed under the MIT License.

//! Docker-based Flex Gateway integration tests.
//!
//! Scope note: end-to-end `pdk_test` runs against a real containerized Flex
//! Gateway (`docker` + the `pdk-test` harness) were explicitly OUT OF SCOPE
//! for this build's required verification gate — that gate is `cargo fmt
//! --check`, `cargo clippy --lib`, and `cargo test --lib`, none of which
//! compile or run this file. This file was inherited from the
//! `mcp-honeytoken-tripwire` template project it was cloned from, whose tests
//! here (raw-socket framing/smuggling, a custom streaming backend image,
//! gateway buffer/timeout limits, response redaction-byte assertions) are
//! specific to that policy's honeytoken-matching and body-rewriting behavior
//! and have no analog in the Aggregate Risk Gate, which never rewrites a
//! body and has no streaming-exclusion surface. Those tests were removed
//! rather than left as dead, misleading code.
//!
//! What replaces them: three tests that adapt the harness to this policy's own
//! headline scenarios — sequential composition against the aggregate budget,
//! independent per-agent budgets, and an MCP session handshake where only the
//! governed `tools/call` is budgeted — run through a real Flex Gateway
//! container rather than the in-process `pdk-unit` harness used by
//! `src/lib.rs`'s unit tests. They are not part of the enforced gate and were
//! not run in this environment (no Docker invocation was performed); anyone
//! picking this up with Docker available can run them via `make test` (which
//! also runs `cargo test --lib` first) to get real containerized coverage of
//! the same reserve-then-authorize behavior the unit tests already prove
//! in-process.

mod common;

use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};

use common::*;

const FLEX_PORT: Port = 8081;

/// The full required config surface for one scope, sharing the same
/// scenario numbers as the spec's sequential-composition example and the
/// `sequential_composition_through_the_real_filter_refuses_the_fourth_call`
/// unit test in `src/lib.rs`: a per-call contribution of 800 against an
/// aggregate budget of 3000 admits exactly 3 of 5 calls (2400 committed),
/// refusing the 4th (would-be 3200).
fn policy_config(scope_header: &str, overrides: serde_json::Value) -> PolicyConfig {
    let mut config = serde_json::json!({
        "budgetScope": "agent",
        // This test API has no authentication policy in front of the gate,
        // so it opts into a trusted header. A production chain must strip
        // and re-inject that header (see the README's identity section).
        "identitySource": "trusted-header",
        "identityField": "client_id",
        "scopeHeader": scope_header,
        "ledgerBackend": "node",
        "ledgerNamespace": "",
        "maxScopes": 10000,
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
        "resultHeader": "x-aggregate-risk-gate"
    });
    for (key, value) in overrides.as_object().unwrap() {
        config[key] = value.clone();
    }
    PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(config)
        .build()
}

async fn start_gateway(
    overrides: serde_json::Value,
) -> anyhow::Result<(TestComposite, String, HttpMock)> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();
    let api_config = ApiConfig::builder()
        .name("myApi")
        .upstream(&httpmock_config)
        .path("/mcp/")
        .port(FLEX_PORT)
        .policies([policy_config("x-agent-id", overrides)])
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
    Ok((composite, flex_url, httpmock))
}

fn call(id: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": "get_orders", "arguments": {}}
    })
    .to_string()
}

/// The sequential-composition scenario end to end through a real Flex
/// Gateway container: five 800-unit calls from the same agent against a
/// 3000-unit aggregate budget. The first three commit (running total 2400);
/// the fourth is refused in-band as a JSON-RPC -32008 error (would-be 3200);
/// the fifth is refused for the same reason.
#[pdk_test]
async fn sequential_composition_through_a_real_gateway_refuses_the_fourth_call(
) -> anyhow::Result<()> {
    let (_composite, flex_url, httpmock) = start_gateway(serde_json::json!({})).await?;
    let mock_server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let upstream = mock_server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#);
        })
        .await;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    for id in 1..=3u64 {
        let response = client
            .post(&flex_url)
            .header("content-type", "application/json")
            .header("x-agent-id", "broker-7")
            .body(call(id))
            .send()
            .await?;
        assert_eq!(response.status(), 200, "call {id} of 3 should be admitted");
    }
    upstream.assert_hits_async(3).await;

    for id in 4..=5u64 {
        let response = client
            .post(&flex_url)
            .header("content-type", "application/json")
            .header("x-agent-id", "broker-7")
            .body(call(id))
            .send()
            .await?;
        assert_eq!(
            response.status(),
            200,
            "a block-mode rpc-error denial is a JSON-RPC 200 envelope, call {id}"
        );
        let body: serde_json::Value = serde_json::from_str(&response.text().await?)?;
        assert_eq!(body["id"], id);
        assert_eq!(body["error"]["code"], -32008, "call {id} must be refused");
    }
    // The two refused calls must never reach the upstream.
    upstream.assert_hits_async(3).await;
    Ok(())
}

/// A different agent's scope key is independent of `broker-7`'s: it gets its
/// own 3000-unit budget rather than sharing (or being blocked by) the first
/// agent's exposure.
#[pdk_test]
async fn a_different_agent_has_an_independent_budget_through_a_real_gateway() -> anyhow::Result<()>
{
    let (_composite, flex_url, httpmock) = start_gateway(serde_json::json!({})).await?;
    let mock_server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let upstream = mock_server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#);
        })
        .await;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // Exhaust broker-7's budget (3 admitted, 4th refused).
    for id in 1..=3u64 {
        let response = client
            .post(&flex_url)
            .header("content-type", "application/json")
            .header("x-agent-id", "broker-7")
            .body(call(id))
            .send()
            .await?;
        assert_eq!(response.status(), 200);
    }
    let refused = client
        .post(&flex_url)
        .header("content-type", "application/json")
        .header("x-agent-id", "broker-7")
        .body(call(4))
        .send()
        .await?;
    let refused_body: serde_json::Value = serde_json::from_str(&refused.text().await?)?;
    assert_eq!(refused_body["error"]["code"], -32008);

    // broker-8's own first call must still be admitted.
    let admitted = client
        .post(&flex_url)
        .header("content-type", "application/json")
        .header("x-agent-id", "broker-8")
        .body(call(5))
        .send()
        .await?;
    assert_eq!(
        admitted.status(),
        200,
        "a different agent's scope must not inherit broker-7's exhausted budget"
    );
    let admitted_body: serde_json::Value = serde_json::from_str(&admitted.text().await?)?;
    assert_eq!(
        admitted_body["error"],
        serde_json::Value::Null,
        "broker-8's first call must be a real pass-through, not a denial"
    );
    upstream.assert_hits_async(4).await;
    Ok(())
}

fn rpc(id: Option<u64>, method: &str, params: serde_json::Value) -> String {
    let mut message = serde_json::json!({"jsonrpc": "2.0", "method": method, "params": params});
    if let Some(id) = id {
        message["id"] = id.into();
    }
    message.to_string()
}

/// An MCP session through a real Flex Gateway container under spend-amount +
/// block with the default `governedMethods: ["tools/call"]`. The lifecycle
/// traffic (`initialize`, `notifications/initialized`, `tools/list`) carries
/// no amount, yet it is forwarded untouched and stamped
/// `pass;reason=ungoverned-method`. Only `tools/call` is priced: one within
/// the 1000-minor-unit budget is admitted, then an over-budget one and one
/// with no amount are both refused in-band with -32008 and never reach the
/// upstream.
#[pdk_test]
async fn an_mcp_handshake_passes_and_only_tools_call_is_budgeted_through_a_real_gateway(
) -> anyhow::Result<()> {
    let (_composite, flex_url, httpmock) = start_gateway(serde_json::json!({
        "contribution": "spend-amount",
        "aggregateBudget": 1000
    }))
    .await?;
    let mock_server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let upstream = mock_server
        .mock_async(|when, then| {
            when.any_request();
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#);
        })
        .await;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let send = |body: String| {
        client
            .post(&flex_url)
            .header("content-type", "application/json")
            .header("x-agent-id", "broker-7")
            .body(body)
            .send()
    };

    let handshake = [
        rpc(
            Some(1),
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pdk-test", "version": "1.0.0"}
            }),
        ),
        rpc(None, "notifications/initialized", serde_json::json!({})),
        rpc(Some(2), "tools/list", serde_json::json!({})),
    ];
    for (step, body) in handshake.iter().enumerate() {
        let response = send(body.clone()).await?;
        assert_eq!(response.status(), 200, "handshake step {} must pass", step);
        assert_eq!(
            response
                .headers()
                .get("x-aggregate-risk-gate")
                .and_then(|value| value.to_str().ok()),
            Some("pass;reason=ungoverned-method"),
            "handshake step {} must be stamped as ungoverned",
            step
        );
    }
    upstream.assert_hits_async(3).await;

    let admitted = send(rpc(
        Some(3),
        "tools/call",
        serde_json::json!({"name": "place_order", "arguments": {}, "amount": 600}),
    ))
    .await?;
    assert_eq!(admitted.status(), 200);
    let admitted_header = admitted
        .headers()
        .get("x-aggregate-risk-gate")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        admitted_header.starts_with("allowed;"),
        "a within-budget tools/call must be admitted, got {}",
        admitted_header
    );
    upstream.assert_hits_async(4).await;

    let refusals = [
        rpc(
            Some(4),
            "tools/call",
            serde_json::json!({"name": "place_order", "arguments": {}, "amount": 600}),
        ),
        rpc(
            Some(5),
            "tools/call",
            serde_json::json!({"name": "place_order", "arguments": {}}),
        ),
    ];
    for (offset, body) in refusals.iter().enumerate() {
        let id = 4 + offset as u64;
        let response = send(body.clone()).await?;
        assert_eq!(
            response.status(),
            200,
            "rpc-error denial envelope, call {}",
            id
        );
        let body: serde_json::Value = serde_json::from_str(&response.text().await?)?;
        assert_eq!(body["id"], id);
        assert_eq!(body["error"]["code"], -32008, "call {} must be refused", id);
    }
    // Neither refused tools/call reached the upstream.
    upstream.assert_hits_async(4).await;
    Ok(())
}
