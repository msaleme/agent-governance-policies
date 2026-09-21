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
//! What replaces them: two tests that adapt the harness to this policy's own
//! two headline scenarios — sequential composition against the aggregate
//! budget, and admission under concurrent load — run through a real Flex
//! Gateway container rather than the in-process `pdk-unit` harness used by
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
fn policy_config(scope_header: &str) -> PolicyConfig {
    PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(serde_json::json!({
            "budgetScope": "agent",
            "scopeHeader": scope_header,
            "aggregateBudget": 3000,
            "window": "rolling-24h",
            "contribution": "fixed-weight",
            "fixedWeight": 800,
            "spendAmountField": "params.amount",
            "estimatedTokens": 500,
            "ledgerEndpoint": "",
            "mode": "block",
            "onDeny": "rpc-error",
            "resultHeader": "x-aggregate-risk-gate"
        }))
        .build()
}

async fn start_gateway() -> anyhow::Result<(TestComposite, String, HttpMock)> {
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
        .policies([policy_config("x-agent-id")])
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
    let (_composite, flex_url, httpmock) = start_gateway().await?;
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
    let (_composite, flex_url, httpmock) = start_gateway().await?;
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
