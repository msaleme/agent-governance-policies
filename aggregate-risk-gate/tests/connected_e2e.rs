// Copyright (c) 2026 msaleme. Licensed under the MIT License.

//! Real-gateway validation cases 2–8 from
//! `docs/ASTRA-TASK-aggregate-risk-connected.md`. Every test drives a real
//! Flex 1.14.0 container (local mode, except cases 2c/2d, which use a
//! connected-mode registration and a control-plane API instance described by
//! `AGP_CONNECTED_FIXTURE`) and a real HTTP mock upstream. Each case
//! appends one sanitized JSON line to the file named by `AGP_E2E_EVIDENCE`
//! (no credentials, registration data or digest keys are written).
//!
//! Run, one case at a time, on a Docker daemon hosting no other PDK test:
//! `DOCKER_DEFAULT_PLATFORM=linux/amd64 AGP_E2E_EVIDENCE=/private/cases.jsonl \
//!  cargo test --test connected_e2e -- --ignored --test-threads=1 --nocapture`
//! Run the case 5 and case 2c/2d tests with `PDK_TEST_FLEX_ENV_FLEX_SERVICE_ENVOY_CONCURRENCY=1`,
//! so all calls share one worker ledger. Results are in `docs/AGGREGATE-RISK-CONNECTED-2026-10-01.md`.

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::io::Write;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;

const FLEX_PORT: Port = 8081;
const RESULT_HEADER: &str = "x-aggregate-risk-gate";

fn gate(overrides: Value) -> PolicyConfig {
    let mut config = json!({
        "budgetScope": "agent",
        "identitySource": "trusted-header",
        "identityField": "client_id",
        "scopeHeader": "x-agent-id",
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
        "resultHeader": RESULT_HEADER
    });
    for (key, value) in overrides.as_object().unwrap() {
        config[key] = value.clone();
    }
    PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(config)
        .build()
}

async fn start(policies: Vec<PolicyConfig>) -> anyhow::Result<(TestComposite, String, HttpMock)> {
    start_with_env(policies, Vec::new()).await
}

/// `start`, with extra environment variables for the Flex container.
async fn start_with_env(
    policies: Vec<PolicyConfig>,
    env: Vec<(&str, &str)>,
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
        .policies(policies)
        .build();
    let flex_config = FlexConfig::builder()
        .version("1.14.0")
        .hostname("local-flex")
        .with_api(api_config)
        .config_mounts([
            (POLICY_DIR, "custom-policies"),
            (COMMON_CONFIG_DIR, "common"),
        ])
        .env(env)
        .build();
    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;
    let flex: Flex = composite.service()?;
    let url = flex.external_url(FLEX_PORT).unwrap();
    let httpmock: HttpMock = composite.service()?;
    Ok((composite, url, httpmock))
}

fn call(id: u64) -> String {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
           "params":{"name":"get_orders","arguments":{}}})
    .to_string()
}

#[derive(Debug, Clone)]
struct Wire {
    status: u16,
    stamp: String,
    rpc_error: Option<i64>,
    at_ms: u128,
}

impl Wire {
    fn json(&self) -> Value {
        json!({"status": self.status, "stamp": self.stamp,
               "rpc_error": self.rpc_error, "at_ms": self.at_ms})
    }
}

fn epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

async fn send(
    client: &reqwest::Client,
    url: &str,
    id: u64,
    headers: &[(&str, &str)],
) -> anyhow::Result<Wire> {
    let mut request = client
        .post(url)
        .header("content-type", "application/json")
        .body(call(id));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await?;
    let status = response.status().as_u16();
    let stamp = response
        .headers()
        .get(RESULT_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = response.text().await?;
    let rpc_error = serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v["error"]["code"].as_i64());
    Ok(Wire {
        status,
        stamp,
        rpc_error,
        at_ms: epoch_ms(),
    })
}

fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?)
}

fn record(case: &str, disposition: &str, detail: Value) {
    let path = std::env::var("AGP_E2E_EVIDENCE").expect("set AGP_E2E_EVIDENCE");
    let line = json!({"case": case, "disposition": disposition, "detail": detail});
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(file, "{line}").unwrap();
}

fn flex_container() -> anyhow::Result<String> {
    let out = Command::new("docker")
        .args([
            "ps",
            "-q",
            "--filter",
            "label=CreatedBy=pdk-test",
            "--filter",
            "ancestor=mulesoft/flex-gateway:1.14.0",
        ])
        .output()?;
    let ids = String::from_utf8(out.stdout)?;
    let ids: Vec<&str> = ids.split_whitespace().collect();
    anyhow::ensure!(
        ids.len() == 1,
        "expected one pdk-test Flex container, got {ids:?}"
    );
    Ok(ids[0].to_string())
}

fn docker(args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new("docker").args(args).output()?;
    anyhow::ensure!(out.status.success(), "docker {args:?} failed");
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn ok_mock(server: &httpmock::MockServer) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.any_request();
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#);
    })
}

/// Case 2: a real authentication policy (built-in HTTP Basic Authentication,
/// which sets the authenticated principal) runs before the gate. The gate keys
/// on `principal`, so a spoofed, ever-changing scope header has no effect.
#[pdk_test]
#[ignore]
async fn case2_real_auth_policy_runs_first_and_spoofed_headers_are_ignored() -> anyhow::Result<()> {
    // A throwaway password generated per run, never recorded.
    let password: String = (0..24)
        .map(|i| (b'a' + ((epoch_ms() as u64 + i * 11) % 26) as u8) as char)
        .collect();
    let basic = PolicyConfig::builder()
        .name("http-basic-authentication-flex")
        .configuration(json!({"username": "agent-alpha", "password": password}))
        .build();
    let (_c, url, httpmock) = start(vec![
        basic,
        gate(json!({"identitySource": "authentication", "identityField": "principal"})),
    ])
    .await?;
    let server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let upstream = ok_mock(&server);
    let client = client()?;

    // (a) No credentials: the auth policy refuses before the gate runs.
    let no_creds = send(&client, &url, 1, &[]).await?;
    upstream.assert_hits(0);

    // (b) Valid credentials, a different spoofed scope header on every call.
    let auth = format!(
        "Basic {}",
        STANDARD.encode(format!("agent-alpha:{password}"))
    );
    let mut calls = Vec::new();
    for id in 1..=4u64 {
        let spoof = format!("spoofed-{id}");
        calls.push(
            send(
                &client,
                &url,
                id,
                &[("authorization", &auth), ("x-agent-id", &spoof)],
            )
            .await?,
        );
    }
    let hits = upstream.hits();

    let pass = no_creds.status == 401
        && calls[..3]
            .iter()
            .all(|w| w.status == 200 && w.rpc_error.is_none())
        && calls[3].rpc_error == Some(-32008)
        && calls.iter().all(|w| !w.stamp.contains("spoofed"))
        && hits == 3;
    record(
        "2-auth-ordering",
        if pass { "qualified" } else { "fail" },
        json!({
            "auth_policy": "http-basic-authentication-flex (Client ID Enforcement needs control-plane contracts, not available in local mode)",
            "no_credentials": no_creds.json(),
            "spoofed_calls": calls.iter().map(Wire::json).collect::<Vec<_>>(),
            "upstream_hits": hits
        }),
    );
    anyhow::ensure!(pass, "case 2 expectations not met");
    Ok(())
}

/// Case 3: with `scopeDisclosure: digest` the result header and the gateway
/// logs never carry the raw identity.
#[pdk_test]
#[ignore]
async fn case3_digest_disclosure_never_exposes_the_identity() -> anyhow::Result<()> {
    let key: String = (0..48)
        .map(|i| (b'a' + ((epoch_ms() as u64 + i * 7) % 26) as u8) as char)
        .collect();
    let identity = "broker-digest-check-7";
    let (_c, url, httpmock) = start(vec![gate(json!({
        "scopeDisclosure": "digest", "scopeDigestKey": key
    }))])
    .await?;
    let server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let _upstream = ok_mock(&server);
    let client = client()?;
    let mut calls = Vec::new();
    for id in 1..=4u64 {
        calls.push(send(&client, &url, id, &[("x-agent-id", identity)]).await?);
    }
    let logs = Command::new("docker")
        .args(["logs", &flex_container()?])
        .output()?;
    let mut all_logs = String::from_utf8_lossy(&logs.stdout).to_string();
    all_logs.push_str(&String::from_utf8_lossy(&logs.stderr));
    let in_logs = all_logs.contains(identity);
    let key_in_logs = all_logs.contains(&key);
    let in_headers = calls.iter().any(|w| w.stamp.contains(identity));
    let pass = !in_logs && !key_in_logs && !in_headers && calls[3].rpc_error == Some(-32008);
    // The stamp's scope is a keyed digest; record its shape, not the key.
    record(
        "3-digest-disclosure",
        if pass { "pass" } else { "fail" },
        json!({
            "stamps": calls.iter().map(|w| w.stamp.clone()).collect::<Vec<_>>(),
            "identity_in_headers": in_headers,
            "identity_in_gateway_logs": in_logs,
            "digest_key_in_gateway_logs": key_in_logs,
            "gateway_log_bytes": all_logs.len()
        }),
    );
    anyhow::ensure!(pass, "case 3 expectations not met");
    Ok(())
}

/// Case 4: monitor mode forwards everything and stamps the over-budget calls.
#[pdk_test]
#[ignore]
async fn case4_monitor_mode_forwards_and_stamps() -> anyhow::Result<()> {
    let (_c, url, httpmock) = start(vec![gate(json!({"mode": "monitor"}))]).await?;
    let server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let upstream = ok_mock(&server);
    let client = client()?;
    let mut calls = Vec::new();
    for id in 1..=5u64 {
        calls.push(send(&client, &url, id, &[("x-agent-id", "broker-7")]).await?);
    }
    let hits = upstream.hits();
    let pass = hits == 5
        && calls
            .iter()
            .all(|w| w.status == 200 && w.rpc_error.is_none())
        && calls[3].stamp.starts_with("monitor;")
        && calls[3].stamp.contains("total=3200/3000")
        && calls[4].stamp.contains("total=4000/3000");
    record(
        "4-monitor-mode",
        if pass { "pass" } else { "fail" },
        json!({"calls": calls.iter().map(Wire::json).collect::<Vec<_>>(), "upstream_hits": hits}),
    );
    anyhow::ensure!(pass, "case 4 expectations not met");
    Ok(())
}

/// Case 5: a slow call's reservation is reclaimed after `reservationTimeoutMs`
/// and frees budget for fast calls. Its response then settles late, or not at
/// all once its tombstone has been dropped. Tombstones are dropped lazily, when
/// a later call touches the scope, so `touch_at_ms` optionally sends one more
/// call past two TTLs before the slow response lands. D's `would-be-total`
/// shows whether the slow call was charged (3200) or not (2400).
async fn reclaim_case(
    case: &str,
    slow_ms: u64,
    touch_at_ms: Option<u64>,
    expected: &str,
    disposition_if_met: &str,
) -> anyhow::Result<()> {
    let (_c, url, httpmock) = start(vec![gate(json!({
        "reservationTimeoutMs": 1000, "aggregateBudget": 1600, "onReservationTimeout": "release"
    }))])
    .await?;
    let server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let slow = server.mock(|when, then| {
        when.header("x-slow", "1");
        then.status(200)
            .header("content-type", "application/json")
            .delay(Duration::from_millis(slow_ms))
            .body(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#);
    });
    let fast = server.mock(|when, then| {
        when.header("x-slow", "0");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#);
    });
    let fast_headers = [("x-agent-id", "broker-7"), ("x-slow", "0")];
    let client = client()?;
    let started = Instant::now();
    let slow_url = url.clone();
    let slow_client = client.clone();
    let slow_call = tokio::spawn(async move {
        send(
            &slow_client,
            &slow_url,
            1,
            &[("x-agent-id", "broker-7"), ("x-slow", "1")],
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let b = send(&client, &url, 2, &fast_headers).await?;
    let c = send(&client, &url, 3, &fast_headers).await?;
    let touch = match touch_at_ms {
        Some(at) => {
            let wait = at.saturating_sub(started.elapsed().as_millis() as u64);
            tokio::time::sleep(Duration::from_millis(wait)).await;
            Some(send(&client, &url, 5, &fast_headers).await?)
        }
        None => None,
    };
    let a = slow_call.await??;
    let elapsed = started.elapsed().as_millis();
    let d = send(&client, &url, 4, &fast_headers).await?;
    let charged = expected == "late-committed";
    let want_d = if charged {
        "would-be-total=3200"
    } else {
        "would-be-total=2400"
    };
    let pass = b.rpc_error.is_none()
        && c.rpc_error.is_none()
        && a.status == 200
        && a.stamp.ends_with(&format!("settlement={expected}"))
        && d.rpc_error == Some(-32008)
        && d.stamp.contains(want_d);
    record(
        case,
        if pass { disposition_if_met } else { "fail" },
        json!({
            "envoy_concurrency": std::env::var("PDK_TEST_FLEX_ENV_FLEX_SERVICE_ENVOY_CONCURRENCY").ok(),
            "slow_delay_ms": slow_ms, "ttl_ms": 1000, "touch_at_ms": touch_at_ms,
            "expected_settlement": expected,
            "slow": a.json(), "fast_b": b.json(), "fast_c": c.json(),
            "touch": touch.as_ref().map(Wire::json),
            "after_settlement_d": d.json(), "slow_elapsed_ms": elapsed,
            "upstream_hits": {"slow": slow.hits(), "fast": fast.hits()}
        }),
    );
    anyhow::ensure!(pass, "{case} expectations not met");
    Ok(())
}

#[pdk_test]
#[ignore]
async fn case5a_late_commit_inside_one_extra_ttl() -> anyhow::Result<()> {
    reclaim_case("5a-late-committed", 1500, None, "late-committed", "pass").await
}

/// No call touches the scope after reclaim, so the tombstone is still held
/// when the slow response lands at 2.6 s and it settles late, past two
/// timeouts. The README documents this as finding F1.
#[pdk_test]
#[ignore]
async fn case5b_untouched_tombstone_still_settles_late_after_two_ttls() -> anyhow::Result<()> {
    reclaim_case(
        "5b-untouched-tombstone",
        2600,
        None,
        "late-committed",
        "qualified",
    )
    .await
}

/// A call at 2.3 s (past two TTLs) drops the tombstone, so the slow response
/// at 3.5 s settles `not-active` and is not charged.
#[pdk_test]
#[ignore]
async fn case5c_not_active_once_a_touch_drops_the_tombstone() -> anyhow::Result<()> {
    reclaim_case("5c-not-active", 3500, Some(2300), "not-active", "pass").await
}

/// Case 6: a 60 s fixed window resets committed exposure at the next
/// epoch-aligned minute boundary.
#[pdk_test]
#[ignore]
async fn case6_fixed_window_resets_at_the_epoch_aligned_boundary() -> anyhow::Result<()> {
    let (_c, url, httpmock) = start(vec![gate(json!({"windowMs": 60000}))]).await?;
    let server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let _upstream = ok_mock(&server);
    let client = client()?;
    // Start early in a minute so all four calls land in one period.
    let into_minute = epoch_ms() % 60_000;
    if into_minute > 40_000 {
        tokio::time::sleep(Duration::from_millis((60_000 - into_minute + 1_000) as u64)).await;
    }
    let mut before = Vec::new();
    for id in 1..=4u64 {
        before.push(send(&client, &url, id, &[("x-agent-id", "broker-7")]).await?);
    }
    let boundary = (before[3].at_ms / 60_000 + 1) * 60_000;
    let wait = boundary.saturating_sub(epoch_ms()) + 1_500;
    tokio::time::sleep(Duration::from_millis(wait as u64)).await;
    let after = send(&client, &url, 5, &[("x-agent-id", "broker-7")]).await?;
    let pass = before[3].rpc_error == Some(-32008)
        && after.rpc_error.is_none()
        && after.at_ms >= boundary
        && after.stamp.contains("total=800/3000");
    record(
        "6-fixed-window",
        if pass { "pass" } else { "fail" },
        json!({
            "window_ms": 60000, "boundary_ms": boundary,
            "before": before.iter().map(Wire::json).collect::<Vec<_>>(),
            "after_boundary": after.json()
        }),
    );
    anyhow::ensure!(pass, "case 6 expectations not met");
    Ok(())
}

/// Case 7: a gateway restart resets the in-process ledger (documented).
#[pdk_test]
#[ignore]
async fn case7_restart_resets_the_ledger() -> anyhow::Result<()> {
    let (_c, url, httpmock) = start(vec![gate(json!({}))]).await?;
    let server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let _upstream = ok_mock(&server);
    let client = client()?;
    let mut before = Vec::new();
    for id in 1..=4u64 {
        before.push(send(&client, &url, id, &[("x-agent-id", "broker-7")]).await?);
    }
    let container = flex_container()?;
    docker(&["restart", &container])?;
    let port = docker(&["port", &container, &format!("{FLEX_PORT}/tcp")])?;
    let socket = port
        .lines()
        .next()
        .unwrap_or("")
        .replace("0.0.0.0", "127.0.0.1");
    let new_url = format!("http://{socket}/mcp/");
    let fresh = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let after = loop {
        match send(&fresh, &new_url, 5, &[("x-agent-id", "broker-7")]).await {
            Ok(w) if w.status == 200 => break w,
            _ if Instant::now() < deadline => tokio::time::sleep(Duration::from_secs(2)).await,
            other => anyhow::bail!("gateway not ready after restart: {other:?}"),
        }
    };
    let pass = before[3].rpc_error == Some(-32008) && after.rpc_error.is_none();
    record(
        "7-restart",
        if pass { "pass" } else { "fail" },
        json!({
            "before_restart": before.iter().map(Wire::json).collect::<Vec<_>>(),
            "after_restart": after.json(),
            "note": "expected: in-process ledger is reset by a restart (documented limitation)"
        }),
    );
    anyhow::ensure!(pass, "case 7 expectations not met");
    Ok(())
}

/// The gateway applies its config twice at startup, about 5 s apart. The second
/// apply replaces the listener and Envoy builds new wasm VMs, each with an empty
/// ledger. Waits until `applies` config applies are logged, plus 2 s for the new
/// VMs, or until `timeout`. Returns what it saw.
async fn wait_for_config_applies(
    container: &str,
    applies: u64,
    timeout: Duration,
) -> anyhow::Result<Value> {
    let started = Instant::now();
    loop {
        let counts = gateway_log_counts(container)?;
        let seen = counts["configuration_applied"].as_u64().unwrap_or(0);
        if seen >= applies || started.elapsed() >= timeout {
            if seen >= applies {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            return Ok(json!({
                "configuration_applied": seen, "reached": seen >= applies,
                "waited_ms": started.elapsed().as_millis() as u64
            }));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Envoy's worker layout inside the Flex container.
fn envoy_layout(container: &str) -> Value {
    let nproc = docker(&["exec", container, "nproc"]).unwrap_or_default();
    let envoy_args = docker(&[
        "exec",
        container,
        "sh",
        "-c",
        "ps -eo args | grep -m1 '[e]nvoy'",
    ])
    .unwrap_or_default();
    let concurrency = envoy_args
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "--concurrency")
        .map(|w| w[1].to_string());
    let processes = docker(&[
        "exec",
        container,
        "sh",
        "-c",
        "ps -e -o comm | grep -c '^envoy$' || true",
    ])
    .unwrap_or_default();
    // Envoy names its worker threads wrk:worker_N.
    let worker_threads = docker(&[
        "exec",
        container,
        "sh",
        "-c",
        "cat /proc/[0-9]*/task/*/comm 2>/dev/null | grep -c '^wrk:' || true",
    ])
    .unwrap_or_default();
    json!({
        "container_nproc": nproc, "envoy_concurrency_flag": concurrency,
        "envoy_processes": processes, "envoy_worker_threads": worker_threads
    })
}

/// Case 8 (`ledgerBackend: worker`): once the gateway has settled, fire many
/// parallel calls over separate connections and record how many the per-worker
/// ledgers admit. Observational: no fixed number asserted.
#[pdk_test]
#[ignore]
async fn case8_observe_the_per_worker_budget() -> anyhow::Result<()> {
    let (_c, url, httpmock) = start(vec![gate(json!({"ledgerBackend": "worker"}))]).await?;
    let server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let upstream = ok_mock(&server);
    let container = flex_container()?;
    let settle = wait_for_config_applies(&container, 2, Duration::from_secs(30)).await?;
    let before = gateway_log_counts(&container)?;
    let result = burst(&url, "broker-7").await?;
    let after = gateway_log_counts(&container)?;
    let hits = upstream.hits();
    record(
        "8-per-worker-budget",
        "observed",
        json!({
            "calls": BURST_CALLS, "per_worker_admit_limit": 3,
            "burst": result.to_json(), "upstream_hits": hits,
            "settle": settle, "envoy": envoy_layout(&container),
            "gateway_log_counts": {"before_burst": before, "after_burst": after}
        }),
    );
    anyhow::ensure!(
        result.other == 0 && result.admitted == hits as u64,
        "case 8 transport errors or hit mismatch"
    );
    Ok(())
}

/// Case 8b: exhaust a scope as soon as the gateway answers, wait for the
/// gateway's second startup config apply, then call the same scope again. A
/// call admitted at total=800 means the apply gave it a fresh ledger.
/// Observational: whether the burst lands before the apply depends on timing,
/// so the config-apply counts around the burst are recorded too.
#[pdk_test]
#[ignore]
async fn case8b_config_apply_resets_the_ledger() -> anyhow::Result<()> {
    let (_c, url, httpmock) = start(vec![gate(json!({"ledgerBackend": "worker"}))]).await?;
    let server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let _upstream = ok_mock(&server);
    let container = flex_container()?;
    let before = gateway_log_counts(&container)?;
    let exhaust = burst(&url, "broker-7").await?;
    let after_exhaust = gateway_log_counts(&container)?;
    let settle = wait_for_config_applies(&container, 2, Duration::from_secs(30)).await?;
    // Sequential calls on one connection, which Envoy pins to one worker.
    let c = client()?;
    let mut probe = Vec::new();
    for id in 1..=4 {
        let w = send(&c, &url, 1000 + id, &[("x-agent-id", "broker-7")]).await?;
        probe.push(json!({"status": w.status, "rpc_error": w.rpc_error, "stamp": w.stamp}));
    }
    let reset_observed = probe
        .iter()
        .any(|w| w["stamp"].as_str().unwrap_or("").contains("total=800/"));
    record(
        "8b-config-apply-resets-ledger",
        "observed",
        json!({
            "exhaust_burst": exhaust.to_json(),
            "applies_before_exhaust": before["configuration_applied"],
            "applies_after_exhaust": after_exhaust["configuration_applied"],
            "settle": settle, "probe_same_scope": probe, "reset_observed": reset_observed,
            "envoy": envoy_layout(&container)
        }),
    );
    anyhow::ensure!(exhaust.other == 0, "case 8b transport errors");
    Ok(())
}

/// Case 8n (`ledgerBackend: node`): the same burst as case 8, on four Envoy
/// workers. The node ledger is one budget for the replica, so exactly
/// `3000 / 800 = 3` calls are admitted however the connections spread.
#[pdk_test]
#[ignore]
async fn case8n_the_node_ledger_admits_exactly_one_budget_across_workers() -> anyhow::Result<()> {
    let (_c, url, httpmock) = start_with_env(
        vec![gate(json!({"ledgerBackend": "node"}))],
        vec![("FLEX_SERVICE_ENVOY_CONCURRENCY", "4")],
    )
    .await?;
    let server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let upstream = ok_mock(&server);
    let container = flex_container()?;
    let settle = wait_for_config_applies(&container, 2, Duration::from_secs(30)).await?;
    let result = burst(&url, "broker-7").await?;
    let hits = upstream.hits();
    let envoy = envoy_layout(&container);
    let pass =
        result.admitted == 3 && result.refused == BURST_CALLS - 3 && result.other == 0 && hits == 3;
    record(
        "8n-node-ledger-one-budget",
        if pass { "pass" } else { "fail" },
        json!({
            "calls": BURST_CALLS, "expected_admitted": 3,
            "burst": result.to_json(), "upstream_hits": hits,
            "settle": settle, "envoy": envoy
        }),
    );
    anyhow::ensure!(
        pass,
        "case 8n: admitted {} refused {} other {} hits {}",
        result.admitted,
        result.refused,
        result.other,
        hits
    );
    Ok(())
}

/// Case 8nb (`ledgerBackend: node`): exhaust a scope as soon as the gateway
/// answers, wait for the second startup config apply (which rebuilds the wasm
/// VMs), then call the same scope again. The node ledger lives in the
/// gateway's shared data, outside the VMs, so the scope should stay exhausted.
/// Observational: whether the burst lands before the apply depends on timing,
/// so the config-apply counts around the burst are recorded too.
#[pdk_test]
#[ignore]
async fn case8nb_the_node_ledger_survives_a_config_apply() -> anyhow::Result<()> {
    let (_c, url, httpmock) = start_with_env(
        vec![gate(json!({"ledgerBackend": "node"}))],
        vec![("FLEX_SERVICE_ENVOY_CONCURRENCY", "4")],
    )
    .await?;
    let server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let _upstream = ok_mock(&server);
    let container = flex_container()?;
    let before = gateway_log_counts(&container)?;
    let exhaust = burst(&url, "broker-7").await?;
    let after_exhaust = gateway_log_counts(&container)?;
    let settle = wait_for_config_applies(&container, 2, Duration::from_secs(30)).await?;
    let c = client()?;
    let mut probe = Vec::new();
    for id in 1..=4 {
        let w = send(&c, &url, 1000 + id, &[("x-agent-id", "broker-7")]).await?;
        probe.push(json!({"status": w.status, "rpc_error": w.rpc_error, "stamp": w.stamp}));
    }
    let survived = probe.iter().all(|w| w["rpc_error"] == json!(-32008));
    let apply_between =
        after_exhaust["configuration_applied"].as_u64() < settle["configuration_applied"].as_u64();
    record(
        "8nb-node-ledger-survives-config-apply",
        "observed",
        json!({
            "exhaust_burst": exhaust.to_json(),
            "applies_before_exhaust": before["configuration_applied"],
            "applies_after_exhaust": after_exhaust["configuration_applied"],
            "apply_between_exhaust_and_probe": apply_between,
            "settle": settle, "probe_same_scope": probe, "ledger_survived": survived,
            "envoy": envoy_layout(&container)
        }),
    );
    anyhow::ensure!(exhaust.other == 0, "case 8nb transport errors");
    Ok(())
}

const BURST_CALLS: u64 = 200;

struct Burst {
    admitted: u64,
    refused: u64,
    other: u64,
    // Each ledger stamps its first admitted call total=800, its second 1600 and
    // its third 2400, so the count of each total is the number of ledgers that
    // reached that step.
    admitted_by_total: std::collections::BTreeMap<String, u64>,
}

impl Burst {
    fn to_json(&self) -> Value {
        json!({
            "admitted": self.admitted, "refused": self.refused, "other": self.other,
            "admitted_by_total": self.admitted_by_total
        })
    }
}

async fn burst(url: &str, agent: &'static str) -> anyhow::Result<Burst> {
    let mut handles = Vec::new();
    for id in 1..=BURST_CALLS {
        let url = url.to_string();
        handles.push(tokio::spawn(async move {
            // One client per call: a fresh connection each time, so calls can
            // land on different worker threads.
            let c = reqwest::Client::builder()
                .pool_max_idle_per_host(0)
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap();
            send(&c, &url, id, &[("x-agent-id", agent)]).await
        }));
    }
    let mut result = Burst {
        admitted: 0,
        refused: 0,
        other: 0,
        admitted_by_total: Default::default(),
    };
    for handle in handles {
        match handle.await? {
            Ok(w) if w.status == 200 && w.rpc_error.is_none() => {
                result.admitted += 1;
                let total = w
                    .stamp
                    .split(';')
                    .find_map(|f| f.strip_prefix("total="))
                    .unwrap_or("none")
                    .to_string();
                *result.admitted_by_total.entry(total).or_default() += 1;
            }
            Ok(w) if w.rpc_error == Some(-32008) => result.refused += 1,
            _ => result.other += 1,
        }
    }
    Ok(result)
}

/// Counts of gateway log lines by keyword. Only counts are recorded: the lines
/// themselves can carry addresses.
fn gateway_log_counts(container: &str) -> anyhow::Result<Value> {
    let logs = Command::new("docker").args(["logs", container]).output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&logs.stdout),
        String::from_utf8_lossy(&logs.stderr)
    );
    let count = |needle: &str| text.lines().filter(|l| l.contains(needle)).count();
    Ok(json!({
        "lines": text.lines().count(), "wasm": count("wasm"), "listener": count("listener"),
        "configuration_applied": count("Configuration applied"),
        "wasm_vms_created": count("Thread-Local Wasm created")
    }))
}

/// Waits until the config-apply count has not changed for `quiet`, or until
/// `timeout`. Returns the count it settled on.
async fn wait_for_quiet_applies(
    container: &str,
    quiet: Duration,
    timeout: Duration,
) -> anyhow::Result<Value> {
    let started = Instant::now();
    let mut seen = gateway_log_counts(container)?["configuration_applied"]
        .as_u64()
        .unwrap_or(0);
    let mut since = Instant::now();
    while since.elapsed() < quiet && started.elapsed() < timeout {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = gateway_log_counts(container)?["configuration_applied"]
            .as_u64()
            .unwrap_or(0);
        if now != seen {
            seen = now;
            since = Instant::now();
        }
    }
    Ok(json!({
        "configuration_applied": seen, "quiet": since.elapsed() >= quiet,
        "waited_ms": started.elapsed().as_millis() as u64
    }))
}

/// Private inputs for the connected cases: a mode-0600 JSON file named by
/// `AGP_CONNECTED_FIXTURE` with `registration_directory`, `route`, `client_id`
/// and `client_secret`. The operator writes `ui-save-apply-<n>.json` next to it
/// after each real UI Save & Apply. None of these values are recorded.
struct Connected {
    dir: std::path::PathBuf,
    fixture: Value,
}

impl Connected {
    fn load() -> anyhow::Result<Self> {
        let path = std::path::PathBuf::from(std::env::var("AGP_CONNECTED_FIXTURE")?);
        let fixture: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        let dir = path.parent().unwrap().to_path_buf();
        Ok(Self { dir, fixture })
    }

    fn field(&self, key: &str) -> String {
        self.fixture[key].as_str().unwrap_or_default().to_string()
    }

    fn phase(&self, phase: &str) {
        let state = json!({"phase": phase, "at_ms": epoch_ms() as u64});
        std::fs::write(self.dir.join("state.json"), state.to_string()).unwrap();
    }

    /// Waits up to 30 minutes for the operator's marker of UI Save & Apply `n`.
    async fn wait_for_save_apply(&self, n: u32) -> anyhow::Result<Value> {
        let marker = self.dir.join(format!("ui-save-apply-{n}.json"));
        let deadline = Instant::now() + Duration::from_secs(1800);
        while !marker.exists() {
            anyhow::ensure!(Instant::now() < deadline, "no UI Save & Apply {n} marker");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Ok(serde_json::from_slice(&std::fs::read(marker)?)?)
    }

    /// Removes the client id from a stamp before it is recorded.
    fn scrub(&self, stamp: &str) -> String {
        stamp.replace(&self.field("client_id"), "<client_id>")
    }
}

/// Case 2c: the same ordering as case 2, with real Client ID Enforcement on a
/// connected gateway. The API, its Client ID Enforcement → gate chain and an
/// approved contract are configured in the control plane, and the gateway gets
/// them only after a real UI Save & Apply. The gate keys on the verified
/// `client_id`, so a spoofed, ever-changing `x-agent-id` has no effect.
///
/// Then, with the client's budget exhausted, a second UI Save & Apply is made
/// and the same client calls again. Admitted at total=800 means that Save &
/// Apply gave it a fresh ledger (finding F4). Run with
/// `PDK_TEST_FLEX_ENV_FLEX_SERVICE_ENVOY_CONCURRENCY=1`, so there is one ledger.
#[pdk_test]
#[ignore]
async fn case2c_client_id_enforcement_on_a_connected_gateway() -> anyhow::Result<()> {
    let ctx = Connected::load()?;
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();
    let registration = ctx.field("registration_directory");
    let flex_config = FlexConfig::builder()
        .version("1.14.0")
        .hostname("connected-flex")
        .ports([FLEX_PORT])
        .config_mounts([(registration.as_str(), "registration")])
        .build();
    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;
    let flex: Flex = composite.service()?;
    let url = format!(
        "{}{}",
        flex.external_url(FLEX_PORT).unwrap(),
        ctx.field("route")
    );
    let httpmock: HttpMock = composite.service()?;
    let server = httpmock::MockServer::connect_async(httpmock.socket()).await;
    let container = flex_container()?;
    let client = client()?;
    let (id, secret) = (ctx.field("client_id"), ctx.field("client_secret"));
    let creds = |spoof: &str| -> Vec<(String, String)> {
        vec![
            ("client_id".into(), id.clone()),
            ("client_secret".into(), secret.clone()),
            ("x-agent-id".into(), spoof.into()),
        ]
    };
    let send_with = |c: &reqwest::Client, n: u64, h: Vec<(String, String)>| {
        let (c, url) = (c.clone(), url.clone());
        async move {
            let refs: Vec<(&str, &str)> = h.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
            send(&c, &url, n, &refs).await
        }
    };

    // First UI Save & Apply, then wait for enforcement (401 without
    // credentials) and for the config applies to go quiet.
    ctx.phase("awaiting-ui-save-apply-1");
    let apply1 = ctx.wait_for_save_apply(1).await?;
    let probe = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        match send(&probe, &url, 900, &[]).await {
            Ok(w) if w.status == 401 => break,
            _ if Instant::now() < deadline => tokio::time::sleep(Duration::from_secs(2)).await,
            other => anyhow::bail!("Client ID Enforcement never answered 401: {other:?}"),
        }
    }
    let settle1 = wait_for_quiet_applies(
        &container,
        Duration::from_secs(20),
        Duration::from_secs(300),
    )
    .await?;
    ctx.phase("running-case-2c");
    let upstream = ok_mock(&server);

    // (a) No credentials: Client ID Enforcement refuses before the gate runs.
    let no_creds = send(&client, &url, 1, &[]).await?;
    let hits_a = upstream.hits();

    // (b) Valid client credentials, a different spoofed scope header each call.
    let mut calls = Vec::new();
    for n in 1..=4u64 {
        calls.push(send_with(&client, n + 1, creds(&format!("spoofed-{n}"))).await?);
    }
    let hits_b = upstream.hits() - hits_a;
    let wire = |w: &Wire| {
        let mut v = w.json();
        v["stamp"] = json!(ctx.scrub(&w.stamp));
        v
    };
    let pass = no_creds.status == 401
        && hits_a == 0
        && calls[..3]
            .iter()
            .all(|w| w.status == 200 && w.rpc_error.is_none())
        && calls[3].rpc_error == Some(-32008)
        && calls
            .iter()
            .all(|w| !w.stamp.contains("spoofed") && !w.stamp.contains(&id))
        && hits_b == 3;
    record(
        "2c-client-id-enforcement-connected",
        if pass { "pass" } else { "fail" },
        json!({
            "auth_policy": "client-id-enforcement (connected, approved contract)",
            "gate_identity": "authentication/client_id",
            "ui_save_apply_1": apply1, "settle": settle1,
            "no_credentials": no_creds.json(), "upstream_hits_no_credentials": hits_a,
            "with_credentials": calls.iter().map(wire).collect::<Vec<_>>(),
            "upstream_hits_with_credentials": hits_b
        }),
    );
    anyhow::ensure!(pass, "case 2c expectations not met");

    // Second UI Save & Apply with the budget exhausted, then the same client.
    let before = gateway_log_counts(&container)?["configuration_applied"].clone();
    ctx.phase("awaiting-ui-save-apply-2");
    let apply2 = ctx.wait_for_save_apply(2).await?;
    // The apply can land after the marker: wait up to 5 minutes for a new
    // config apply, then for quiet. No new apply is a result too.
    let wait = Instant::now();
    while gateway_log_counts(&container)?["configuration_applied"] == before
        && wait.elapsed() < Duration::from_secs(300)
    {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let settle2 = wait_for_quiet_applies(
        &container,
        Duration::from_secs(20),
        Duration::from_secs(300),
    )
    .await?;
    ctx.phase("running-case-2d");
    let after = send_with(&client, 10, creds("spoofed-after")).await?;
    let reset_observed = after.rpc_error.is_none() && after.stamp.contains("total=800/");
    record(
        "2d-ui-save-apply-ledger",
        "observed",
        json!({
            "ui_save_apply_2": apply2, "applies_before": before,
            "settle": settle2, "same_client_after": wire(&after),
            "reset_observed": reset_observed
        }),
    );
    ctx.phase("done");
    Ok(())
}
