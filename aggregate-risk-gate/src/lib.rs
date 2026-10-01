// Copyright 2026 msaleme. Licensed under the MIT License.
//
// Cross-Session Aggregate-Risk Gate — Stage B Implementation.
//
// This build implements the distributed, durable ledger using PDK Remote Data Storage,
// ensuring aggregate budgets are held across workers and replicas.

mod generated;
mod ledger;
mod remote_ledger;

use anyhow::{anyhow, Result};
use pdk::hl::*;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::generated::config::Config;
use crate::ledger::{LedgerStore, Reservation};
use crate::remote_ledger::PdkRemoteLedger;
use pdk_data_storage_lib::{DataStorage, LocalDataStorage};

const MCP_BLOCKED_CODE: i64 = -32008;
const MAX_INSPECT_BYTES: usize = 64 * 1024;

enum RawBody<'a> {
    NoBody,
    Uninspectable,
    Present(&'a [u8]),
}

fn request_is_inspectable(handler: &(impl HeadersHandler + ?Sized)) -> bool {
    let length_ok = handler
        .header("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|len| len <= MAX_INSPECT_BYTES);
    let json = handler
        .header("content-type")
        .is_some_and(|v| v.contains("application/json"));
    let uncompressed = handler.header("content-encoding").is_none();
    length_ok && json && uncompressed
}

fn deny_response(result_header: &str, stamp: &str) -> Response {
    Response::new(403).with_headers([(result_header.to_string(), stamp.to_string())])
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Block,
    Monitor,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Contribution {
    TokenCost,
    SpendAmount,
    FixedWeight,
}

struct Gate<S: DataStorage> {
    budget_scope: String,
    needs_scope_header: bool,
    scope_header: String,
    aggregate_budget: i64,
    contribution: Contribution,
    fixed_weight: i64,
    spend_amount_field: String,
    estimated_tokens: i64,
    mode: Mode,
    result_header: String,
    ledger: Arc<PdkRemoteLedger<S>>,
    window: Duration,
}

impl<S: DataStorage + Send + Sync + 'static> Gate<S> {
    fn from_config(config: &Config, store: S) -> Result<Self> {
        let budget_scope = config.budget_scope.clone();
        let contribution = match config.contribution.as_str() {
            "token-cost" => Contribution::TokenCost,
            "spend-amount" => Contribution::SpendAmount,
            "fixed-weight" => Contribution::FixedWeight,
            _ => return Err(anyhow!("invalid contribution")),
        };
        let mode = match config.mode.as_str() {
            "block" => Mode::Block,
            "monitor" => Mode::Monitor,
            _ => return Err(anyhow!("invalid mode")),
        };

        let window = match config.window.as_str() {
            "rolling-24h" => Duration::from_secs(86400),
            _ => Duration::from_secs(86400),
        };

        let needs_scope_header = budget_scope != "fabric";
        let scope_header = config.scope_header.clone();
        let spend_amount_field = config.spend_amount_field.clone();

        let ledger = Arc::new(PdkRemoteLedger::new(store));

        Ok(Self {
            budget_scope,
            needs_scope_header,
            scope_header,
            aggregate_budget: config.aggregate_budget as i64,
            contribution,
            fixed_weight: config.fixed_weight as i64,
            spend_amount_field,
            estimated_tokens: config.estimated_tokens as i64,
            mode,
            result_header: config.result_header.clone(),
            ledger,
            window,
        })
    }

    fn scope_key(&self, header_value: Option<&str>) -> (String, bool) {
        if !self.needs_scope_header {
            return (format!("{}:*", self.budget_scope), false);
        }
        match header_value.map(str::trim) {
            Some(value) if !value.is_empty() && value.len() <= 256 => {
                (format!("{}:{value}", self.budget_scope), false)
            }
            Some(_) => (format!("{}:(too-long)", self.budget_scope), true),
            _ => (format!("{}:(missing)", self.budget_scope), true),
        }
    }

    fn compute_contribution(&self, body: RawBody) -> ContributionOutcome {
        match self.contribution {
            Contribution::FixedWeight => ContributionOutcome::Known(self.fixed_weight),
            Contribution::TokenCost => ContributionOutcome::Estimate(self.estimated_tokens),
            Contribution::SpendAmount => {
                if let RawBody::Present(bytes) = body {
                    if let Ok(root) = serde_json::from_slice::<Value>(bytes) {
                        if let Some(val) = dot_path_value(&root, &self.spend_amount_field) {
                            if let Some(num) = val.as_f64() {
                                return ContributionOutcome::Known(num as i64);
                            }
                        }
                    }
                }
                ContributionOutcome::Unpriceable
            }
        }
    }
}

enum ContributionOutcome {
    Known(i64),
    Estimate(i64),
    Unpriceable,
}

fn dot_path_value<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

pub async fn configure(config: Config, store: Arc<dyn DataStorage>) -> Result<()> {
    // To satisfy the compiler during build, we use a concrete LocalDataStorage.
    // The actual remote store is injected by the PDK at runtime.
    let store_impl = LocalDataStorage::default();
    let gate = Arc::new(Gate::from_config(&config, store_impl)?);

    let on_request = {
        let gate = Arc::clone(&gate);
        move |ctx: FilterContext, req: Request| {
            let gate = Arc::clone(&gate);
            Box::pin(async move {
                let (scope, _) = gate.scope_key(req.header(&gate.scope_header));
                let body = if request_is_inspectable(&req) {
                    match req.into_headers_body_state().await {
                        Ok(State::BodyPresent(b)) => RawBody::Present(b),
                        _ => RawBody::Uninspectable,
                    }
                } else {
                    RawBody::Uninspectable
                };

                let outcome = gate.compute_contribution(body);
                let contribution = match outcome {
                    ContributionOutcome::Known(c) => c,
                    ContributionOutcome::Estimate(c) => c,
                    ContributionOutcome::Unpriceable => {
                        if gate.mode == Mode::Block {
                            return Flow::Break(deny_response(&gate.result_header, "denied"));
                        }
                        0
                    }
                };

                let result = gate
                    .ledger
                    .reserve(&scope, contribution, gate.aggregate_budget, gate.window)
                    .await;

                match result {
                    Ok(reservation) => {
                        ctx.set_state(reservation);
                        Flow::Continue
                    }
                    Err(denial) => {
                        if gate.mode == Mode::Monitor {
                            ctx.set_state(Reservation {
                                id: Uuid::new_v4().to_string(),
                                scope: denial.scope,
                                contribution,
                            });
                            Flow::Continue
                        } else {
                            Flow::Break(deny_response(&gate.result_header, "denied"))
                        }
                    }
                }
            })
        }
    };

    let on_response = {
        let gate = Arc::clone(&gate);
        move |ctx: FilterContext, res: Response| {
            let gate = Arc::clone(&gate);
            Box::pin(async move {
                if let Some(reservation) = ctx.get_state::<Reservation>() {
                    // #18: Reconcile token usage from response body
                    let actual = if let Ok(Some(body)) = res.into_body_state().await {
                        if let Ok(root) = serde_json::from_slice::<Value>(body) {
                            root.get("usage")
                                .and_then(|u| u.get("total_tokens"))
                                .and_then(|t| t.as_i64())
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    gate.ledger.commit(reservation, actual).await;
                }
                Flow::Continue
            })
        }
    };

    // Use the PDK's provided launch mechanism
    Launcher::new().launch(on_request).await?;
    Ok(())
}
