use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "aggregateBudget")]
    pub aggregate_budget: f64,
    #[serde(alias = "budgetScope")]
    pub budget_scope: String,
    #[serde(alias = "contribution")]
    pub contribution: String,
    #[serde(alias = "estimatedTokens")]
    pub estimated_tokens: f64,
    #[serde(alias = "fixedWeight")]
    pub fixed_weight: f64,
    #[serde(alias = "ledgerEndpoint")]
    pub ledger_endpoint: String,
    #[serde(alias = "mode")]
    pub mode: String,
    #[serde(alias = "onDeny")]
    pub on_deny: String,
    #[serde(alias = "resultHeader")]
    pub result_header: String,
    #[serde(alias = "scopeHeader")]
    pub scope_header: String,
    #[serde(alias = "spendAmountField")]
    pub spend_amount_field: String,
    #[serde(alias = "window")]
    pub window: String,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
