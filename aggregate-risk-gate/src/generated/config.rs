use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "aggregateBudget")]
    pub aggregate_budget: i64,
    #[serde(alias = "budgetScope")]
    pub budget_scope: String,
    #[serde(alias = "contribution")]
    pub contribution: String,
    #[serde(alias = "estimatedTokens")]
    pub estimated_tokens: i64,
    #[serde(alias = "fixedWeight")]
    pub fixed_weight: i64,
    #[serde(alias = "identityField")]
    pub identity_field: String,
    #[serde(alias = "identitySource")]
    pub identity_source: String,
    #[serde(alias = "maxScopes")]
    pub max_scopes: i64,
    #[serde(alias = "mode")]
    pub mode: String,
    #[serde(alias = "onDeny")]
    pub on_deny: String,
    #[serde(alias = "reservationTimeoutMs")]
    pub reservation_timeout_ms: i64,
    #[serde(alias = "resultHeader")]
    pub result_header: String,
    #[serde(alias = "scopeDigestKey")]
    pub scope_digest_key: String,
    #[serde(alias = "scopeDisclosure")]
    pub scope_disclosure: String,
    #[serde(alias = "scopeHeader")]
    pub scope_header: String,
    #[serde(alias = "spendAmountField")]
    pub spend_amount_field: String,
    #[serde(alias = "spendCurrency")]
    pub spend_currency: String,
    #[serde(alias = "window")]
    pub window: String,
    #[serde(alias = "windowMs")]
    pub window_ms: i64,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
