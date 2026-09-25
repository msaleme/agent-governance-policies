use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct AttesterKeys0Config {
    #[serde(alias = "key")]
    pub key: String,
    #[serde(alias = "kid")]
    pub kid: String,
}
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(alias = "approvalHeader")]
    pub approval_header: String,
    #[serde(alias = "approvalRpcField")]
    pub approval_rpc_field: String,
    #[serde(alias = "approvalSource")]
    pub approval_source: String,
    #[serde(alias = "attesterKeys")]
    pub attester_keys: Vec<AttesterKeys0Config>,
    #[serde(alias = "clockSkewSeconds")]
    pub clock_skew_seconds: i64,
    #[serde(default, alias = "expectedAudience")]
    pub expected_audience: String,
    #[serde(default, alias = "expectedEnvironment")]
    pub expected_environment: String,
    #[serde(default, alias = "expectedTenant")]
    pub expected_tenant: String,
    #[serde(alias = "executorHeader")]
    pub executor_header: String,
    #[serde(alias = "mode")]
    pub mode: String,
    #[serde(alias = "onDeny")]
    pub on_deny: String,
    #[serde(alias = "requiredPredicates")]
    pub required_predicates: Vec<String>,
    #[serde(alias = "resultHeader")]
    pub result_header: String,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    abi.setup()?;
    Ok(())
}
