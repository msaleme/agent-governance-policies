use aggregate_risk_gate::remote_ledger::PdkRemoteLedger;
use aggregate_risk_gate::ledger::{LedgerStore, Snapshot};
use pdk::data_storage::MockDataStorage;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn budget_is_held_across_multiple_replicas() {
    let shared_store = Arc::new(MockDataStorage::new());
    
    let replica1 = PdkRemoteLedger::new(shared_store.clone());
    let replica2 = PdkRemoteLedger::new(shared_store.clone());
    let replica3 = PdkRemoteLedger::new(shared_store.clone());

    let agent_id = "broker-1";
    let budget = 1000i64;
    let contribution = 400i64;
    let window = Duration::from_secs(86400);

    // Replica 1: First call (400/1000) - ALLOWED
    let res1 = replica1.reserve(agent_id, contribution, budget, window).await;
    assert!(res1.is_ok());

    // Replica 2: Second call (800/1000) - ALLOWED
    let res2 = replica2.reserve(agent_id, contribution, budget, window).await;
    assert!(res2.is_ok());

    // Replica 3: Third call (1200/1000) - DENIED
    let res3 = replica3.reserve(agent_id, contribution, budget, window).await;
    assert!(res3.is_err());
    
    let denial = res3.unwrap_err();
    assert_eq!(denial.would_be_total, 1200);
}
