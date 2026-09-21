// Copyright 2026 Salesforce, Inc. All rights reserved.
// Modifications Copyright (c) 2026 msaleme. Licensed under the MIT License.

// This module contains common Rust stuff shared between test files.

// Directory where the policies implementations are stored.
pub const POLICY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/wasm32-wasip1/release");

// Directory with the common configurations for tests.
pub const COMMON_CONFIG_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/config");

// Generated implementation extension name from `cargo anypoint gcl-gen` for this policy.
pub const POLICY_NAME: &str = "aggregate-risk-gate-v1-0-impl";
