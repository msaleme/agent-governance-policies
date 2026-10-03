## What changed

<!-- Which policy and behavior changed, and why. Link the issue. -->

## Checks run

- [ ] `cargo +1.89.0 fmt --check` and `clippy -- -D warnings`, run in each changed policy
- [ ] `cargo +1.89.0 test --lib --locked`, with the test count stated: …
- [ ] `make build` was run and `src/generated/config.rs` committed, if `definition/gcl.yaml` changed
- [ ] The release WASM builds for `wasm32-wasip1`

## Evidence

<!-- For runtime claims: the docs/ report and evidence JSON, or "none: local only". -->

## Honesty and redaction

- [ ] No test was weakened to make it pass, and the README claims match what is tested
- [ ] `CHANGELOG.md` *Unreleased* is updated, with **Breaking** marked where it applies
- [ ] The redaction scan in CONTRIBUTING.md is clean: no ids, secrets, keys, hosts or IPs
