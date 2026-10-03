# Contributing

Thanks for your interest. This repository is public and its policies are security
controls, so changes are held to three rules:

- **Real behavior only.** No mock code and no fake data.
- **Evidence for runtime claims.** Every claim about runtime behavior needs evidence.
- **Nothing that identifies a deployment.** Nothing that identifies a real
  deployment is committed.

## Before you start

- **Bugs and features:** open an issue first for anything beyond a small fix, and
  describe the predicate, budget or behavior you're changing.
- **Security issues:** do **not** open a public issue. Follow [SECURITY.md](SECURITY.md).

## Local checks

Each policy is a self-contained PDK project. Run these from inside
`approval-execution-binding/` or `aggregate-risk-gate/`. They are the same checks as
the CI `policies` job:

```bash
cargo +1.89.0 fmt --check
cargo +1.89.0 clippy --lib --locked --offline -- -D warnings
cargo +1.89.0 test --lib --locked --offline
cargo +1.89.0 test --tests --no-run --locked --offline
cargo +1.89.0 build --release --target wasm32-wasip1 --locked
```

The first run needs network access to fetch dependencies; drop `--offline` for it.
The `#[pdk_test]` suites in `tests/` need Docker, and they start a real Flex Gateway
container. You need a local-mode registration for them, and it must stay untracked.

If you change `definition/gcl.yaml`, run `make build` and commit the regenerated
`src/generated/config.rs`. CI fails when the two drift apart.

## Rules for changes

- **Don't weaken a test to make it pass.** If a gate fails, fix the policy or
  report the failure. Changing what the test asserts is not a fix.
- **Fail closed.** Unparseable input, a missing identity or an unexpected storage
  result must deny. Don't add a path that forwards on error.
- **Keep the policies independent.** They must not share state or pass control
  signals to each other in headers. See [COMPOSITION.md](COMPOSITION.md).
- **Keep claims honest.**
  - Framework references (NIST, OWASP, MITRE, EU AI Act, AIUC-1) are design context,
    not certification.
  - Don't claim coverage of an asset type, protocol or deployment shape without a test
    for it.
- **Breaking changes:** a change to configuration, the result header or the denial
  format is breaking. Mark it **Breaking** in [CHANGELOG.md](CHANGELOG.md) under
  *Unreleased*.

## Real-gateway evidence

A runtime claim that local tests can't show needs a real-gateway run, recorded as
described in [docs/README.md](docs/README.md). In brief:

1. Use only disposable, explicitly authorized resources.
2. Record the wire result as observed.
3. Count a policy change as enforced only after a UI Save & Apply has deployed it.
4. Delete everything afterwards, and record how you confirmed the deletion.

## Redaction

Never commit any of these:

- org, environment, client or gateway ids
- client secrets, tokens or digest keys
- registration or certificate material
- hostnames or IP addresses

`registration.yaml`, `certificate.yaml` and `*.pem` are gitignored. Keep it that
way. In evidence files, use placeholders such as `<ANYPOINT_ORG_ID>`. Each policy's
`Cargo.toml` keeps the placeholder `group_id = "REPLACE_WITH_YOUR_ANYPOINT_ORG_ID"`.

Before every commit, scan what you've staged:

```bash
git diff --cached | rg -i \
  '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|client_secret|cloudhub\.io|\b\d{1,3}(\.\d{1,3}){3}\b'
```

The only expected match is a documented example, such as the nil UUID in
`scripts/check_exchange_metadata.py`. Look at every other match before you commit.

## Pull requests

1. Branch from `main`, and keep each pull request to one concern.
2. Fill in the pull request template: what changed, what you ran, and which evidence
   it relies on.
3. CI must pass. Pull requests from forks skip the packaging and runtime jobs because
   they need repository secrets, and a maintainer runs those before merging.
4. Add an entry to `CHANGELOG.md` under *Unreleased* for any change users will notice.

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
