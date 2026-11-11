# Contributing

Security Assessment Coverage Reporter is an offline assessment completeness auditor. Changes to scanner adapters must cite the native field's documented semantics and include positive and negative fixtures. Do not infer execution from zero findings, a scanner plan, or process exit alone.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

Golden receipts are intentional public contract snapshots. To regenerate one after reviewing a contract change:

```sh
cargo run -- analyze --manifest examples/incomplete-assessment/scanreceipt.yaml --out tests/golden/incomplete.json --quiet
cargo run -- analyze --manifest examples/complete-assessment/scanreceipt.yaml --out tests/golden/complete.json --quiet
cargo run -- analyze --manifest examples/complete-with-findings/scanreceipt.yaml --out tests/golden/complete-with-findings.json --quiet
```

Open an issue or pull request with the evidence semantics, compatibility scope, and any new limitations. Never commit real secrets or raw authentication diagnostics.
