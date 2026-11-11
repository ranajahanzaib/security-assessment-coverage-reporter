# CI integration

The [offline workflow](../.github/workflows/security-assessment-coverage-reporter-example.yml) builds Security Assessment Coverage Reporter, analyzes checked-in Nmap evidence, uploads JSON and HTML, then checks policy. The main CI also runs the intentionally incomplete three-scanner example and asserts exit code `2` without failing the overall build.

For a real pipeline, collect scanner-native artifacts and runner sidecars in a job, then run:

```sh
security-assessment-coverage-reporter validate --manifest scanreceipt.yaml --check-files
security-assessment-coverage-reporter analyze --manifest scanreceipt.yaml --out assessment-receipt.json --html assessment-receipt.html
security-assessment-coverage-reporter check --receipt assessment-receipt.json
```

Upload the receipt before the policy step so a failed assessment still leaves evidence. Protect sidecar creation and raw scanner artifacts in CI. `source: external_runner` is an attribution label, not cryptographic proof. Do not commit credentials or diagnostics.
