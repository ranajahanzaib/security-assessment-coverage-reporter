# Security Assessment Coverage Reporter

**Know what your security scans actually tested.**

A pipeline can report zero vulnerabilities while authentication failed, a target was missed, or a scanner never completed. Security Assessment Coverage Reporter reads existing Nmap, OWASP ZAP, and Nuclei artifacts and evaluates the _declared assessment contract_. It produces deterministic JSON and a standalone HTML receipt. It does not run scanners or claim that an application is secure.

## Quick start

Requires Rust 1.88 or newer. Build Security Assessment Coverage Reporter from a checkout; analysis does not need network access or scanner installations.

```sh
git clone https://github.com/ranajahanzaib/security-assessment-coverage-reporter.git
cd security-assessment-coverage-reporter
cargo build --locked
cargo install --path . --locked  # optional: install the security-assessment-coverage-reporter command
cargo run -- demo --out-dir security-assessment-coverage-reporter-demo
cargo run -- analyze --manifest examples/incomplete-assessment/scanreceipt.yaml --out incomplete-receipt.json --html incomplete-receipt.html
cargo run -- check --receipt incomplete-receipt.json   # exits 2: intentionally incomplete
cargo run -- analyze --manifest examples/complete-assessment/scanreceipt.yaml --out assessment-receipt.json --html assessment-receipt.html
cargo run -- check --receipt assessment-receipt.json   # exits 0
```

The synthetic, offline example schedules three tools. Nmap supplies native port evidence; Nuclei has an explicit external stage attestation; ZAP reports no alerts but failed authentication. The resulting receipt reports zero findings and `INCOMPLETE` completeness.

```text
Tools: 3 scheduled, 2 completed, 1 incomplete, 0 unknown
Findings reported: 0
[Failed] zap-auth — AUTHENTICATION_FAILED
[Unknown] zap-active — DEPENDENCY_UNSATISFIED
CI policy: fail
```

## Commands

| Command                                                                     | Purpose                                                                                       |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | --------- | -------------------------- | ------------------------------------ |
| `init [--out PATH]`                                                         | Create a starter manifest and `evidence/` directory without overwriting an existing manifest. |
| `validate --manifest PATH [--check-files]`                                  | Validate version, IDs, references, criteria, and optionally artifact existence.               |
| `analyze --manifest PATH --out PATH [--html PATH] [--max-artifact-bytes N]` | Write a receipt even if policy will fail.                                                     |
| `explain --receipt PATH`                                                    | Explain status and remediation.                                                               |
| `check --receipt PATH`                                                      | Enforce the recorded policy decision.                                                         |
| `schema manifest                                                            | receipt                                                                                       | execution | verification [--out PATH]` | Print or write a public JSON Schema. |
| `demo [--out-dir PATH]`                                                     | Copy the bundled offline example and generate JSON/HTML.                                      |

`--help`, `--version`, `--quiet`, and `--no-color` are available. Output is plain text, so color is never needed. Exit codes: `0` command succeeded or policy passed; `2` policy failed; `3` invalid input or I/O error. Analysis and policy enforcement are separate.

## Assessment contract

A manifest declares scope, scanner runs, artifacts, required checks, and policy. For example:

```yaml
schema_version: 1
assessment: { id: network-ci, name: Network CI }
scope:
  - { id: server, kind: ip, value: 192.0.2.10 }
runs:
  - id: nmap-server
    tool: nmap
    scope_ids: [server]
    artifacts:
      - { kind: report, path: evidence/nmap.xml }
checks:
  - id: expected-ports
    run_id: nmap-server
    kind: tcp_port_scan
    criteria: { ports: "22,80,443" }
policy: { on_incomplete: fail, on_inconclusive: fail, on_findings: ignore }
```

A receipt includes check status, stable reason code, artifact SHA-256 hashes, evidence IDs, limitations and suggested actions. The standalone HTML file embeds its CSS and requires no server or external assets.

## Supported evidence

- **Nmap:** XML `nmaprun`, TCP `scaninfo`, host status/address, explicit TCP port state, and `runstats/finished` exit. A down host does not establish port checks; aggregate `extraports` is not assigned to individual ports.
- **ZAP:** Traditional JSON and JSON Plus `site`/`alerts`, Automation Framework errors, and Authentication Report `summaryItems` `auth.summary.auth`. Tool-reported authentication success is distinct from independent positive verification.
- **Nuclei:** JSONL finding count and observed finding hosts. Empty findings and statistics do not establish template execution. A versioned external runner sidecar can attest a selected template set, target set, and stage outcome under the declared contract.

External sidecars are **attestations**, not cryptographic proof of origin. A successful exit only establishes process completion. See [scanner support](docs/scanner-support.md), [evidence model](docs/evidence-model.md), [reason codes](docs/reason-codes.md), and [limitations](docs/limitations.md).

## CI and safety

The [offline example workflow](.github/workflows/security-assessment-coverage-reporter-example.yml) builds the CLI, analyzes checked-in evidence, uploads JSON/HTML, then enforces policy. No scanner installations, credentials, Docker, or network scanning are needed. Findings policy is separate from completeness policy.

Input artifacts are bounded to 16 MiB each by default; `--max-artifact-bytes` allows a per-file limit up to 128 MiB. The reporter hashes raw artifacts but emits only allowlisted observations; it does not copy ZAP authentication diagnostics, HTTP messages, cookies, or credentials into the receipt. Keep raw artifacts and external attestations in a trusted CI workspace. HTML escapes untrusted text.

## Project

Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --locked`. See [contributing](CONTRIBUTING.md) and [security disclosure](SECURITY.md). Licensed under the [MIT License](LICENSE).
