# Limits of conclusions

- A complete receipt applies only to declared scope and criteria. It cannot prove absence of unknown vulnerabilities.
- An empty findings file cannot prove that a scanner ran or that templates executed.
- A successful process exit cannot prove target, route, authentication, or per-check coverage.
- A scanner plan is configuration, not execution evidence.
- Runner sidecars and verification probes are external attestations unless the surrounding workflow authenticates them.
- A discovered URL is not necessarily a fully tested URL. Query strings and fragments are not accepted in runner route observations; observed paths absent from declared `expected_routes` are represented by SHA-256 identifiers in receipts.
- Nuclei template selection and aggregate statistics do not prove per-template-per-target execution.
- ZAP tool-reported authentication success is weaker than an independent positive and negative control probe.
- Exact target matching may leave equivalent aliases as unknown rather than silently merging distinct scopes.
- Each artifact has a configurable per-file size limit; total input memory can still grow with the number of artifacts in one assessment.
- Artifact hashing is an integrity identifier, not a signature. Raw input files can contain secrets; only allowlisted fields are emitted, but users should still treat receipts as assessment metadata.
- Native scanner versions are not exhaustively certified. An unsupported shape is rejected rather than guessed.
