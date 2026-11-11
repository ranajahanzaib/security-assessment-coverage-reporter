# Evidence and attestations

Each artifact is listed with a SHA-256 digest and relative path. Evidence records carry a stable content-derived ID, run ID, category, artifact path, locator, provenance, and an allowlisted fact description. Provenance is `NATIVE_REPORT` for parsed scanner observations, `RUNNER_ATTESTATION` for external sidecars, `USER_DECLARATION` for manifest expectations, and `DERIVED` for check conclusions. Derived records list their supporting evidence IDs. A receipt does not embed raw scanner reports.

## Execution sidecar

The versioned JSON shape is in `schemas/execution.schema.json`. It includes `schema_version: 1`, `run_id`, `tool`, `source`, optional `exit_code`, `timed_out`, `started_at`, `finished_at`, `termination_reason`, and `stages[]`. A stage has `check_id`, `status`, and optional `target`, `selected_templates`, `selected_targets`, and `observed_routes`. Stages refer to declared checks in the same run. `source` is descriptive metadata, not origin authentication. The user or CI runner must protect this file.

`COMPLETED`, `PARTIAL`, `FAILED`, `TIMED_OUT`, `SKIPPED`, `UNSUPPORTED`, `NOT_RUN`, and `UNKNOWN` are check states. A completed stage is an external claim. Nuclei template set completion additionally requires a zero process exit and matching declared selected templates and targets. It does **not** prove each template executed against each target.

## Independent authentication verification

The versioned verification schema is `schemas/verification.schema.json`. A verification JSON file contains `schema_version: 1`, `run_id`, `target`, `protected_resource`, `authenticated_access`, and `unauthenticated_access`. The target must match declared scope, a protected resource must be named, the authenticated probe must gain access, and the unauthenticated control must not. No credentials or request/response bodies are accepted. This is still an external attestation unless separately authenticated.

Positive verification is stronger than ZAP's `auth.summary.auth: true`, which means authentication appeared to work. Failure in either the ZAP summary or the control probe is reported as failure. Contradictory native process evidence and runner exit evidence produce `CONFLICTING_EVIDENCE` and conservative evaluation.
