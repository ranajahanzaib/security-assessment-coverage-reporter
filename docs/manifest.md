# Manifest v1

Use `security-assessment-coverage-reporter schema manifest` for the exact machine-readable schema. Unknown fields are rejected. Paths are relative to the manifest directory; absolute artifact paths are rejected. Duplicate IDs and unknown scope/run/dependency references are rejected.

| Field                              | Meaning                                                                                                                                     |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `schema_version`                   | Must be `1`.                                                                                                                                |
| `assessment.id`, `assessment.name` | Stable ID and display name.                                                                                                                 |
| `scope[]`                          | Expected target `{id, kind, value}`; kind is `url`, `ip`, or `host`. Matching is exact and conservative.                                    |
| `runs[]`                           | Scanner `{id, tool, scope_ids, artifacts}`; tool is `nmap`, `zap`, or `nuclei`.                                                             |
| `artifacts[]`                      | `{kind, path}`. Kinds: `report`, `findings`, `statistics`, `execution`, `authentication`, `verification`, `plan`. One of each kind per run. |
| `checks[]`                         | `{id, run_id, kind, required, criteria, depends_on}`. `required` defaults to true.                                                          |
| `policy`                           | `on_incomplete`, `on_inconclusive`, `on_findings`: `fail` or `ignore`; defaults to completeness failures and findings ignored.              |

Check kinds: `host_discovery`, `tcp_port_scan`, `authentication`, `route_discovery`, `active_scan`, `template_scan`. Criteria: `ports` (comma-separated ports/ranges), `expected_routes` (exact path strings), `minimum_observed_routes` (positive count), `requires_positive_verification`, `expected_templates`, `expected_targets`. TCP port checks require `ports`. Template checks require declared templates and targets plus a matching external stage sidecar to complete. A plan describes intent; it never establishes execution.

See [the complete example](../examples/complete-assessment/scanreceipt.yaml) and [the three-tool negative example](../examples/incomplete-assessment/scanreceipt.yaml).
