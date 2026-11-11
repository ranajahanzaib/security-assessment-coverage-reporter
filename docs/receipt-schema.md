# Receipt contract

`schema_version` is `1`. The authoritative JSON Schema is [`schemas/receipt.schema.json`](../schemas/receipt.schema.json), generated from the Rust types with `security-assessment-coverage-reporter schema receipt`.

`assessment.status` is `COMPLETE`, `INCOMPLETE`, or `INCONCLUSIVE`. `summary` counts tool processes, required completed/incomplete/unknown checks, and reported findings separately. `coverage` reports named dimensions with observed and declared expected counts, without inventing percentages. `runs` list process outcomes and observed targets/routes. `checks` list required/optional status, reason code, and evidence IDs. `limitations` carry explanation, remediation, scope of impact, and evidence IDs. `artifacts` contain SHA-256 hashes; `evidence` records the provenance and locator. `policy` separates completeness and findings decisions.

Keys, arrays, IDs, and serialization are deterministic for identical inputs. No generated timestamp or absolute host path appears in canonical output. The golden fixture in `tests/golden/incomplete.json` protects the public shape.
