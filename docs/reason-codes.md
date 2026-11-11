# Stable reason codes (receipt v1)

Check outcomes use these codes:

| Code                                                      | Meaning                                                                                                                                                             |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CHECK_COMPLETED`                                         | Declared check met its documented acceptance criteria.                                                                                                              |
| `EXPLICIT_STAGE_OUTCOME`                                  | External stage sidecar recorded a noncompleted state. Read `status` for `FAILED`, `TIMED_OUT`, `SKIPPED`, `UNSUPPORTED`, or `NOT_RUN`.                              |
| `INSUFFICIENT_EXECUTION_EVIDENCE`                         | Available native/runner evidence does not establish completion.                                                                                                     |
| `AUTHENTICATION_FAILED`                                   | Scoped authentication report or verification control failed.                                                                                                        |
| `AUTHENTICATION_UNKNOWN`                                  | Required authentication outcome is unobserved.                                                                                                                      |
| `AUTHENTICATION_UNVERIFIED`                               | Tool reported success but the required independent control is missing.                                                                                              |
| `DEPENDENCY_UNSATISFIED`                                  | A prerequisite check did not complete.                                                                                                                              |
| `EXPECTED_TARGET_MISSING`                                 | An expected target was not observed.                                                                                                                                |
| `EXPECTED_PORTS_MISSING`                                  | An expected target/port pair lacks explicit scan state.                                                                                                             |
| `EXPECTED_ROUTES_MISSING`                                 | A declared route threshold or list was not met.                                                                                                                     |
| `ROUTE_COVERAGE_UNKNOWN`                                  | Route discovery lacks sufficient stage evidence.                                                                                                                    |
| `SCAN_STAGE_FAILED`                                       | ZAP reported Automation Framework errors.                                                                                                                           |
| `SCAN_STAGE_UNKNOWN`                                      | Active-scan stage completion is unproven.                                                                                                                           |
| `TEMPLATE_EXECUTION_UNVERIFIED`                           | Nuclei selected-set or finer template execution claim is unproven. It may also appear as an informational limitation when only selected-set completion is required. |
| `TOOL_EXECUTION_FAILED`, `TOOL_TIMED_OUT`, `TOOL_NOT_RUN` | Process outcome or a check blocked by that process outcome.                                                                                                         |
| `CONFLICTING_EVIDENCE`                                    | Evidence sources or fields disagree; optimistic completion is suppressed.                                                                                           |
| `ARTIFACT_MISSING`                                        | Declared artifact is absent; this alone is not proof of `NOT_RUN`.                                                                                                  |

Policy reasons are `ASSESSMENT_NOT_COMPLETE` and `FINDINGS_PRESENT`. Stable codes are part of the versioned receipt contract. A malformed or unsupported input artifact is a CLI input error (exit `3`) rather than a fabricated check outcome.
