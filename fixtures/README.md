# Deterministic assessment fixtures

The human-readable source artifacts live under `examples/`. The integration suite copies those artifacts into isolated temporary directories and changes one condition at a time. The scenarios cover normal, incomplete, contradictory, malformed, and unsupported evidence:

| Scenario                                              | Test or source                                                       |
| ----------------------------------------------------- | -------------------------------------------------------------------- |
| 01 completed Nmap ports                               | `complete_network`                                                   |
| 02 truncated Nmap XML                                 | `malformed_inputs_rejected`                                          |
| 03 down host without port evidence                    | `host_down_not_port_evidence`                                        |
| 04 zero ZAP alerts with failed auth                   | `demo_incomplete_zero_findings`                                      |
| 05 missing ZAP auth diagnostics                       | `missing_zap_auth_report_is_unknown`                                 |
| 06 tool success without independent auth verification | `forward_dependency_is_enforced`                                     |
| 07 positive auth verification                         | `complete_with_findings_and_verified_auth`                           |
| 08 empty Nuclei findings without execution            | `empty_nuclei_without_execution_is_unknown`                          |
| 09 Nuclei process exit without selected-set evidence  | `successful_nuclei_process_without_selected_set_is_unknown`          |
| 10 timeout after completed stage                      | `timeout_preserves_completed_stage`                                  |
| 11 required stage skipped                             | `explicit_stage_states_remain_distinct`                              |
| 12 all required checks complete                       | `complete_network`                                                   |
| 13 complete with findings                             | `complete_with_findings_and_verified_auth`                           |
| 14 native/runner conflict                             | `contradictory_execution_conservative`                               |
| 15 missing expected target                            | `expected_target_absent_is_partial`                                  |
| 16 route shortfall                                    | `route_shortfall_is_partial`                                         |
| 17 malformed/unsupported version                      | `malformed_inputs_rejected`, `unsupported_nmap_xml_version_rejected` |
| 18 optional skipped stage                             | `optional_skip_does_not_fail_complete`                               |

The scanner reports are synthetic examples shaped from the documented native fields. Execution and verification JSON files are Security Assessment Coverage Reporter's own external attestation formats, not scanner-native output. See [scanner support](../docs/scanner-support.md) for primary format references.
