//! Typed check rules. Parser observations and external attestations remain distinct.
use crate::{
    Check, CheckKind, Execution, Manifest, Run, Status, Verification, adapters, parse_ports,
};

pub(crate) fn verification_valid(v: &Verification, run: &Run, manifest: &Manifest) -> bool {
    run.scope_ids.iter().any(|id| {
        manifest
            .scope
            .iter()
            .any(|s| &s.id == id && s.value == v.target)
    }) && v
        .protected_resource
        .starts_with(&format!("{}/", v.target.trim_end_matches('/')))
        && !v.protected_resource.contains('?')
        && !v.protected_resource.contains('#')
        && v.authenticated_access
        && !v.unauthenticated_access
}

pub(crate) fn evaluate(
    c: &Check,
    r: &Run,
    m: &Manifest,
    o: &adapters::Observation,
    x: Option<&Execution>,
    v: Option<&Verification>,
) -> (Status, &'static str) {
    if matches!(c.kind, CheckKind::Authentication)
        && o.auth_failed
        && o.auth_target.as_deref().is_some_and(|t| {
            r.scope_ids
                .iter()
                .any(|id| m.scope.iter().any(|s| &s.id == id && s.value == t))
        })
    {
        return (Status::Failed, "AUTHENTICATION_FAILED");
    }
    if let Some(stage) = x.and_then(|x| x.stages.iter().find(|s| s.check_id == c.id))
        && stage.status != Status::Completed
    {
        return (stage.status.clone(), "EXPLICIT_STAGE_OUTCOME");
    }
    let stage_completed = x.is_some_and(|x| {
        x.stages
            .iter()
            .any(|s| s.check_id == c.id && s.status == Status::Completed)
    });
    if x.is_some_and(|x| x.timed_out)
        && (!stage_completed || matches!(c.kind, CheckKind::TemplateScan))
    {
        return (Status::Unknown, "TOOL_TIMED_OUT");
    }
    if x.is_some_and(|x| x.exit_code.is_some_and(|n| n != 0))
        && (!stage_completed || matches!(c.kind, CheckKind::TemplateScan))
    {
        return (Status::Unknown, "TOOL_EXECUTION_FAILED");
    }
    if o.af_error {
        return (Status::Failed, "SCAN_STAGE_FAILED");
    }
    let scope: Vec<&str> = r
        .scope_ids
        .iter()
        .filter_map(|id| {
            m.scope
                .iter()
                .find(|s| &s.id == id)
                .map(|s| s.value.as_str())
        })
        .collect();
    match c.kind {
        CheckKind::HostDiscovery => {
            if o.native_complete == Some(true) && scope.iter().all(|s| o.targets.contains(*s)) {
                (Status::Completed, "CHECK_COMPLETED")
            } else if o.native_complete == Some(true) {
                (Status::Partial, "EXPECTED_TARGET_MISSING")
            } else {
                (Status::Unknown, "INSUFFICIENT_EXECUTION_EVIDENCE")
            }
        }
        CheckKind::TcpPortScan => {
            let ports = c
                .criteria
                .ports
                .as_ref()
                .and_then(|s| parse_ports(s).ok())
                .unwrap_or_default();
            let expected = ports
                .iter()
                .map(|(a, b)| *b as usize - *a as usize + 1)
                .sum::<usize>();
            let found = scope
                .iter()
                .filter(|s| o.host_up.contains(**s))
                .map(|s| {
                    ports
                        .iter()
                        .map(|(a, b)| {
                            (*a..=*b)
                                .filter(|p| o.ports.contains(&(s.to_string(), *p)))
                                .count()
                        })
                        .sum::<usize>()
                })
                .sum::<usize>();
            if o.native_complete == Some(true) && expected > 0 && found == expected * scope.len() {
                (Status::Completed, "CHECK_COMPLETED")
            } else if o.native_complete == Some(true) {
                (Status::Partial, "EXPECTED_PORTS_MISSING")
            } else {
                (Status::Unknown, "INSUFFICIENT_EXECUTION_EVIDENCE")
            }
        }
        CheckKind::Authentication => {
            if let Some(v) = v {
                if verification_valid(v, r, m) {
                    return (Status::Completed, "CHECK_COMPLETED");
                }
                if scope.contains(&v.target.as_str())
                    && (!v.authenticated_access || v.unauthenticated_access)
                {
                    return (Status::Failed, "AUTHENTICATION_FAILED");
                }
            }
            if o.auth_failed && o.auth_target.as_deref().is_some_and(|t| scope.contains(&t)) {
                return (Status::Failed, "AUTHENTICATION_FAILED");
            }
            if o.auth_success && o.auth_target.as_deref().is_some_and(|t| scope.contains(&t)) {
                if c.criteria.requires_positive_verification {
                    (Status::Unknown, "AUTHENTICATION_UNVERIFIED")
                } else {
                    (Status::Completed, "CHECK_COMPLETED")
                }
            } else {
                (Status::Unknown, "AUTHENTICATION_UNKNOWN")
            }
        }
        CheckKind::RouteDiscovery => {
            if o.auth_failed {
                return (Status::Unknown, "AUTHENTICATION_FAILED");
            }
            let stage = x.and_then(|x| x.stages.iter().find(|s| s.check_id == c.id));
            let target_ok = stage
                .and_then(|s| s.target.as_deref())
                .is_some_and(|t| scope.contains(&t));
            let routes = if target_ok {
                stage.map(|s| &s.observed_routes)
            } else {
                None
            };
            let stage_ok = stage.is_some_and(|s| s.status == Status::Completed) && target_ok;
            let routes_ok = routes.is_some_and(|routes| {
                (c.criteria.expected_routes.is_empty()
                    || c.criteria
                        .expected_routes
                        .iter()
                        .all(|p| routes.contains(p)))
                    && c.criteria
                        .minimum_observed_routes
                        .is_none_or(|n| routes.len() >= n)
            });
            if stage_ok && routes_ok {
                (Status::Completed, "CHECK_COMPLETED")
            } else if routes.is_some_and(|r| !r.is_empty())
                && (!c.criteria.expected_routes.is_empty()
                    || c.criteria.minimum_observed_routes.is_some())
            {
                (Status::Partial, "EXPECTED_ROUTES_MISSING")
            } else {
                (Status::Unknown, "ROUTE_COVERAGE_UNKNOWN")
            }
        }
        CheckKind::ActiveScan => {
            if o.auth_failed {
                return (Status::Unknown, "AUTHENTICATION_FAILED");
            }
            if x.is_some_and(|x| {
                x.stages.iter().any(|s| {
                    s.check_id == c.id
                        && s.status == Status::Completed
                        && s.target.as_deref().is_some_and(|t| scope.contains(&t))
                })
            }) {
                (Status::Completed, "CHECK_COMPLETED")
            } else {
                (Status::Unknown, "SCAN_STAGE_UNKNOWN")
            }
        }
        CheckKind::TemplateScan => {
            if x.is_some_and(|x| {
                x.exit_code == Some(0)
                    && x.stages.iter().any(|s| {
                        s.check_id == c.id
                            && s.status == Status::Completed
                            && !c.criteria.expected_templates.is_empty()
                            && !c.criteria.expected_targets.is_empty()
                            && c.criteria
                                .expected_templates
                                .iter()
                                .all(|t| s.selected_templates.contains(t))
                            && c.criteria
                                .expected_targets
                                .iter()
                                .all(|t| s.selected_targets.contains(t))
                            && c.criteria
                                .expected_targets
                                .iter()
                                .all(|t| scope.contains(&t.as_str()))
                    })
            }) {
                (Status::Completed, "CHECK_COMPLETED")
            } else {
                (Status::Unknown, "TEMPLATE_EXECUTION_UNVERIFIED")
            }
        }
    }
}
pub(crate) fn explain_reason(r: &str) -> &'static str {
    match r {
        "AUTHENTICATION_FAILED" => {
            "Authentication failed or the unauthenticated control gained access."
        }
        "EXPECTED_PORTS_MISSING" => "Expected target and port evidence is incomplete.",
        "EXPECTED_TARGET_MISSING" => "An expected target was not observed.",
        "TEMPLATE_EXECUTION_UNVERIFIED" => {
            "Selected template execution cannot be established from findings alone."
        }
        "EXPLICIT_STAGE_OUTCOME" => "The external runner recorded a noncompleted stage.",
        "DEPENDENCY_UNSATISFIED" => {
            "A prerequisite check is incomplete or unknown, so dependent coverage cannot be established."
        }
        "TOOL_EXECUTION_FAILED" => {
            "The scanner process failed; this check has no conclusive stage outcome."
        }
        "TOOL_TIMED_OUT" => {
            "The scanner process timed out; this check has no conclusive stage outcome."
        }
        "AUTHENTICATION_UNVERIFIED" => {
            "ZAP reported authentication success, but independent positive verification is required."
        }
        _ => "The available evidence does not establish this check as completed.",
    }
}
pub(crate) fn remedy(r: &str) -> &'static str {
    match r {
        "AUTHENTICATION_FAILED" => "Repair authentication and rerun affected authenticated checks.",
        "EXPECTED_PORTS_MISSING" => "Rerun Nmap against the declared target and ports.",
        "TEMPLATE_EXECUTION_UNVERIFIED" => {
            "Capture explicit stage execution metadata and selected templates and targets."
        }
        "DEPENDENCY_UNSATISFIED" => "Repair the prerequisite check and rerun this dependent stage.",
        "TOOL_EXECUTION_FAILED" | "TOOL_TIMED_OUT" => {
            "Repair and rerun the scanner; capture stage outcomes."
        }
        "AUTHENTICATION_UNVERIFIED" => {
            "Add a protected-resource probe with authenticated and unauthenticated controls."
        }
        _ => "Capture scanner-native stage evidence or a documented external execution sidecar.",
    }
}
