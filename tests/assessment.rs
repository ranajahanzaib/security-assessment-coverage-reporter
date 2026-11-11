use security_assessment_coverage_reporter::{
    ArtifactKind, Overall, Status, Tool, adapters, analyze, canonical_json, load_manifest,
    parse_ports,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
        .join("scanreceipt.yaml")
}
fn temp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "scanreceipt-{}-{}-{}",
        name,
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(p.join("evidence")).unwrap();
    p
}
fn copy_fixture(name: &str, dest: &Path) {
    let src = fixture(name);
    fs::copy(&src, dest.join("scanreceipt.yaml")).unwrap();
    for entry in fs::read_dir(src.parent().unwrap().join("evidence")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), dest.join("evidence").join(entry.file_name())).unwrap();
    }
}
#[test]
fn demo_incomplete_zero_findings() {
    let r = analyze(&fixture("incomplete-assessment")).unwrap();
    assert!(matches!(r.assessment.status, Overall::Incomplete));
    assert_eq!(r.summary.reported_findings, 0);
    assert_eq!(
        (
            r.summary.tools_scheduled,
            r.summary.tools_completed,
            r.summary.tools_incomplete
        ),
        (3, 2, 1)
    );
    assert_eq!(
        r.checks.iter().find(|c| c.id == "zap-auth").unwrap().status,
        Status::Failed
    );
    assert!(
        r.limitations
            .iter()
            .any(|l| l.reason_code == "AUTHENTICATION_FAILED")
    );
    let json = String::from_utf8(canonical_json(&r).unwrap()).unwrap();
    assert!(!json.contains("SCANRECEIPT_SYNTHETIC_SENTINEL"));
}
#[test]
fn complete_network() {
    let r = analyze(&fixture("complete-assessment")).unwrap();
    assert!(matches!(r.assessment.status, Overall::Complete));
    assert_eq!(r.policy.status, "pass");
}
#[test]
fn canonical_golden() {
    let r = analyze(&fixture("incomplete-assessment")).unwrap();
    let bytes = canonical_json(&r).unwrap();
    assert_eq!(bytes, include_bytes!("golden/incomplete.json"));
    assert_eq!(
        bytes,
        canonical_json(&analyze(&fixture("incomplete-assessment")).unwrap()).unwrap()
    );
}
#[test]
fn empty_findings_are_not_execution() {
    let o = adapters::parse(&Tool::Nuclei, &ArtifactKind::Findings, b"").unwrap();
    assert_eq!(o.findings, 0);
    assert_eq!(o.native_complete, None);
}
#[test]
fn malformed_inputs_rejected() {
    assert!(adapters::parse(&Tool::Nmap, &ArtifactKind::Report, b"<nmaprun>").is_err());
    assert!(adapters::parse(&Tool::Nuclei, &ArtifactKind::Findings, b"{broken\n").is_err());
    assert!(adapters::parse(&Tool::Zap, &ArtifactKind::Report, b"{}").is_err());
}
#[test]
fn host_down_not_port_evidence() {
    let xml=b"<nmaprun scanner=\"nmap\"><scaninfo protocol=\"tcp\"/><host><status state=\"down\"/><address addr=\"192.0.2.10\" addrtype=\"ipv4\"/></host><runstats><finished exit=\"success\"/></runstats></nmaprun>";
    let o = adapters::parse(&Tool::Nmap, &ArtifactKind::Report, xml).unwrap();
    assert!(o.host_up.is_empty());
    assert!(o.ports.is_empty());
}
#[test]
fn duplicate_and_unknown_references_rejected() {
    let mut m = load_manifest(&fixture("complete-assessment")).unwrap();
    m.checks.push(m.checks[0].clone());
    assert!(security_assessment_coverage_reporter::validate(&m).is_err());
    m.checks.pop();
    m.checks[0].run_id = "missing".into();
    assert!(security_assessment_coverage_reporter::validate(&m).is_err());
}
#[test]
fn missing_artifact_is_unknown() {
    let p = temp("missing");
    copy_fixture("complete-assessment", &p);
    fs::remove_file(p.join("evidence/nmap.xml")).unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert!(matches!(r.assessment.status, Overall::Inconclusive));
    assert_eq!(r.checks[0].status, Status::Unknown);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn optional_skip_does_not_fail_complete() {
    let p = temp("optional");
    copy_fixture("complete-assessment", &p);
    let mut v: serde_json::Value =
        serde_json::to_value(load_manifest(&p.join("scanreceipt.yaml")).unwrap()).unwrap();
    v["checks"].as_array_mut().unwrap().push(serde_json::json!({"id":"optional-discovery","run_id":"nmap-server","kind":"host_discovery","required":false}));
    v["runs"][0]["artifacts"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"kind":"execution","path":"evidence/run.json"}));
    fs::write(p.join("scanreceipt.yaml"), serde_json::to_vec(&v).unwrap()).unwrap();
    fs::write(p.join("evidence/run.json"),r#"{"schema_version":1,"run_id":"nmap-server","tool":"nmap","exit_code":0,"source":"external_runner","stages":[{"check_id":"optional-discovery","status":"SKIPPED"}]}"#).unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert!(matches!(r.assessment.status, Overall::Complete));
    assert_eq!(r.checks[1].status, Status::Skipped);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn contradictory_execution_conservative() {
    let p = temp("conflict");
    copy_fixture("complete-assessment", &p);
    let mut v: serde_json::Value =
        serde_json::to_value(load_manifest(&p.join("scanreceipt.yaml")).unwrap()).unwrap();
    v["runs"][0]["artifacts"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"kind":"execution","path":"evidence/run.json"}));
    fs::write(p.join("scanreceipt.yaml"), serde_json::to_vec(&v).unwrap()).unwrap();
    fs::write(p.join("evidence/run.json"),r#"{"schema_version":1,"run_id":"nmap-server","tool":"nmap","exit_code":1,"source":"external_runner"}"#).unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert!(
        r.limitations
            .iter()
            .any(|l| l.reason_code == "CONFLICTING_EVIDENCE")
    );
    assert_ne!(r.checks[0].status, Status::Completed);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn ports_normalized() {
    assert_eq!(
        parse_ports("80,22-24,23,443").unwrap(),
        vec![(22, 24), (80, 80), (443, 443)]
    );
    assert!(parse_ports("0,65536").is_err());
}

#[test]
fn complete_with_findings_and_verified_auth() {
    let r = analyze(&fixture("complete-with-findings")).unwrap();
    assert!(matches!(r.assessment.status, Overall::Complete));
    assert_eq!(r.summary.reported_findings, 1);
    assert_eq!(r.policy.status, "pass");
    assert!(r.checks.iter().all(|c| c.status == Status::Completed));
}
#[test]
fn findings_policy_is_independent() {
    let p = temp("findings-policy");
    copy_fixture("complete-with-findings", &p);
    let mut v: serde_json::Value =
        serde_json::to_value(load_manifest(&p.join("scanreceipt.yaml")).unwrap()).unwrap();
    v["policy"]["on_findings"] = serde_json::json!("fail");
    fs::write(p.join("scanreceipt.yaml"), serde_json::to_vec(&v).unwrap()).unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert!(matches!(r.assessment.status, Overall::Complete));
    assert_eq!(r.policy.completeness, "pass");
    assert_eq!(r.policy.findings, "fail");
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn explicit_stage_states_remain_distinct() {
    for (label, expected) in [
        ("SKIPPED", Status::Skipped),
        ("UNSUPPORTED", Status::Unsupported),
        ("NOT_RUN", Status::NotRun),
        ("TIMED_OUT", Status::TimedOut),
        ("PARTIAL", Status::Partial),
        ("FAILED", Status::Failed),
    ] {
        let p = temp(label);
        copy_fixture("complete-assessment", &p);
        let mut v: serde_json::Value =
            serde_json::to_value(load_manifest(&p.join("scanreceipt.yaml")).unwrap()).unwrap();
        v["runs"][0]["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"kind":"execution","path":"evidence/run.json"}));
        fs::write(p.join("scanreceipt.yaml"), serde_json::to_vec(&v).unwrap()).unwrap();
        let sidecar = serde_json::json!({"schema_version":1,"run_id":"nmap-server","tool":"nmap","exit_code":0,"source":"external_runner","stages":[{"check_id":"nmap-ports","status":label}]});
        fs::write(
            p.join("evidence/run.json"),
            serde_json::to_vec(&sidecar).unwrap(),
        )
        .unwrap();
        let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
        assert_eq!(r.checks[0].status, expected);
        assert!(matches!(r.assessment.status, Overall::Incomplete));
        fs::remove_dir_all(p).unwrap();
    }
}

#[test]
fn forward_dependency_is_enforced() {
    let p = temp("forward-dependency");
    copy_fixture("complete-with-findings", &p);
    let mut v: serde_json::Value =
        serde_json::to_value(load_manifest(&p.join("scanreceipt.yaml")).unwrap()).unwrap();
    v["checks"].as_array_mut().unwrap().reverse();
    v["runs"][0]["artifacts"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a["kind"] != "verification");
    fs::write(p.join("scanreceipt.yaml"), serde_json::to_vec(&v).unwrap()).unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert_eq!(r.checks[0].id, "zap-active");
    assert_eq!(r.checks[0].status, Status::Unknown);
    assert_eq!(r.checks[1].reason_code, "AUTHENTICATION_UNVERIFIED");
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn dependency_cycle_rejected() {
    let mut m = load_manifest(&fixture("complete-with-findings")).unwrap();
    m.checks[0].depends_on.push("zap-active".into());
    assert!(security_assessment_coverage_reporter::validate(&m).is_err());
}

#[test]
fn wrong_target_verification_does_not_complete_auth() {
    let p = temp("wrong-auth-target");
    copy_fixture("complete-with-findings", &p);
    let mut v: serde_json::Value =
        serde_json::from_slice(&fs::read(p.join("evidence/verification.json")).unwrap()).unwrap();
    v["target"] = serde_json::json!("https://other.example.test");
    fs::write(
        p.join("evidence/verification.json"),
        serde_json::to_vec(&v).unwrap(),
    )
    .unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert_eq!(r.checks[0].status, Status::Unknown);
    assert!(matches!(r.assessment.status, Overall::Inconclusive));
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn expected_target_absent_is_partial() {
    let p = temp("missing-target");
    copy_fixture("complete-assessment", &p);
    let mut v: serde_json::Value =
        serde_json::to_value(load_manifest(&p.join("scanreceipt.yaml")).unwrap()).unwrap();
    v["scope"][0]["value"] = serde_json::json!("192.0.2.99");
    fs::write(p.join("scanreceipt.yaml"), serde_json::to_vec(&v).unwrap()).unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert_eq!(r.checks[0].status, Status::Partial);
    assert_eq!(r.coverage[0].observed, Some(0));
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn empty_nuclei_without_execution_is_unknown() {
    let p = temp("nuclei-no-execution");
    copy_fixture("incomplete-assessment", &p);
    let mut v: serde_json::Value =
        serde_json::to_value(load_manifest(&p.join("scanreceipt.yaml")).unwrap()).unwrap();
    v["runs"][1]["artifacts"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a["kind"] != "execution");
    fs::write(p.join("scanreceipt.yaml"), serde_json::to_vec(&v).unwrap()).unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert_eq!(r.summary.reported_findings, 0);
    assert_eq!(
        r.checks
            .iter()
            .find(|c| c.id == "nuclei-selected-set")
            .unwrap()
            .status,
        Status::Unknown
    );
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn route_shortfall_is_partial() {
    let p = temp("route-shortfall");
    copy_fixture("complete-with-findings", &p);
    let mut v: serde_json::Value =
        serde_json::to_value(load_manifest(&p.join("scanreceipt.yaml")).unwrap()).unwrap();
    v["checks"].as_array_mut().unwrap().push(serde_json::json!({"id":"routes","run_id":"zap-web","kind":"route_discovery","criteria":{"expected_routes":["/account","/settings"]}}));
    fs::write(p.join("scanreceipt.yaml"), serde_json::to_vec(&v).unwrap()).unwrap();
    let mut x: serde_json::Value =
        serde_json::from_slice(&fs::read(p.join("evidence/execution.json")).unwrap()).unwrap();
    x["stages"].as_array_mut().unwrap().push(serde_json::json!({"check_id":"routes","status":"COMPLETED","target":"https://app.example.test","observed_routes":["/account"]}));
    fs::write(
        p.join("evidence/execution.json"),
        serde_json::to_vec(&x).unwrap(),
    )
    .unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert_eq!(r.checks[2].status, Status::Partial);
    assert_eq!(r.coverage[2].expected, Some(2));
    assert_eq!(r.coverage[2].observed, Some(1));
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn timeout_preserves_completed_stage() {
    let p = temp("partial-timeout");
    copy_fixture("complete-with-findings", &p);
    let mut v: serde_json::Value =
        serde_json::to_value(load_manifest(&p.join("scanreceipt.yaml")).unwrap()).unwrap();
    v["checks"]
        .as_array_mut()
        .unwrap()
        .retain(|c| c["id"] != "zap-auth");
    v["checks"][0]["depends_on"] = serde_json::json!([]);
    v["checks"].as_array_mut().unwrap().push(serde_json::json!({"id":"routes","run_id":"zap-web","kind":"route_discovery","criteria":{"minimum_observed_routes":2}}));
    fs::write(p.join("scanreceipt.yaml"), serde_json::to_vec(&v).unwrap()).unwrap();
    let mut x: serde_json::Value =
        serde_json::from_slice(&fs::read(p.join("evidence/execution.json")).unwrap()).unwrap();
    x["timed_out"] = serde_json::json!(true);
    x["exit_code"] = serde_json::Value::Null;
    x["stages"].as_array_mut().unwrap().push(serde_json::json!({"check_id":"routes","status":"TIMED_OUT","target":"https://app.example.test","observed_routes":["/account"]}));
    fs::write(
        p.join("evidence/execution.json"),
        serde_json::to_vec(&x).unwrap(),
    )
    .unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert_eq!(r.checks[0].status, Status::Completed);
    assert_eq!(r.checks[1].status, Status::TimedOut);
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn nmap_invalid_port_state_not_counted() {
    let xml = b"<nmaprun scanner=\"nmap\"><scaninfo protocol=\"tcp\"/><host><status state=\"up\"/><address addr=\"192.0.2.10\" addrtype=\"ipv4\"/><ports><port protocol=\"tcp\" portid=\"22\"><state state=\"mystery\"/></port></ports></host><runstats><finished exit=\"success\"/></runstats></nmaprun>";
    let o = adapters::parse(&Tool::Nmap, &ArtifactKind::Report, xml).unwrap();
    assert!(o.ports.is_empty());
}

#[test]
fn missing_zap_auth_report_is_unknown() {
    let p = temp("zap-auth-missing");
    copy_fixture("complete-with-findings", &p);
    let mut v: serde_json::Value =
        serde_json::to_value(load_manifest(&p.join("scanreceipt.yaml")).unwrap()).unwrap();
    v["runs"][0]["artifacts"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a["kind"] != "verification");
    fs::write(p.join("scanreceipt.yaml"), serde_json::to_vec(&v).unwrap()).unwrap();
    fs::remove_file(p.join("evidence/zap-auth.json")).unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert_eq!(r.checks[0].status, Status::Unknown);
    assert!(
        r.limitations
            .iter()
            .any(|l| l.reason_code == "ARTIFACT_MISSING")
    );
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn successful_nuclei_process_without_selected_set_is_unknown() {
    let p = temp("nuclei-exit-only");
    copy_fixture("incomplete-assessment", &p);
    let mut x: serde_json::Value =
        serde_json::from_slice(&fs::read(p.join("evidence/nuclei-execution.json")).unwrap())
            .unwrap();
    x["stages"] = serde_json::json!([]);
    fs::write(
        p.join("evidence/nuclei-execution.json"),
        serde_json::to_vec(&x).unwrap(),
    )
    .unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert_eq!(r.summary.tools_completed, 2);
    assert_eq!(
        r.checks
            .iter()
            .find(|c| c.id == "nuclei-selected-set")
            .unwrap()
            .status,
        Status::Unknown
    );
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn artifact_size_limit_is_enforced() {
    assert!(
        security_assessment_coverage_reporter::analyze_with_limit(
            &fixture("complete-assessment"),
            1
        )
        .is_err()
    );
    assert!(
        security_assessment_coverage_reporter::analyze_with_limit(
            &fixture("complete-assessment"),
            0
        )
        .is_err()
    );
}

#[test]
fn nmap_rejects_misplaced_completion() {
    let xml = b"<nmaprun scanner=\"nmap\"><host><finished exit=\"success\"/></host></nmaprun>";
    assert!(adapters::parse(&Tool::Nmap, &ArtifactKind::Report, xml).is_err());
}

#[test]
fn html_escapes_untrusted_assessment_text_and_omits_auth_diagnostics() {
    let p = temp("html-escaping");
    copy_fixture("incomplete-assessment", &p);
    let mut v: serde_json::Value =
        serde_json::to_value(load_manifest(&p.join("scanreceipt.yaml")).unwrap()).unwrap();
    v["assessment"]["name"] = serde_json::json!("<script>alert('x')</script>");
    fs::write(p.join("scanreceipt.yaml"), serde_json::to_vec(&v).unwrap()).unwrap();
    let r = analyze(&p.join("scanreceipt.yaml")).unwrap();
    let html = security_assessment_coverage_reporter::render::html(&r);
    assert!(html.contains("&lt;script&gt;"));
    assert!(!html.contains("<script>alert"));
    assert!(!html.contains("SCANRECEIPT_SYNTHETIC_SENTINEL"));
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn checked_in_schemas_match_generated_contract() {
    for name in ["manifest", "receipt", "execution", "verification"] {
        let checked_in = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas")
                .join(format!("{name}.schema.json")),
        )
        .unwrap();
        assert_eq!(
            security_assessment_coverage_reporter::schema(name).unwrap(),
            checked_in,
            "schema drift: {name}"
        );
    }
}

#[test]
fn github_workflows_are_valid_yaml_with_expected_jobs() {
    for file in [
        "ci.yml",
        "security-assessment-coverage-reporter-example.yml",
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".github/workflows")
            .join(file);
        let yaml = fs::read_to_string(path).unwrap();
        let workflow: serde_json::Value = serde_saphyr::from_str(&yaml).unwrap();
        assert!(workflow["jobs"].is_object(), "missing jobs in {file}");
        assert!(workflow["on"].is_object(), "missing triggers in {file}");
    }
}

#[test]
fn nmap_preserves_host_states_and_user_aliases() {
    let xml = b"<nmaprun scanner=\"nmap\"><scaninfo protocol=\"tcp\"/><host><status state=\"up\"/><address addr=\"192.0.2.10\" addrtype=\"ipv4\"/><hostnames><hostname name=\"server.example.test\" type=\"user\"/></hostnames><ports><port protocol=\"tcp\" portid=\"22\"><state state=\"filtered\"/></port></ports></host><runstats><finished exit=\"success\"/></runstats></nmaprun>";
    let o = adapters::parse(&Tool::Nmap, &ArtifactKind::Report, xml).unwrap();
    assert_eq!(
        o.host_states.get("192.0.2.10").map(String::as_str),
        Some("up")
    );
    assert_eq!(
        o.host_states.get("server.example.test").map(String::as_str),
        Some("up")
    );
    assert!(o.ports.contains(&("192.0.2.10".into(), 22)));
    assert!(o.ports.contains(&("server.example.test".into(), 22)));
}

#[test]
fn unsupported_nmap_xml_version_rejected() {
    let xml = b"<nmaprun scanner=\"nmap\" xmloutputversion=\"99.0\"><runstats><finished exit=\"success\"/></runstats></nmaprun>";
    assert!(adapters::parse(&Tool::Nmap, &ArtifactKind::Report, xml).is_err());
}

#[test]
fn complete_receipts_match_goldens() {
    for (fixture_name, golden) in [
        (
            "complete-assessment",
            include_bytes!("golden/complete.json").as_slice(),
        ),
        (
            "complete-with-findings",
            include_bytes!("golden/complete-with-findings.json").as_slice(),
        ),
    ] {
        let receipt = analyze(&fixture(fixture_name)).unwrap();
        assert_eq!(canonical_json(&receipt).unwrap(), golden);
    }
}

#[test]
fn contradictory_authentication_claims_are_exposed() {
    let p = temp("auth-conflict");
    copy_fixture("complete-with-findings", &p);
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(p.join("evidence/zap-auth.json")).unwrap()).unwrap();
    report["summaryItems"][0]["passed"] = serde_json::json!(false);
    fs::write(
        p.join("evidence/zap-auth.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    let receipt = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert_eq!(receipt.checks[0].status, Status::Failed);
    assert!(
        receipt
            .limitations
            .iter()
            .any(|l| l.reason_code == "CONFLICTING_EVIDENCE")
    );
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn zap_plan_is_intent_not_execution() {
    let plan = b"env:\n  contexts: []\njobs:\n  - type: spider\n  - type: activeScan\n";
    let observed = adapters::parse(&Tool::Zap, &ArtifactKind::Plan, plan).unwrap();
    assert_eq!(observed.planned_jobs, vec!["spider", "activeScan"]);
    assert_eq!(observed.native_complete, None);
}

#[test]
fn nuclei_finding_is_counted_without_copying_request_body() {
    let input = include_bytes!("../fixtures/nuclei/finding.jsonl");
    let observed = adapters::parse(&Tool::Nuclei, &ArtifactKind::Findings, input).unwrap();
    assert_eq!(observed.findings, 1);
    assert!(adapters::parse(&Tool::Nuclei, &ArtifactKind::Findings, b"{}\n").is_err());
    let p = temp("nuclei-finding-secret");
    copy_fixture("incomplete-assessment", &p);
    fs::write(p.join("evidence/nuclei.jsonl"), input).unwrap();
    let receipt = analyze(&p.join("scanreceipt.yaml")).unwrap();
    assert_eq!(receipt.summary.reported_findings, 1);
    assert!(
        !String::from_utf8(canonical_json(&receipt).unwrap())
            .unwrap()
            .contains("SCANRECEIPT_SYNTHETIC_SENTINEL")
    );
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn nuclei_jsonl_stream_rejects_oversized_and_malformed_lines() {
    let p = temp("nuclei-jsonl-bounds");
    copy_fixture("incomplete-assessment", &p);
    let path = p.join("evidence/nuclei.jsonl");
    fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap();
    let error = analyze(&p.join("scanreceipt.yaml"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("JSONL file or line size limit"));
    fs::write(
        &path,
        b"{\"template-id\":\"x\",\"host\":\"example.test\"}\n{broken}\n",
    )
    .unwrap();
    let error = analyze(&p.join("scanreceipt.yaml"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("Nuclei JSONL line 2"));
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn nmap_rejects_excessive_xml_nesting_and_duplicate_finish() {
    let mut xml = String::from("<nmaprun scanner=\"nmap\">");
    xml.push_str(&"<x>".repeat(129));
    xml.push_str(&"</x>".repeat(129));
    xml.push_str("<runstats><finished exit=\"success\"/></runstats></nmaprun>");
    assert!(adapters::parse(&Tool::Nmap, &ArtifactKind::Report, xml.as_bytes()).is_err());
    let duplicate = b"<nmaprun scanner=\"nmap\"><runstats><finished exit=\"success\"/><finished exit=\"error\"/></runstats></nmaprun>";
    assert!(adapters::parse(&Tool::Nmap, &ArtifactKind::Report, duplicate).is_err());
}
