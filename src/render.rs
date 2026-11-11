//! Plain terminal and standalone HTML presentation of canonical receipts.
use crate::Receipt;
use std::fmt::Write;

pub fn terminal(r: &Receipt) -> String {
    let mut s = format!(
        "SECURITY ASSESSMENT COVERAGE REPORTER\nAssessment: {} ({})\nStatus: {:?}\nTools: {} scheduled, {} completed, {} incomplete, {} unknown\nFindings reported: {}\nRequired checks: {} / {} completed, {} incomplete, {} unknown\n\n",
        r.assessment.name,
        r.assessment.id,
        r.assessment.status,
        r.summary.tools_scheduled,
        r.summary.tools_completed,
        r.summary.tools_incomplete,
        r.summary.tools_unknown,
        r.summary.reported_findings,
        r.summary.completed_checks,
        r.summary.required_checks,
        r.summary.incomplete_checks,
        r.summary.unknown_checks
    );
    for run in &r.runs {
        let _ = writeln!(
            s,
            "{:?} {} — process {:?}, auth {:?}, findings {}",
            run.tool, run.id, run.process, run.authentication, run.findings
        );
    }
    s.push_str("\nChecks\n");
    for c in &r.checks {
        let _ = writeln!(
            s,
            "[{:?}] {} ({}) — {}",
            c.status,
            c.id,
            if c.required { "required" } else { "optional" },
            c.reason_code
        );
    }
    if !r.limitations.is_empty() {
        s.push_str("\nLimitations and actions\n");
        for l in &r.limitations {
            let _ = writeln!(
                s,
                "{}: {} Action: {}",
                l.reason_code, l.explanation, l.remediation
            );
        }
    }
    let _ = writeln!(
        s,
        "\nCI policy: {} (completeness {}, findings {})",
        r.policy.status, r.policy.completeness, r.policy.findings
    );
    s
}
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub fn html(r: &Receipt) -> String {
    let mut s = String::from(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Security Assessment Coverage Reporter</title><style>body{font:16px/1.55 system-ui,sans-serif;color:#17212b;background:#f3f5f6;margin:0}main{max-width:1080px;margin:auto;padding:2rem}header,.card{background:white;border:1px solid #d9e0e4;border-radius:8px;padding:1.25rem;margin:1rem 0}h1{margin:0}h2{margin-top:2rem}code{font-family:ui-monospace,monospace;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;background:white}th,td{border-bottom:1px solid #d9e0e4;padding:.7rem;text-align:left;vertical-align:top}th{background:#e8edef}.status{font-weight:700}.muted{color:#536373}summary{cursor:pointer;font-weight:600}@media(max-width:600px){main{padding:1rem}table{display:block;overflow-x:auto}}</style><main>",
    );
    let _ = write!(
        s,
        "<header><p class=\"muted\">SECURITY ASSESSMENT COVERAGE REPORTER · OFFLINE ASSESSMENT RECEIPT</p><h1>{}</h1><p><code>{}</code> · <span class=\"status\">{:?}</span></p><p>Completeness describes the declared assessment, not application security. Runner sidecars are external attestations.</p></header>",
        esc(&r.assessment.name),
        esc(&r.assessment.id),
        r.assessment.status
    );
    let _ = write!(
        s,
        "<section class=\"card\"><h2>Summary</h2><p>{} tools scheduled · {} completed · {} incomplete · {} unknown</p><p>{} of {} required checks completed · {} incomplete · {} unknown · {} reported findings</p></section>",
        r.summary.tools_scheduled,
        r.summary.tools_completed,
        r.summary.tools_incomplete,
        r.summary.tools_unknown,
        r.summary.completed_checks,
        r.summary.required_checks,
        r.summary.incomplete_checks,
        r.summary.unknown_checks,
        r.summary.reported_findings
    );
    s.push_str("<h2>Scanner results</h2><table><thead><tr><th>Run</th><th>Tool</th><th>Process</th><th>Authentication</th><th>Findings</th></tr></thead><tbody>");
    for run in &r.runs {
        let _ = write!(
            s,
            "<tr><td><code>{}</code></td><td>{:?}</td><td>{:?}</td><td>{:?}</td><td>{}</td></tr>",
            esc(&run.id),
            run.tool,
            run.process,
            run.authentication,
            run.findings
        );
    }
    s.push_str("</tbody></table>");
    s.push_str("<h2>Checks and coverage</h2><table><thead><tr><th>Check</th><th>Required</th><th>Status</th><th>Reason</th></tr></thead><tbody>");
    for c in &r.checks {
        let _ = write!(
            s,
            "<tr><td><code>{}</code></td><td>{}</td><td>{:?}</td><td><code>{}</code></td></tr>",
            esc(&c.id),
            c.required,
            c.status,
            esc(&c.reason_code)
        );
    }
    s.push_str("</tbody></table><h2>Coverage dimensions</h2><table><thead><tr><th>Check</th><th>Dimension</th><th>Observed / expected</th><th>Status</th></tr></thead><tbody>");
    for c in &r.coverage {
        let counts = match (c.observed, c.expected) {
            (Some(o), Some(e)) => format!("{o} / {e}"),
            _ => "unknown".into(),
        };
        let _ = write!(
            s,
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{:?}</td></tr>",
            esc(&c.check_id),
            esc(&c.dimension),
            counts,
            c.status
        );
    }
    s.push_str("</tbody></table>");
    s.push_str("<h2>Limitations</h2>");
    for l in &r.limitations {
        let _ = write!(
            s,
            "<article class=\"card\"><h3><code>{}</code></h3><p>{}</p><p><strong>Action:</strong> {}</p><p class=\"muted\">Run: <code>{}</code>; check: <code>{}</code>; evidence: {}</p></article>",
            esc(&l.reason_code),
            esc(&l.explanation),
            esc(&l.remediation),
            esc(&l.run_id),
            esc(l.check_id.as_deref().unwrap_or("run")),
            esc(&l.evidence_ids.join(", "))
        );
    }
    let _ = write!(
        s,
        "<h2>CI decision</h2><p class=\"card\">Overall: <strong>{}</strong>. Completeness: {}. Findings: {}.</p>",
        esc(&r.policy.status),
        esc(&r.policy.completeness),
        esc(&r.policy.findings)
    );
    s.push_str("<details class=\"card\"><summary>Artifacts and evidence</summary><table><thead><tr><th>Artifact</th><th>SHA-256</th></tr></thead><tbody>");
    for a in &r.artifacts {
        let _ = write!(
            s,
            "<tr><td><code>{}</code></td><td><code>{}</code></td></tr>",
            esc(&a.path),
            esc(&a.sha256)
        );
    }
    s.push_str("</tbody></table><ul>");
    for e in &r.evidence {
        let _ = write!(
            s,
            "<li><code>{}</code> · {} · <code>{}</code> · <code>{}</code><br>{}</li>",
            esc(&e.id),
            esc(&e.provenance),
            esc(&e.source_artifact),
            esc(&e.locator),
            esc(&e.fact)
        );
    }
    s.push_str("</ul></details></main></html>\n");
    s
}
#[cfg(test)]
mod tests {
    #[test]
    fn escaping() {
        assert_eq!(super::esc("<script>&\""), "&lt;script&gt;&amp;&quot;");
    }
}
