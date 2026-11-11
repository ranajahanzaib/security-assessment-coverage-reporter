//! Offline assessment completeness evaluation. Native reports and external attestations
//! are separate inputs; findings never establish execution coverage.
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader, Read},
    path::Path,
};

pub mod adapters;
mod evaluation;
pub mod render;
use evaluation::{evaluate, explain_reason, remedy, verification_valid};

const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
fn msg(s: impl Into<String>) -> Error {
    Error::Message(s.into())
}
fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    read_bounded_limit(path, MAX_ARTIFACT_BYTES)
}
fn read_bounded_limit(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    let meta = file.metadata().map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !meta.is_file() || meta.len() > limit {
        return Err(msg(format!(
            "{} is not a regular file or exceeds {} bytes",
            path.display(),
            limit
        )));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| Error::Io {
            path: path.display().to_string(),
            source,
        })?;
    if bytes.len() as u64 > limit {
        return Err(msg(format!("{} exceeds {} bytes", path.display(), limit)));
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_nuclei_jsonl(
    path: &Path,
    kind: &ArtifactKind,
    limit: u64,
) -> Result<(adapters::Observation, String)> {
    let file = fs::File::open(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    let meta = file.metadata().map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    if !meta.is_file() || meta.len() > limit {
        return Err(msg(format!(
            "{} is not a regular file or exceeds {} bytes",
            path.display(),
            limit
        )));
    }
    let mut reader = BufReader::new(file.take(limit + 1));
    let mut hash = Sha256::new();
    let mut observation = adapters::Observation::default();
    let mut line = Vec::new();
    let mut total = 0_u64;
    let mut line_no = 0;
    loop {
        let available = reader.fill_buf().map_err(|source| Error::Io {
            path: path.display().to_string(),
            source,
        })?;
        if available.is_empty() {
            break;
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if total + count as u64 > limit || line.len() + count > 1024 * 1024 {
            return Err(msg(format!(
                "{} exceeds the JSONL file or line size limit",
                path.display()
            )));
        }
        hash.update(&available[..count]);
        line.extend_from_slice(&available[..count]);
        total += count as u64;
        reader.consume(count);
        if line.last() == Some(&b'\n') {
            line_no += 1;
            adapters::parse_nuclei_line(kind, &line, line_no, &mut observation)?;
            line.clear();
        }
    }
    if !line.is_empty() {
        adapters::parse_nuclei_line(kind, &line, line_no + 1, &mut observation)?;
    }
    Ok((observation, format!("{:x}", hash.finalize())))
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub assessment: Assessment,
    pub scope: Vec<Scope>,
    pub runs: Vec<Run>,
    pub checks: Vec<Check>,
    #[serde(default)]
    pub policy: Policy,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub id: String,
    pub kind: ScopeKind,
    pub value: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Url,
    Ip,
    Host,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Tool {
    Nmap,
    Zap,
    Nuclei,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub id: String,
    pub tool: Tool,
    pub scope_ids: Vec<String>,
    pub artifacts: Vec<Artifact>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub kind: ArtifactKind,
    pub path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Report,
    Findings,
    Statistics,
    Execution,
    Authentication,
    Verification,
    Plan,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    HostDiscovery,
    TcpPortScan,
    Authentication,
    RouteDiscovery,
    ActiveScan,
    TemplateScan,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Criteria {
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default)]
    pub expected_routes: Vec<String>,
    #[serde(default)]
    pub minimum_observed_routes: Option<usize>,
    #[serde(default)]
    pub requires_positive_verification: bool,
    #[serde(default)]
    pub expected_templates: Vec<String>,
    #[serde(default)]
    pub expected_targets: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub id: String,
    pub run_id: String,
    pub kind: CheckKind,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub criteria: Criteria,
    #[serde(default)]
    pub depends_on: Vec<String>,
}
fn default_true() -> bool {
    true
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Fail,
    Ignore,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub on_incomplete: Action,
    pub on_inconclusive: Action,
    pub on_findings: Action,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            on_incomplete: Action::Fail,
            on_inconclusive: Action::Fail,
            on_findings: Action::Ignore,
        }
    }
}

pub fn load_manifest(path: &Path) -> Result<Manifest> {
    let bytes = read_bounded(path)?;
    let s = std::str::from_utf8(&bytes).map_err(|e| msg(format!("manifest is not UTF-8: {e}")))?;
    let m: Manifest =
        serde_saphyr::from_str(s).map_err(|e| msg(format!("invalid manifest: {e}")))?;
    validate(&m)?;
    Ok(m)
}
fn valid_scope_value(scope: &Scope) -> bool {
    match scope.kind {
        ScopeKind::Ip => scope.value.parse::<std::net::IpAddr>().is_ok(),
        ScopeKind::Host => {
            scope.value.len() <= 253
                && scope.value.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        }
        ScopeKind::Url => {
            let remainder = scope
                .value
                .strip_prefix("https://")
                .or_else(|| scope.value.strip_prefix("http://"));
            remainder.is_some_and(|r| {
                let authority = r.split('/').next().unwrap_or("");
                !authority.is_empty()
                    && !authority.contains('@')
                    && !scope.value.contains('?')
                    && !scope.value.contains('#')
                    && !scope.value.chars().any(char::is_whitespace)
            })
        }
    }
}
pub fn validate(m: &Manifest) -> Result<()> {
    if m.schema_version != 1 {
        return Err(msg("unsupported manifest schema_version"));
    }
    if m.assessment.id.trim().is_empty()
        || m.assessment.name.trim().is_empty()
        || m.scope.is_empty()
        || m.runs.is_empty()
        || m.checks.is_empty()
    {
        return Err(msg("assessment, scope, runs and checks must be nonempty"));
    }
    let mut ids = BTreeSet::new();
    for s in &m.scope {
        if s.id.is_empty() || !valid_scope_value(s) || !ids.insert(s.id.clone()) {
            return Err(msg("empty or duplicate scope ID/value"));
        }
    }
    let mut scope_values = BTreeSet::new();
    for scope in &m.scope {
        if !scope_values.insert(&scope.value) {
            return Err(msg("duplicate scope value"));
        }
    }
    ids.clear();
    for r in &m.runs {
        if r.id.is_empty() || !ids.insert(r.id.clone()) || r.scope_ids.is_empty() {
            return Err(msg("empty or duplicate run ID, or run without scope"));
        }
        let mut scope_refs = BTreeSet::new();
        for id in &r.scope_ids {
            let scope = m.scope.iter().find(|s| &s.id == id);
            if scope.is_none() || !scope_refs.insert(id) {
                return Err(msg(format!("unknown or duplicate scope {id}")));
            }
            if scope.is_some_and(|s| {
                (matches!(r.tool, Tool::Nmap) && matches!(s.kind, ScopeKind::Url))
                    || (matches!(r.tool, Tool::Zap) && !matches!(s.kind, ScopeKind::Url))
            }) {
                return Err(msg(format!(
                    "scope {id} is incompatible with tool {:?}",
                    r.tool
                )));
            }
        }
        let mut kinds = BTreeSet::new();
        for a in &r.artifacts {
            if a.path.trim().is_empty()
                || Path::new(&a.path).is_absolute()
                || Path::new(&a.path)
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                || !kinds.insert(format!("{:?}", a.kind))
            {
                return Err(msg(format!("invalid or duplicate artifact in {}", r.id)));
            }
        }
    }
    ids.clear();
    for c in &m.checks {
        if c.id.is_empty() || !ids.insert(c.id.clone()) || !m.runs.iter().any(|r| r.id == c.run_id)
        {
            return Err(msg(format!("invalid check ID or run reference: {}", c.id)));
        }
        match c.kind {
            CheckKind::TcpPortScan
                if c.criteria
                    .ports
                    .as_ref()
                    .is_none_or(|p| parse_ports(p).is_err()) =>
            {
                return Err(msg(format!("{} requires valid ports", c.id)));
            }
            CheckKind::Authentication
                if !matches!(
                    m.runs.iter().find(|r| r.id == c.run_id).map(|r| &r.tool),
                    Some(Tool::Zap)
                ) =>
            {
                return Err(msg("authentication requires ZAP"));
            }
            _ => {}
        }
        if c.criteria.minimum_observed_routes == Some(0) {
            return Err(msg("minimum_observed_routes must be positive"));
        }
        let run = m
            .runs
            .iter()
            .find(|r| r.id == c.run_id)
            .ok_or_else(|| msg("unknown run"))?;
        let tool_ok = matches!(
            (&c.kind, &run.tool),
            (
                CheckKind::HostDiscovery | CheckKind::TcpPortScan,
                Tool::Nmap
            ) | (
                CheckKind::Authentication | CheckKind::RouteDiscovery | CheckKind::ActiveScan,
                Tool::Zap
            ) | (CheckKind::TemplateScan, Tool::Nuclei)
        );
        if !tool_ok {
            return Err(msg(format!("check {} is unsupported by its tool", c.id)));
        }
        let criteria = &c.criteria;
        for values in [
            &criteria.expected_routes,
            &criteria.expected_templates,
            &criteria.expected_targets,
        ] {
            if values.iter().any(|v| v.trim().is_empty())
                || values.iter().collect::<BTreeSet<_>>().len() != values.len()
            {
                return Err(msg(format!(
                    "empty or duplicate criteria values for {}",
                    c.id
                )));
            }
        }
        let valid = match c.kind {
            CheckKind::TcpPortScan => {
                criteria.ports.is_some()
                    && criteria.expected_routes.is_empty()
                    && criteria.minimum_observed_routes.is_none()
                    && criteria.expected_templates.is_empty()
                    && criteria.expected_targets.is_empty()
                    && !criteria.requires_positive_verification
            }
            CheckKind::RouteDiscovery => {
                (criteria.minimum_observed_routes.is_some() || !criteria.expected_routes.is_empty())
                    && criteria.ports.is_none()
                    && criteria.expected_templates.is_empty()
                    && criteria.expected_targets.is_empty()
                    && !criteria.requires_positive_verification
                    && criteria
                        .expected_routes
                        .iter()
                        .all(|p| p.starts_with('/') && !p.contains('?') && !p.contains('#'))
            }
            CheckKind::TemplateScan => {
                !criteria.expected_templates.is_empty()
                    && !criteria.expected_targets.is_empty()
                    && criteria.ports.is_none()
                    && criteria.expected_routes.is_empty()
                    && criteria.minimum_observed_routes.is_none()
                    && !criteria.requires_positive_verification
                    && criteria.expected_targets.iter().all(|t| {
                        run.scope_ids
                            .iter()
                            .any(|id| m.scope.iter().any(|s| &s.id == id && &s.value == t))
                    })
            }
            CheckKind::Authentication => {
                criteria.ports.is_none()
                    && criteria.expected_routes.is_empty()
                    && criteria.minimum_observed_routes.is_none()
                    && criteria.expected_templates.is_empty()
                    && criteria.expected_targets.is_empty()
            }
            CheckKind::HostDiscovery | CheckKind::ActiveScan => {
                criteria.ports.is_none()
                    && criteria.expected_routes.is_empty()
                    && criteria.minimum_observed_routes.is_none()
                    && criteria.expected_templates.is_empty()
                    && criteria.expected_targets.is_empty()
                    && !criteria.requires_positive_verification
            }
        };
        if !valid {
            return Err(msg(format!(
                "invalid or contradictory criteria for {}",
                c.id
            )));
        }
    }
    for c in &m.checks {
        for d in &c.depends_on {
            if d == &c.id || !ids.contains(d.as_str()) {
                return Err(msg(format!("unknown or self dependency {d}")));
            }
        }
    }
    for c in &m.checks {
        let mut seen = BTreeSet::new();
        let mut pending = c.depends_on.clone();
        while let Some(id) = pending.pop() {
            if id == c.id {
                return Err(msg(format!("dependency cycle involving {}", c.id)));
            }
            if seen.insert(id.clone())
                && let Some(dep) = m.checks.iter().find(|x| x.id == id)
            {
                pending.extend(dep.depends_on.iter().cloned());
            }
        }
    }
    Ok(())
}
pub fn parse_ports(s: &str) -> Result<Vec<(u16, u16)>> {
    let mut ranges = Vec::new();
    for part in s.split(',') {
        let mut p = part.split('-');
        let a: u16 = p
            .next()
            .unwrap_or("")
            .trim()
            .parse()
            .map_err(|_| msg("invalid port"))?;
        let b: u16 = match p.next() {
            Some(v) => v.trim().parse().map_err(|_| msg("invalid port"))?,
            None => a,
        };
        if a == 0 || a > b || p.next().is_some() {
            return Err(msg("invalid port range"));
        }
        ranges.push((a, b));
    }
    ranges.sort_unstable();
    let mut out: Vec<(u16, u16)> = Vec::new();
    for (a, b) in ranges {
        if let Some(last) = out.last_mut()
            && a as u32 <= last.1 as u32 + 1
        {
            last.1 = last.1.max(b);
            continue;
        }
        out.push((a, b));
    }
    Ok(out)
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Completed,
    Partial,
    Failed,
    TimedOut,
    Skipped,
    Unsupported,
    NotRun,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Overall {
    Complete,
    Incomplete,
    Inconclusive,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Process {
    Completed,
    Failed,
    TimedOut,
    NotRun,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub id: String,
    pub run_id: String,
    pub category: String,
    pub source_artifact: String,
    pub locator: String,
    pub provenance: String,
    pub fact: String,
    pub supporting_evidence_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub run_id: String,
    pub kind: ArtifactKind,
    pub path: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub id: String,
    pub run_id: String,
    pub kind: CheckKind,
    pub required: bool,
    pub status: Status,
    pub reason_code: String,
    pub evidence_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunResult {
    pub id: String,
    pub tool: Tool,
    pub process: Process,
    pub authentication: AuthenticationState,
    pub findings: usize,
    pub version: Option<String>,
    pub declared_scan_type: Option<String>,
    pub requested_ports: Option<String>,
    pub aggregate_port_states: BTreeMap<String, usize>,
    pub automation_warnings: usize,
    pub statistics_present: bool,
    pub planned_jobs: Vec<String>,
    pub observed_targets: Vec<String>,
    pub observed_host_states: BTreeMap<String, String>,
    pub observed_routes: Vec<String>,
    pub evidence_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthenticationState {
    NotRequired,
    NotAttempted,
    Failed,
    ToolReportedSuccess,
    VerifiedSuccess,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub check_id: String,
    pub dimension: String,
    pub expected: Option<usize>,
    pub observed: Option<usize>,
    pub status: Status,
    pub evidence_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Limitation {
    pub reason_code: String,
    pub explanation: String,
    pub run_id: String,
    pub check_id: Option<String>,
    pub evidence_ids: Vec<String>,
    pub remediation: String,
    pub affects_required: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub tools_scheduled: usize,
    pub tools_completed: usize,
    pub tools_incomplete: usize,
    pub tools_unknown: usize,
    pub required_checks: usize,
    pub completed_checks: usize,
    pub incomplete_checks: usize,
    pub unknown_checks: usize,
    pub reported_findings: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyResult {
    pub completeness: String,
    pub findings: String,
    pub status: String,
    pub reason_codes: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u32,
    pub assessment: AssessmentReceipt,
    pub summary: Summary,
    pub runs: Vec<RunResult>,
    pub checks: Vec<CheckResult>,
    pub coverage: Vec<Coverage>,
    pub limitations: Vec<Limitation>,
    pub artifacts: Vec<ArtifactDigest>,
    pub evidence: Vec<Evidence>,
    pub policy: PolicyResult,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssessmentReceipt {
    pub id: String,
    pub name: String,
    pub status: Overall,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub schema_version: u32,
    pub run_id: String,
    pub tool: Tool,
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub timed_out: bool,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub finished_at: Option<String>,
    #[serde(default)]
    pub termination_reason: Option<String>,
    pub source: String,
    #[serde(default)]
    pub stages: Vec<Stage>,
}
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    pub check_id: String,
    pub status: Status,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub selected_templates: Vec<String>,
    #[serde(default)]
    pub selected_targets: Vec<String>,
    #[serde(default)]
    pub observed_routes: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub schema_version: u32,
    pub run_id: String,
    pub target: String,
    pub protected_resource: String,
    pub authenticated_access: bool,
    pub unauthenticated_access: bool,
}

fn add_evidence(
    e: &mut Vec<Evidence>,
    run: &str,
    category: &str,
    artifact: &str,
    locator: &str,
    provenance: &str,
    fact: &str,
) -> String {
    let seed = format!("{run}\0{category}\0{artifact}\0{locator}\0{fact}");
    let id = format!("ev-{}", &digest(seed.as_bytes())[..16]);
    e.push(Evidence {
        id: id.clone(),
        run_id: run.into(),
        category: category.into(),
        source_artifact: artifact.into(),
        locator: locator.into(),
        provenance: provenance.into(),
        fact: fact.into(),
        supporting_evidence_ids: Vec::new(),
    });
    id
}

pub fn analyze(manifest_path: &Path) -> Result<Receipt> {
    analyze_with_limit(manifest_path, MAX_ARTIFACT_BYTES)
}
pub fn analyze_with_limit(manifest_path: &Path, max_artifact_bytes: u64) -> Result<Receipt> {
    if max_artifact_bytes == 0 || max_artifact_bytes > 128 * 1024 * 1024 {
        return Err(msg("max_artifact_bytes must be between 1 and 134217728"));
    }
    let m = load_manifest(manifest_path)?;
    let base = manifest_path.parent().unwrap_or(Path::new("."));
    let mut evidence = Vec::new();
    let mut artifacts = Vec::new();
    let mut runs = Vec::new();
    let mut checks = Vec::new();
    let mut limitations = Vec::new();
    let mut parsed = BTreeMap::new();
    for run in &m.runs {
        let mut obs = adapters::Observation::default();
        let mut execution: Option<Execution> = None;
        let mut verification: Option<Verification> = None;
        let mut ev_ids = Vec::new();
        for art in &run.artifacts {
            let p = base.join(&art.path);
            if !p.exists() {
                limitations.push(Limitation {
                    reason_code: "ARTIFACT_MISSING".into(),
                    explanation: format!("Declared artifact is missing: {}", art.path),
                    run_id: run.id.clone(),
                    check_id: None,
                    evidence_ids: Vec::new(),
                    remediation: "Capture the declared artifact and rerun analysis.".into(),
                    affects_required: false,
                });
                continue;
            }
            let streamed = if matches!(run.tool, Tool::Nuclei)
                && matches!(art.kind, ArtifactKind::Findings | ArtifactKind::Statistics)
            {
                Some(read_nuclei_jsonl(&p, &art.kind, max_artifact_bytes)?)
            } else {
                None
            };
            let bytes = if streamed.is_none() {
                Some(read_bounded_limit(&p, max_artifact_bytes)?)
            } else {
                None
            };
            artifacts.push(ArtifactDigest {
                run_id: run.id.clone(),
                kind: art.kind.clone(),
                path: art.path.clone(),
                sha256: streamed
                    .as_ref()
                    .map(|(_, sha)| sha.clone())
                    .unwrap_or_else(|| digest(bytes.as_deref().unwrap_or_default())),
            });
            let bytes = bytes.as_deref().unwrap_or_default();
            match art.kind {
                ArtifactKind::Execution => {
                    let x: Execution = serde_json::from_slice(bytes)?;
                    if x.schema_version != 1
                        || x.run_id != run.id
                        || std::mem::discriminant(&x.tool) != std::mem::discriminant(&run.tool)
                    {
                        return Err(msg(format!("execution sidecar mismatch in {}", art.path)));
                    }
                    let mut seen = BTreeSet::new();
                    for (stage_index, stage) in x.stages.iter().enumerate() {
                        if !m
                            .checks
                            .iter()
                            .any(|c| c.id == stage.check_id && c.run_id == run.id)
                            || !seen.insert(&stage.check_id)
                        {
                            return Err(msg(format!(
                                "invalid or duplicate stage check_id in {}",
                                art.path
                            )));
                        }
                        for route in &stage.observed_routes {
                            if !route.starts_with('/') || route.contains('?') || route.contains('#')
                            {
                                return Err(msg(
                                    "observed_routes must be path-only without query or fragment",
                                ));
                            }
                        }
                        ev_ids.push(add_evidence(&mut evidence, &run.id, "stage_outcome", &art.path, &format!("/stages/{stage_index}/status"), "RUNNER_ATTESTATION", &format!("check {} status {:?}; selected templates {}; selected targets {}; observed routes {}", stage.check_id, stage.status, stage.selected_templates.len(), stage.selected_targets.len(), stage.observed_routes.len())));
                        if stage.target.as_deref().is_some_and(|t| {
                            run.scope_ids.iter().any(|id| {
                                m.scope
                                    .iter()
                                    .any(|scope| &scope.id == id && scope.value == t)
                            })
                        }) {
                            obs.routes.extend(stage.observed_routes.iter().cloned());
                        }
                    }
                    let process_fact =
                        format!("exit_code {:?}; timed_out {}", x.exit_code, x.timed_out);
                    execution = Some(x);
                    ev_ids.push(add_evidence(
                        &mut evidence,
                        &run.id,
                        "execution",
                        &art.path,
                        "/exit_code",
                        "RUNNER_ATTESTATION",
                        &process_fact,
                    ));
                }
                ArtifactKind::Verification => {
                    let x: Verification = serde_json::from_slice(bytes)?;
                    if x.schema_version != 1 || x.run_id != run.id {
                        return Err(msg("verification sidecar mismatch"));
                    }
                    let verification_fact = format!(
                        "authenticated_access {}; unauthenticated_access {}",
                        x.authenticated_access, x.unauthenticated_access
                    );
                    verification = Some(x);
                    ev_ids.push(add_evidence(
                        &mut evidence,
                        &run.id,
                        "authentication_verification",
                        &art.path,
                        "/authenticated_access",
                        "RUNNER_ATTESTATION",
                        &verification_fact,
                    ));
                }
                ArtifactKind::Report
                | ArtifactKind::Findings
                | ArtifactKind::Statistics
                | ArtifactKind::Authentication
                | ArtifactKind::Plan => {
                    let v = if let Some((observation, _)) = streamed {
                        observation
                    } else {
                        adapters::parse(&run.tool, &art.kind, bytes)?
                    };
                    let (locator, provenance, fact) = match (&run.tool, &art.kind) {
                        (Tool::Nmap, ArtifactKind::Report) => (
                            "/nmaprun",
                            "NATIVE_REPORT",
                            format!(
                                "native completion {:?}; {} targets; {} explicit TCP port states",
                                v.native_complete,
                                v.targets.len(),
                                v.ports.len()
                            ),
                        ),
                        (Tool::Zap, ArtifactKind::Authentication) => (
                            "/summaryItems",
                            "NATIVE_REPORT",
                            format!(
                                "tool authentication success {}; failure {}",
                                v.auth_success, v.auth_failed
                            ),
                        ),
                        (Tool::Zap, ArtifactKind::Report) => (
                            "/site",
                            "NATIVE_REPORT",
                            format!(
                                "{} reported alerts; automation errors {}",
                                v.findings, v.af_error
                            ),
                        ),
                        (Tool::Nuclei, ArtifactKind::Findings) => (
                            "/",
                            "NATIVE_REPORT",
                            format!("{} reported findings", v.findings),
                        ),
                        (_, ArtifactKind::Plan) => (
                            "/jobs",
                            "USER_DECLARATION",
                            format!("{} planned jobs; intent only", v.planned_jobs.len()),
                        ),
                        _ => (
                            "/",
                            "NATIVE_REPORT",
                            "scanner statistics supplied; no individual execution proof".into(),
                        ),
                    };
                    obs.merge(v);
                    ev_ids.push(add_evidence(
                        &mut evidence,
                        &run.id,
                        "scanner_observation",
                        &art.path,
                        locator,
                        provenance,
                        &fact,
                    ));
                }
            }
        }
        let scope_values: BTreeSet<&str> = run
            .scope_ids
            .iter()
            .filter_map(|id| {
                m.scope
                    .iter()
                    .find(|s| &s.id == id)
                    .map(|s| s.value.as_str())
            })
            .collect();
        obs.targets.retain(|t| scope_values.contains(t.as_str()));
        let auth_applies = obs
            .auth_target
            .as_deref()
            .is_some_and(|t| scope_values.contains(t));
        if auth_applies && obs.auth_failed && obs.auth_success {
            obs.conflict = true;
        }
        if let Some(v) = &verification
            && scope_values.contains(v.target.as_str())
            && auth_applies
            && ((obs.auth_failed && verification_valid(v, run, &m))
                || (obs.auth_success && (!v.authenticated_access || v.unauthenticated_access)))
        {
            obs.conflict = true;
        }
        if execution
            .as_ref()
            .is_some_and(|x| x.timed_out && x.exit_code == Some(0))
        {
            obs.conflict = true;
        }
        let mut process = match execution.as_ref() {
            Some(x)
                if x.termination_reason.as_deref() == Some("not_started")
                    && x.exit_code.is_none() =>
            {
                Process::NotRun
            }
            Some(x) if x.timed_out => Process::TimedOut,
            Some(x) if x.exit_code == Some(0) => Process::Completed,
            Some(x) if x.exit_code.is_some() => Process::Failed,
            _ => Process::Unknown,
        };
        if obs.native_complete == Some(true) {
            if matches!(
                process,
                Process::Failed | Process::TimedOut | Process::NotRun
            ) {
                obs.conflict = true;
            } else {
                process = Process::Completed;
            }
        }
        if obs.native_complete == Some(false) {
            if matches!(process, Process::Completed) {
                obs.conflict = true;
            }
            process = Process::Failed;
        }
        if obs.conflict {
            limitations.push(Limitation {
                reason_code: "CONFLICTING_EVIDENCE".into(),
                explanation: "Evidence sources or fields disagree about this run.".into(),
                run_id: run.id.clone(),
                check_id: None,
                evidence_ids: ev_ids.clone(),
                remediation: "Inspect native and runner evidence, then capture a consistent rerun."
                    .into(),
                affects_required: m.checks.iter().any(|c| c.run_id == run.id && c.required),
            });
        }
        if !obs.conflict
            && matches!(
                process,
                Process::Failed | Process::TimedOut | Process::NotRun
            )
        {
            let reason = match process {
                Process::Failed => "TOOL_EXECUTION_FAILED",
                Process::TimedOut => "TOOL_TIMED_OUT",
                Process::NotRun => "TOOL_NOT_RUN",
                Process::Completed | Process::Unknown => "CHECK_EXECUTION_UNKNOWN",
            };
            limitations.push(Limitation {
                reason_code: reason.into(),
                explanation: "Scanner process did not complete successfully; individual check outcomes require separate evidence.".into(),
                run_id: run.id.clone(), check_id: None, evidence_ids: ev_ids.clone(),
                remediation: "Repair the scanner run and capture execution and stage evidence.".into(),
                affects_required: m.checks.iter().any(|c| c.run_id == run.id && c.required),
            });
        }
        let authentication = if !m
            .checks
            .iter()
            .any(|c| c.run_id == run.id && matches!(c.kind, CheckKind::Authentication))
        {
            AuthenticationState::NotRequired
        } else if (obs.auth_failed
            && obs
                .auth_target
                .as_deref()
                .is_some_and(|t| scope_values.contains(t)))
            || verification.as_ref().is_some_and(|v| {
                scope_values.contains(v.target.as_str())
                    && (!v.authenticated_access || v.unauthenticated_access)
            })
        {
            AuthenticationState::Failed
        } else if verification
            .as_ref()
            .is_some_and(|v| verification_valid(v, run, &m))
        {
            AuthenticationState::VerifiedSuccess
        } else if obs.auth_success
            && obs
                .auth_target
                .as_deref()
                .is_some_and(|t| scope_values.contains(t))
        {
            AuthenticationState::ToolReportedSuccess
        } else if execution.as_ref().is_some_and(|x| {
            x.stages.iter().any(|s| {
                matches!(s.status, Status::NotRun | Status::Skipped)
                    && m.checks
                        .iter()
                        .any(|c| c.id == s.check_id && matches!(c.kind, CheckKind::Authentication))
            })
        }) {
            AuthenticationState::NotAttempted
        } else {
            AuthenticationState::Unknown
        };
        let declared_routes: BTreeSet<&str> = m
            .checks
            .iter()
            .filter(|c| c.run_id == run.id)
            .flat_map(|c| c.criteria.expected_routes.iter().map(String::as_str))
            .collect();
        runs.push(RunResult {
            id: run.id.clone(),
            tool: run.tool.clone(),
            process,
            authentication,
            findings: obs.findings,
            version: obs.version.clone(),
            declared_scan_type: obs.scan_type.clone(),
            requested_ports: obs.requested_ports.clone(),
            aggregate_port_states: obs.aggregate_port_states.clone(),
            automation_warnings: obs.af_warnings,
            statistics_present: obs.statistics_present,
            planned_jobs: obs.planned_jobs.clone(),
            observed_targets: obs.targets.iter().cloned().collect(),
            observed_host_states: obs
                .host_states
                .iter()
                .filter(|(t, _)| scope_values.contains(t.as_str()))
                .map(|(t, s)| (t.clone(), s.clone()))
                .collect(),
            observed_routes: obs
                .routes
                .iter()
                .map(|route| {
                    if declared_routes.contains(route.as_str()) {
                        route.clone()
                    } else {
                        format!("sha256:{}", digest(route.as_bytes()))
                    }
                })
                .collect(),
            evidence_ids: ev_ids.clone(),
        });
        parsed.insert(run.id.clone(), (obs, execution, verification, ev_ids));
    }
    for c in &m.checks {
        let run = m
            .runs
            .iter()
            .find(|r| r.id == c.run_id)
            .ok_or_else(|| msg("unknown run"))?;
        let (obs, execution, verification, ev_ids) =
            parsed.get(&c.run_id).ok_or_else(|| msg("unparsed run"))?;
        let (mut status, mut reason) =
            evaluate(c, run, &m, obs, execution.as_ref(), verification.as_ref());
        if obs.conflict && status == Status::Completed {
            status = Status::Unknown;
            reason = "CONFLICTING_EVIDENCE";
        }
        let result = CheckResult {
            id: c.id.clone(),
            run_id: c.run_id.clone(),
            kind: c.kind.clone(),
            required: c.required,
            status: status.clone(),
            reason_code: reason.into(),
            evidence_ids: ev_ids.clone(),
        };
        checks.push(result);
    }
    // Resolve dependencies after all base results exist, so manifest order cannot change outcomes.
    for _ in 0..checks.len() {
        let previous: BTreeMap<String, Status> = checks
            .iter()
            .map(|c| (c.id.clone(), c.status.clone()))
            .collect();
        let mut changed = false;
        for (result, declared) in checks.iter_mut().zip(&m.checks) {
            if declared
                .depends_on
                .iter()
                .any(|d| previous.get(d) != Some(&Status::Completed))
                && matches!(
                    result.status,
                    Status::Completed | Status::Partial | Status::Unknown
                )
                && result.reason_code != "DEPENDENCY_UNSATISFIED"
            {
                result.status = Status::Unknown;
                result.reason_code = "DEPENDENCY_UNSATISFIED".into();
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for (index, c) in checks.iter_mut().enumerate() {
        let declaration = add_evidence(
            &mut evidence,
            &c.run_id,
            "expected_check",
            "assessment_manifest",
            &format!("/checks/{index}"),
            "USER_DECLARATION",
            &format!(
                "{} {:?} check",
                if c.required { "required" } else { "optional" },
                c.kind
            ),
        );
        c.evidence_ids.push(declaration);
        let fact = format!("status {:?}; reason {}", c.status, c.reason_code);
        let seed = format!("{}\0{}\0{}", c.run_id, c.id, fact);
        let id = format!("ev-{}", &digest(seed.as_bytes())[..16]);
        evidence.push(Evidence {
            id: id.clone(),
            run_id: c.run_id.clone(),
            category: "check_outcome".into(),
            source_artifact: "security-assessment-coverage-reporter".into(),
            locator: format!("/checks/{index}"),
            provenance: "DERIVED".into(),
            fact,
            supporting_evidence_ids: c.evidence_ids.clone(),
        });
        c.evidence_ids.push(id);
    }
    for c in &checks {
        if c.status != Status::Completed {
            limitations.push(Limitation {
                reason_code: c.reason_code.clone(),
                explanation: explain_reason(&c.reason_code).into(),
                run_id: c.run_id.clone(),
                check_id: Some(c.id.clone()),
                evidence_ids: c.evidence_ids.clone(),
                remediation: remedy(&c.reason_code).into(),
                affects_required: c.required,
            });
        }
    }
    let coverage = checks
        .iter()
        .zip(&m.checks)
        .map(|(result, declared)| {
            let (obs, execution, _, _) = parsed
                .get(&declared.run_id)
                .ok_or_else(|| msg("validated run missing during coverage evaluation"))?;
            let scope_values: Vec<&str> = m
                .runs
                .iter()
                .find(|r| r.id == declared.run_id)
                .map(|r| {
                    r.scope_ids
                        .iter()
                        .filter_map(|id| {
                            m.scope
                                .iter()
                                .find(|s| &s.id == id)
                                .map(|s| s.value.as_str())
                        })
                        .collect()
                })
                .unwrap_or_default();
            let scope_count = scope_values.len();
            let (dimension, expected, observed) = match declared.kind {
                CheckKind::TcpPortScan => {
                    let ranges = declared
                        .criteria
                        .ports
                        .as_deref()
                        .and_then(|p| parse_ports(p).ok())
                        .unwrap_or_default();
                    let per_target: usize = ranges
                        .iter()
                        .map(|(a, b)| (*b as usize) - (*a as usize) + 1)
                        .sum();
                    (
                        "tcp_ports",
                        Some(per_target * scope_count),
                        Some(
                            scope_values
                                .iter()
                                .filter(|t| obs.host_up.contains(**t))
                                .map(|t| {
                                    ranges
                                        .iter()
                                        .map(|(a, b)| {
                                            (*a..=*b)
                                                .filter(|p| {
                                                    obs.ports.contains(&(t.to_string(), *p))
                                                })
                                                .count()
                                        })
                                        .sum::<usize>()
                                })
                                .sum(),
                        ),
                    )
                }
                CheckKind::RouteDiscovery => {
                    let count = execution
                        .as_ref()
                        .and_then(|x| x.stages.iter().find(|s| s.check_id == declared.id))
                        .map(|s| s.observed_routes.len());
                    (
                        "web_routes",
                        Some(
                            declared
                                .criteria
                                .minimum_observed_routes
                                .unwrap_or(0)
                                .max(declared.criteria.expected_routes.len()),
                        ),
                        count,
                    )
                }
                CheckKind::TemplateScan => (
                    "selected_templates",
                    Some(declared.criteria.expected_templates.len()),
                    execution
                        .as_ref()
                        .and_then(|x| x.stages.iter().find(|s| s.check_id == declared.id))
                        .map(|s| {
                            declared
                                .criteria
                                .expected_templates
                                .iter()
                                .filter(|t| s.selected_templates.contains(t))
                                .count()
                        }),
                ),
                CheckKind::HostDiscovery => (
                    "targets",
                    Some(scope_count),
                    Some(
                        scope_values
                            .iter()
                            .filter(|t| obs.targets.contains(**t))
                            .count(),
                    ),
                ),
                CheckKind::Authentication => ("authentication", None, None),
                CheckKind::ActiveScan => ("scan_stage", None, None),
            };
            Ok(Coverage {
                check_id: result.id.clone(),
                dimension: dimension.into(),
                expected,
                observed,
                status: result.status.clone(),
                evidence_ids: result.evidence_ids.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for c in &checks {
        if matches!(c.kind, CheckKind::TemplateScan) && c.status == Status::Completed {
            limitations.push(Limitation {
                reason_code: "TEMPLATE_EXECUTION_UNVERIFIED".into(),
                explanation: "Selected template set was attested; per-template-per-target execution remains unverified.".into(),
                run_id: c.run_id.clone(), check_id: Some(c.id.clone()), evidence_ids: c.evidence_ids.clone(),
                remediation: "Capture per-template-per-target execution evidence if that finer claim is required.".into(),
                affects_required: false,
            });
        }
    }
    let required_run_failure = runs.iter().any(|r| {
        matches!(
            r.process,
            Process::Failed | Process::TimedOut | Process::NotRun
        ) && m.checks.iter().any(|c| c.required && c.run_id == r.id)
            && parsed
                .get(&r.id)
                .is_some_and(|(obs, _, _, _)| !obs.conflict)
    });
    let overall = if required_run_failure
        || checks
            .iter()
            .any(|c| c.required && !matches!(c.status, Status::Completed | Status::Unknown))
    {
        Overall::Incomplete
    } else if checks
        .iter()
        .any(|c| c.required && c.status == Status::Unknown)
        || limitations
            .iter()
            .any(|l| l.reason_code == "CONFLICTING_EVIDENCE" && l.affects_required)
    {
        Overall::Inconclusive
    } else {
        Overall::Complete
    };
    let findings = runs.iter().map(|r| r.findings).sum();
    let completeness_fail = matches!(
        (&overall, &m.policy.on_incomplete, &m.policy.on_inconclusive),
        (Overall::Incomplete, Action::Fail, _) | (Overall::Inconclusive, _, Action::Fail)
    );
    let findings_fail = findings > 0 && matches!(m.policy.on_findings, Action::Fail);
    let policy = PolicyResult {
        completeness: if completeness_fail { "fail" } else { "pass" }.into(),
        findings: if findings_fail { "fail" } else { "pass" }.into(),
        status: if completeness_fail || findings_fail {
            "fail"
        } else {
            "pass"
        }
        .into(),
        reason_codes: [
            if completeness_fail {
                Some("ASSESSMENT_NOT_COMPLETE".into())
            } else {
                None
            },
            if findings_fail {
                Some("FINDINGS_PRESENT".into())
            } else {
                None
            },
        ]
        .into_iter()
        .flatten()
        .collect(),
    };
    let summary = Summary {
        tools_scheduled: runs.len(),
        tools_completed: runs
            .iter()
            .filter(|r| matches!(r.process, Process::Completed))
            .count(),
        tools_incomplete: runs
            .iter()
            .filter(|r| {
                matches!(
                    r.process,
                    Process::Failed | Process::TimedOut | Process::NotRun
                )
            })
            .count(),
        tools_unknown: runs
            .iter()
            .filter(|r| matches!(r.process, Process::Unknown))
            .count(),
        required_checks: checks.iter().filter(|c| c.required).count(),
        completed_checks: checks
            .iter()
            .filter(|c| c.required && c.status == Status::Completed)
            .count(),
        incomplete_checks: checks
            .iter()
            .filter(|c| c.required && !matches!(c.status, Status::Completed | Status::Unknown))
            .count(),
        unknown_checks: checks
            .iter()
            .filter(|c| c.required && c.status == Status::Unknown)
            .count(),
        reported_findings: findings,
    };
    evidence.sort_by(|a, b| a.id.cmp(&b.id));
    artifacts.sort_by(|a, b| (&a.run_id, &a.path).cmp(&(&b.run_id, &b.path)));
    limitations.sort_by(|a, b| {
        (&a.run_id, &a.check_id, &a.reason_code).cmp(&(&b.run_id, &b.check_id, &b.reason_code))
    });
    Ok(Receipt {
        schema_version: 1,
        assessment: AssessmentReceipt {
            id: m.assessment.id,
            name: m.assessment.name,
            status: overall,
        },
        summary,
        runs,
        checks,
        coverage,
        limitations,
        artifacts,
        evidence,
        policy,
    })
}

pub fn load_receipt(path: &Path) -> Result<Receipt> {
    let bytes = read_bounded_limit(path, 128 * 1024 * 1024)?;
    let receipt: Receipt = serde_json::from_slice(&bytes)?;
    if receipt.schema_version != 1 {
        return Err(msg("unsupported receipt schema_version"));
    }
    Ok(receipt)
}

pub fn canonical_json(r: &Receipt) -> Result<Vec<u8>> {
    let mut s = serde_json::to_vec_pretty(r)?;
    s.push(b'\n');
    Ok(s)
}
pub fn schema(name: &str) -> Result<String> {
    let value = match name {
        "manifest" => serde_json::to_value(schema_for!(Manifest))?,
        "receipt" => serde_json::to_value(schema_for!(Receipt))?,
        "execution" => serde_json::to_value(schema_for!(Execution))?,
        "verification" => serde_json::to_value(schema_for!(Verification))?,
        _ => {
            return Err(msg(
                "schema must be manifest, receipt, execution, or verification",
            ));
        }
    };
    Ok(serde_json::to_string_pretty(&value)? + "\n")
}
