//! Narrow allowlist parsers for scanner-native artifacts.
use crate::{ArtifactKind, Error, Result, Tool};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default, Clone)]
pub struct Observation {
    pub native_complete: Option<bool>,
    pub conflict: bool,
    pub findings: usize,
    pub version: Option<String>,
    pub scan_type: Option<String>,
    pub requested_ports: Option<String>,
    pub aggregate_port_states: BTreeMap<String, usize>,
    pub af_warnings: usize,
    pub statistics_present: bool,
    pub planned_jobs: Vec<String>,
    pub targets: BTreeSet<String>,
    pub host_up: BTreeSet<String>,
    pub host_states: BTreeMap<String, String>,
    pub ports: BTreeSet<(String, u16)>,
    pub routes: BTreeSet<String>,
    pub auth_failed: bool,
    pub auth_success: bool,
    pub auth_target: Option<String>,
    pub af_error: bool,
}
impl Observation {
    pub fn merge(&mut self, other: Self) {
        if let (Some(a), Some(b)) = (self.native_complete, other.native_complete)
            && a != b
        {
            self.conflict = true;
        }
        self.native_complete = self.native_complete.or(other.native_complete);
        self.conflict |= other.conflict;
        self.findings += other.findings;
        self.af_warnings += other.af_warnings;
        self.statistics_present |= other.statistics_present;
        self.planned_jobs.extend(other.planned_jobs);
        self.version = self.version.take().or(other.version);
        self.scan_type = self.scan_type.take().or(other.scan_type);
        self.requested_ports = self.requested_ports.take().or(other.requested_ports);
        for (state, count) in other.aggregate_port_states {
            *self.aggregate_port_states.entry(state).or_default() += count;
        }
        self.targets.extend(other.targets);
        self.host_up.extend(other.host_up);
        self.host_states.extend(other.host_states);
        self.ports.extend(other.ports);
        self.routes.extend(other.routes);
        self.auth_failed |= other.auth_failed;
        self.auth_success |= other.auth_success;
        if self.auth_target.is_none() {
            self.auth_target = other.auth_target;
        }
        self.af_error |= other.af_error;
    }
}
pub fn parse(tool: &Tool, kind: &ArtifactKind, bytes: &[u8]) -> Result<Observation> {
    match (tool, kind) {
        (Tool::Nmap, ArtifactKind::Report) => nmap(bytes),
        (Tool::Zap, ArtifactKind::Report | ArtifactKind::Authentication | ArtifactKind::Plan) => {
            zap(kind, bytes)
        }
        (Tool::Nuclei, ArtifactKind::Findings | ArtifactKind::Statistics) => nuclei(kind, bytes),
        _ => Err(Error::Message("unsupported artifact kind for tool".into())),
    }
}
fn attr(e: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Option<String> {
    e.attributes()
        .with_checks(true)
        .flatten()
        .find(|a| a.key.as_ref() == name)
        .map(|a| String::from_utf8_lossy(a.value.as_ref()).into_owned())
}
fn path_is(stack: &[String], names: &[&str]) -> bool {
    stack.len() == names.len() && stack.iter().zip(names).all(|(a, b)| a == b)
}
fn nmap(bytes: &[u8]) -> Result<Observation> {
    use quick_xml::{Reader, events::Event};
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut o = Observation::default();
    let mut current: Vec<String> = Vec::new();
    let mut host_addresses: Vec<String> = Vec::new();
    let mut host_state: Option<String> = None;
    let mut root = false;
    let mut ended = false;
    let mut finished = false;
    let mut tcp = false;
    let mut current_port: Option<u16> = None;
    loop {
        match reader.read_event() {
            Ok(ev @ (Event::Start(_) | Event::Empty(_))) => {
                let e = match &ev {
                    Event::Start(e) | Event::Empty(e) => e,
                    _ => return Err(Error::Message("unexpected XML event".into())),
                };
                let is_empty = matches!(ev, Event::Empty(_));
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if ended || (!root && name != "nmaprun") || (name == "nmaprun" && root) {
                    return Err(Error::Message("invalid Nmap XML root structure".into()));
                }
                match name.as_str() {
                    "nmaprun" => {
                        root = true;
                        o.version = attr(e, b"version").filter(|v| {
                            v.len() <= 32
                                && v.bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                        });
                        if attr(e, b"xmloutputversion")
                            .is_some_and(|v| !matches!(v.as_str(), "1.03" | "1.04" | "1.05"))
                        {
                            return Err(Error::Message(
                                "unsupported Nmap XML output version".into(),
                            ));
                        }
                        if attr(e, b"scanner").as_deref() != Some("nmap") {
                            return Err(Error::Message("not an Nmap XML report".into()));
                        }
                    }
                    "scaninfo" if path_is(&current, &["nmaprun"]) => {
                        if attr(e, b"protocol").as_deref() == Some("tcp") {
                            tcp = true;
                            o.scan_type = attr(e, b"type").filter(|v| {
                                v.len() <= 32
                                    && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                            });
                            o.requested_ports = attr(e, b"services").filter(|v| {
                                v.len() <= 256
                                    && v.bytes()
                                        .all(|b| b.is_ascii_digit() || b == b',' || b == b'-')
                            });
                        }
                    }
                    "host" if path_is(&current, &["nmaprun"]) => {
                        host_addresses.clear();
                        host_state = None;
                    }
                    "status" if path_is(&current, &["nmaprun", "host"]) => {
                        host_state =
                            attr(e, b"state").filter(|v| matches!(v.as_str(), "up" | "down"));
                    }
                    "address" if path_is(&current, &["nmaprun", "host"]) => {
                        if matches!(attr(e, b"addrtype").as_deref(), Some("ipv4" | "ipv6"))
                            && let Some(address) = attr(e, b"addr")
                        {
                            host_addresses.push(address);
                        }
                    }
                    "hostname" if path_is(&current, &["nmaprun", "host", "hostnames"]) => {
                        if attr(e, b"type").as_deref() == Some("user")
                            && let Some(name) = attr(e, b"name")
                        {
                            host_addresses.push(name);
                        }
                    }
                    "port" if path_is(&current, &["nmaprun", "host", "ports"]) => {
                        current_port = if tcp
                            && host_state.as_deref() == Some("up")
                            && attr(e, b"protocol").as_deref() == Some("tcp")
                        {
                            attr(e, b"portid")
                                .and_then(|s| s.parse::<u16>().ok())
                                .filter(|p| *p > 0)
                        } else {
                            None
                        };
                    }
                    "state" if path_is(&current, &["nmaprun", "host", "ports", "port"]) => {
                        if let Some(p) = current_port
                            && matches!(
                                attr(e, b"state").as_deref(),
                                Some(
                                    "open"
                                        | "closed"
                                        | "filtered"
                                        | "unfiltered"
                                        | "open|filtered"
                                        | "closed|filtered"
                                )
                            )
                        {
                            for address in &host_addresses {
                                o.ports.insert((address.clone(), p));
                            }
                        }
                    }
                    "extraports" if path_is(&current, &["nmaprun", "host", "ports"]) => {
                        if let (Some(state), Some(count)) = (
                            attr(e, b"state"),
                            attr(e, b"count").and_then(|s| s.parse::<usize>().ok()),
                        ) && matches!(
                            state.as_str(),
                            "open"
                                | "closed"
                                | "filtered"
                                | "unfiltered"
                                | "open|filtered"
                                | "closed|filtered"
                        ) {
                            *o.aggregate_port_states.entry(state).or_default() += count;
                        }
                    }
                    "finished" if path_is(&current, &["nmaprun", "runstats"]) => {
                        if finished {
                            return Err(Error::Message(
                                "duplicate Nmap completion metadata".into(),
                            ));
                        }
                        finished = true;
                        o.native_complete = attr(e, b"exit").map(|v| v == "success");
                    }
                    _ => {}
                }
                if is_empty {
                    if name == "host" {
                        record_host(&mut o, &host_addresses, host_state.as_deref());
                    }
                } else {
                    if current.len() >= 128 {
                        return Err(Error::Message("Nmap XML nesting exceeds 128 levels".into()));
                    }
                    current.push(name);
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name();
                if current.last().is_none_or(|n| n.as_bytes() != name.as_ref()) {
                    return Err(Error::Message("mismatched Nmap XML closing tag".into()));
                }
                if name.as_ref() == b"port" {
                    current_port = None;
                }
                if name.as_ref() == b"host" {
                    record_host(&mut o, &host_addresses, host_state.as_deref());
                }
                if name.as_ref() == b"nmaprun" {
                    ended = true;
                }
                current.pop();
            }
            Ok(Event::DocType(_)) => return Err(Error::Message("XML DTD is not accepted".into())),
            Ok(Event::Eof) => break,
            Err(e) => return Err(Error::Message(format!("invalid Nmap XML: {e}"))),
            _ => {}
        }
    }
    if !root || !ended || !finished {
        return Err(Error::Message("truncated or incomplete Nmap XML".into()));
    }
    Ok(o)
}
fn record_host(o: &mut Observation, addresses: &[String], state: Option<&str>) {
    for address in addresses {
        if address.is_empty() {
            continue;
        }
        o.targets.insert(address.clone());
        if state == Some("up") {
            o.host_up.insert(address.clone());
        }
        o.host_states
            .insert(address.clone(), state.unwrap_or("unknown").into());
    }
}
fn zap(kind: &ArtifactKind, bytes: &[u8]) -> Result<Observation> {
    let v: serde_json::Value = if *kind == ArtifactKind::Plan {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| Error::Message(format!("invalid ZAP plan UTF-8: {e}")))?;
        serde_saphyr::from_str(text)
            .map_err(|e| Error::Message(format!("invalid ZAP plan YAML: {e}")))?
    } else {
        serde_json::from_slice(bytes)?
    };
    let mut o = Observation::default();
    if *kind == ArtifactKind::Authentication {
        o.statistics_present = v.get("statistics").is_some();
        o.auth_target = v.get("site").and_then(|x| x.as_str()).map(str::to_owned);
        let arr = v
            .get("summaryItems")
            .and_then(|x| x.as_array())
            .ok_or_else(|| Error::Message("ZAP auth report lacks summaryItems".into()))?;
        for item in arr {
            if item.get("key").and_then(|x| x.as_str()) == Some("auth.summary.auth") {
                match item.get("passed").and_then(|x| x.as_bool()) {
                    Some(true) => o.auth_success = true,
                    Some(false) => o.auth_failed = true,
                    _ => {}
                }
            }
        }
    } else if *kind == ArtifactKind::Report {
        o.statistics_present = v.get("statistics").is_some();
        o.version = v
            .get("@version")
            .and_then(|x| x.as_str())
            .filter(|v| {
                v.len() <= 32
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            })
            .map(str::to_owned);
        o.af_warnings = v
            .get("afPlanWarns")
            .and_then(|x| x.as_array())
            .map_or(0, Vec::len);
        let sites = v
            .get("site")
            .and_then(|x| x.as_array())
            .ok_or_else(|| Error::Message("ZAP report lacks site array".into()))?;
        for s in sites {
            if let Some(name) = s.get("@name").and_then(|x| x.as_str()) {
                o.targets.insert(name.into());
            }
            if let Some(alerts) = s.get("alerts").and_then(|x| x.as_array()) {
                o.findings += alerts.len();
            }
        }
        o.af_error = v
            .get("afPlanErrors")
            .and_then(|x| x.as_array())
            .is_some_and(|a| !a.is_empty());
    } else {
        let jobs = v
            .get("jobs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::Message("ZAP plan lacks jobs array".into()))?;
        for job in jobs {
            if let Some(kind) = job.get("type").and_then(|v| v.as_str()).filter(|v| {
                v.len() <= 40 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }) {
                o.planned_jobs.push(kind.into());
            }
        }
    }
    Ok(o)
}
fn nuclei(kind: &ArtifactKind, bytes: &[u8]) -> Result<Observation> {
    let mut o = Observation::default();
    for (i, line) in bytes.split(|b| *b == b'\n').enumerate() {
        parse_nuclei_line(kind, line, i + 1, &mut o)?;
    }
    Ok(o)
}
pub(crate) fn parse_nuclei_line(
    kind: &ArtifactKind,
    line: &[u8],
    line_no: usize,
    o: &mut Observation,
) -> Result<()> {
    let line = std::str::from_utf8(line)
        .map_err(|e| Error::Message(format!("Nuclei JSONL line {line_no} invalid UTF-8: {e}")))?;
    if line.trim().is_empty() {
        return Ok(());
    }
    let v: serde_json::Value = serde_json::from_str(line)
        .map_err(|e| Error::Message(format!("Nuclei JSONL line {line_no}: {e}")))?;
    if !v.is_object() {
        return Err(Error::Message(format!(
            "Nuclei JSONL line {} is not an object",
            line_no
        )));
    }
    if *kind == ArtifactKind::Statistics {
        o.statistics_present = true;
    }
    if *kind == ArtifactKind::Findings {
        if v.get("template-id")
            .and_then(|x| x.as_str())
            .is_none_or(str::is_empty)
            || v.get("host")
                .and_then(|x| x.as_str())
                .is_none_or(str::is_empty)
        {
            return Err(Error::Message(format!(
                "Nuclei finding line {} lacks template-id or host",
                line_no
            )));
        }
        o.findings += 1;
        if let Some(host) = v.get("host").and_then(|x| x.as_str()) {
            o.targets.insert(host.into());
        }
    }
    Ok(())
}
