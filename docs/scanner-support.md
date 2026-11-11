# Scanner support and source formats

The adapters are intentionally narrow. They parse only documented native fields and never equate zero findings with complete execution.

## Nmap XML

Reads `nmaprun` version, TCP `scaninfo` type and requested services, `host/status`, IPv4/IPv6 `address`, user-supplied `hostname` aliases, explicit host states, explicit TCP `port/state`, aggregate `extraports`, and `runstats/finished/@exit`. Port checks require an up host, exact target match, explicit state evidence for each declared port, and native successful completion. `open`, `closed`, and `filtered` all show a port was checked; none is a vulnerability finding by itself. `extraports` is aggregate and is not allocated to specific expected ports. A down host may satisfy host discovery but not a port check. DTDs and XML nesting beyond 128 levels are rejected. XML syntax must be complete. Source: [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html) and [DTD](https://nmap.org/book/nmap-dtd.html). Declared Nmap XML output versions `1.03` through `1.05` are accepted; other declared XML output versions are rejected. Reports without this attribute are parsed by the documented field subset, without a version certification claim.

## ZAP Traditional JSON / JSON Plus

Reads `@version`, `site[].@name`, `site[].alerts`, `afPlanErrors`, the count of `afPlanWarns`, and the presence of a statistics section. Statistics presence alone does not establish stage completion. A report's alert count does not establish spider or active-scan completion. A YAML/JSON Automation Framework plan contributes only `jobs[].type` as planned job types; it is intent, not execution proof. See the [Automation Framework plan documentation](https://www.zaproxy.org/docs/desktop/addons/automation-framework/). Authentication Report JSON reads `site` and `summaryItems[]` for `auth.summary.auth` with boolean `passed`. Other diagnostics, messages, and storage sections are ignored and never copied to a receipt. The auth summary is a tool-reported result, not independent verification. Sources: [Traditional JSON](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/), [JSON Plus](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json-plus/), and [Authentication Report JSON](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-report-json/). No blanket ZAP version range is certified.

## Nuclei JSONL

Finding lines are parsed as JSON objects with nonempty `template-id` and `host` fields; other fields are not copied. `host` is retained only as an observed finding target; the findings file is never execution evidence. Statistics JSONL is syntax-checked and its presence reported, but is not used to establish individual template execution. An explicit versioned external stage attestation plus zero exit and matching selected template/target sets can satisfy a _selected-set_ check. It cannot establish per-template-per-target execution. Source: [Nuclei output documentation](https://docs.projectdiscovery.io/opensource/nuclei/running#output).

Compatibility is based on the fields above. Unsupported or malformed formats produce an input error rather than an optimistic receipt.
