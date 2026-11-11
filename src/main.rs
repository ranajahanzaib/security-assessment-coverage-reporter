use clap::{Parser, Subcommand};
use security_assessment_coverage_reporter::{
    analyze, analyze_with_limit, canonical_json, load_manifest, load_receipt, render, schema,
};
use std::{fs, path::PathBuf, process::ExitCode};
#[derive(Parser)]
#[command(
    name = "security-assessment-coverage-reporter",
    version,
    about = "Know what your security scans actually tested"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(long, global = true)]
    quiet: bool,
    #[arg(long, global = true)]
    no_color: bool,
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long, default_value = "scanreceipt.yaml")]
        out: PathBuf,
    },
    Analyze {
        #[arg(long, default_value = "scanreceipt.yaml")]
        manifest: PathBuf,
        #[arg(long, default_value = "assessment-receipt.json")]
        out: PathBuf,
        #[arg(long)]
        html: Option<PathBuf>,
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        max_artifact_bytes: u64,
    },
    Validate {
        #[arg(long, default_value = "scanreceipt.yaml")]
        manifest: PathBuf,
        #[arg(long)]
        check_files: bool,
    },
    Explain {
        #[arg(long)]
        receipt: PathBuf,
    },
    Check {
        #[arg(long)]
        receipt: PathBuf,
    },
    Schema {
        #[arg(value_parser=["manifest","receipt","execution","verification"])]
        name: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Demo {
        #[arg(long, default_value = "security-assessment-coverage-reporter-demo")]
        out_dir: PathBuf,
    },
}
fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(n) => ExitCode::from(n),
        Err(e) => {
            eprintln!("security-assessment-coverage-reporter: {e}");
            ExitCode::from(3)
        }
    }
}
fn run(cli: Cli) -> security_assessment_coverage_reporter::Result<u8> {
    match cli.command {
        Command::Init { out } => {
            if out.exists() {
                return Err(security_assessment_coverage_reporter::Error::Message(
                    format!("{} already exists", out.display()),
                ));
            }
            fs::write(&out, include_str!("../examples/basic/scanreceipt.yaml")).map_err(|e| {
                security_assessment_coverage_reporter::Error::Message(e.to_string())
            })?;
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent.join("evidence")).map_err(|e| {
                    security_assessment_coverage_reporter::Error::Message(e.to_string())
                })?;
            }
            println!("Created {}", out.display());
            Ok(0)
        }
        Command::Analyze {
            manifest,
            out,
            html,
            max_artifact_bytes,
        } => {
            let receipt = analyze_with_limit(&manifest, max_artifact_bytes)?;
            fs::write(&out, canonical_json(&receipt)?).map_err(|e| {
                security_assessment_coverage_reporter::Error::Message(e.to_string())
            })?;
            if let Some(path) = html {
                fs::write(path, render::html(&receipt)).map_err(|e| {
                    security_assessment_coverage_reporter::Error::Message(e.to_string())
                })?;
            }
            if !cli.quiet {
                print!("{}", render::terminal(&receipt));
            }
            Ok(0)
        }
        Command::Validate {
            manifest,
            check_files,
        } => {
            let m = load_manifest(&manifest)?;
            if check_files {
                let base = manifest.parent().unwrap_or(std::path::Path::new("."));
                for r in &m.runs {
                    for a in &r.artifacts {
                        if !base.join(&a.path).is_file() {
                            return Err(security_assessment_coverage_reporter::Error::Message(
                                format!("missing {}", a.path),
                            ));
                        }
                    }
                }
            }
            if !cli.quiet {
                println!("Manifest valid");
            }
            Ok(0)
        }
        Command::Explain { receipt } => {
            let r = load_receipt(&receipt)?;
            print!("{}", render::terminal(&r));
            Ok(0)
        }
        Command::Check { receipt } => {
            let r = load_receipt(&receipt)?;
            if r.schema_version != 1 {
                return Err(security_assessment_coverage_reporter::Error::Message(
                    "unsupported receipt schema_version".into(),
                ));
            }
            println!("CI policy: {}", r.policy.status);
            Ok(if r.policy.status == "pass" { 0 } else { 2 })
        }
        Command::Schema { name, out } => {
            let s = schema(&name)?;
            if let Some(p) = out {
                fs::write(p, s).map_err(|e| {
                    security_assessment_coverage_reporter::Error::Message(e.to_string())
                })?;
            } else {
                print!("{s}");
            }
            Ok(0)
        }
        Command::Demo { out_dir } => {
            if out_dir.exists() {
                return Err(security_assessment_coverage_reporter::Error::Message(
                    "demo output already exists".into(),
                ));
            }
            fs::create_dir_all(out_dir.join("evidence")).map_err(|e| {
                security_assessment_coverage_reporter::Error::Message(e.to_string())
            })?;
            for (name, bytes) in [
                (
                    "scanreceipt.yaml",
                    include_bytes!("../examples/incomplete-assessment/scanreceipt.yaml").as_slice(),
                ),
                (
                    "evidence/nmap.xml",
                    include_bytes!("../examples/incomplete-assessment/evidence/nmap.xml")
                        .as_slice(),
                ),
                (
                    "evidence/zap.json",
                    include_bytes!("../examples/incomplete-assessment/evidence/zap.json")
                        .as_slice(),
                ),
                (
                    "evidence/zap-auth.json",
                    include_bytes!("../examples/incomplete-assessment/evidence/zap-auth.json")
                        .as_slice(),
                ),
                (
                    "evidence/zap-execution.json",
                    include_bytes!("../examples/incomplete-assessment/evidence/zap-execution.json")
                        .as_slice(),
                ),
                (
                    "evidence/nuclei.jsonl",
                    include_bytes!("../examples/incomplete-assessment/evidence/nuclei.jsonl")
                        .as_slice(),
                ),
                (
                    "evidence/nuclei-execution.json",
                    include_bytes!(
                        "../examples/incomplete-assessment/evidence/nuclei-execution.json"
                    )
                    .as_slice(),
                ),
            ] {
                fs::write(out_dir.join(name), bytes).map_err(|e| {
                    security_assessment_coverage_reporter::Error::Message(e.to_string())
                })?;
            }
            let r = analyze(&out_dir.join("scanreceipt.yaml"))?;
            fs::write(out_dir.join("assessment-receipt.json"), canonical_json(&r)?).map_err(
                |e| security_assessment_coverage_reporter::Error::Message(e.to_string()),
            )?;
            fs::write(out_dir.join("assessment-receipt.html"), render::html(&r)).map_err(|e| {
                security_assessment_coverage_reporter::Error::Message(e.to_string())
            })?;
            print!("{}", render::terminal(&r));
            Ok(0)
        }
    }
}
