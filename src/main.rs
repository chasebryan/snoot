//! snoot — snoot out the crypto hiding in your codebase.
//!
//! A developer-native scanner for classical public-key cryptography usage:
//! finds RSA / ECDSA / ECDH / DSA / DH in source, key material, manifests and
//! TLS configs, and emits machine-readable evidence (SARIF, CycloneDX CBOM,
//! JSON) for PQC migration planning.

mod baseline;
mod engines;
mod model;
mod reporters;
mod rules;
mod scanner;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use model::{OutputFormat, Severity};

#[derive(Debug, Parser)]
#[command(
    name = "snoot",
    version,
    about = "Snoot out the crypto hiding in your codebase.",
    long_about = "snoot scans a source tree for classical public-key cryptography \
                  (RSA, ECDSA/ECDH, DSA, DH), reports what is quantum-vulnerable, \
                  and emits machine-readable evidence (SARIF, CycloneDX CBOM, JSON) \
                  for post-quantum migration planning."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan a source tree for classical public-key crypto usage
    Scan(ScanArgs),
    /// Write a baseline file from current findings (suppresses them on later scans)
    Init(InitArgs),
    /// List all detection rules with IDs and descriptions
    Rules,
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// Path to scan (default: current directory)
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Output format; repeatable, e.g. --format sarif --format json (default: console)
    #[arg(long, value_enum, value_name = "FORMAT")]
    format: Vec<OutputFormat>,

    /// Write the report to FILE instead of stdout
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Exit non-zero if any finding is at or above SEVERITY (CI gating)
    #[arg(long, value_enum, value_name = "SEVERITY")]
    fail_on: Option<Severity>,

    /// Suppress findings already recorded in baseline FILE
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Findings only: no banner or summary
    #[arg(long)]
    quiet: bool,
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Path to scan (default: current directory)
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Where to write the baseline file
    #[arg(long, default_value = ".snoot-baseline.json", value_name = "FILE")]
    output: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan(args) => cmd_scan(args),
        Commands::Init(args) => cmd_init(args),
        Commands::Rules => cmd_rules(),
    }
}

fn cmd_scan(args: ScanArgs) -> ExitCode {
    let formats = if args.format.is_empty() {
        vec![OutputFormat::Console]
    } else {
        args.format.clone()
    };

    let opts = scanner::ScanOptions {
        root: args.path.clone(),
        baseline: args.baseline.clone(),
        ..Default::default()
    };
    let report = match scanner::scan(&opts) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("snoot: scan failed: {err:#}");
            return ExitCode::from(3);
        }
    };

    let mut chunks = Vec::with_capacity(formats.len());
    for fmt in &formats {
        let rendered = match fmt {
            OutputFormat::Console => {
                reporters::console::render(&report, !args.no_color, args.quiet)
            }
            OutputFormat::Json => reporters::json::render(&report)
                .unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}")),
            OutputFormat::Sarif => reporters::sarif::render(&report),
            OutputFormat::Cbom => reporters::cbom::render(&report),
        };
        chunks.push(rendered);
    }
    let out = chunks.join("\n");

    if let Some(path) = args.output.as_deref() {
        if let Err(err) = std::fs::write(path, &out) {
            eprintln!("snoot: cannot write {}: {err:#}", path.display());
            return ExitCode::from(3);
        }
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        let _ = writeln!(handle, "{out}");
    }

    if let Some(min) = args.fail_on {
        if report.findings.iter().any(|f| f.severity.at_least(min)) {
            if !args.quiet {
                eprintln!(
                    "snoot: findings at or above severity '{min}' — failing (--fail-on {min})"
                );
            }
            return ExitCode::from(2);
        }
    }

    ExitCode::SUCCESS
}

fn cmd_init(args: InitArgs) -> ExitCode {
    let opts = scanner::ScanOptions {
        root: args.path.clone(),
        ..Default::default()
    };
    let report = match scanner::scan(&opts) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("snoot: scan failed: {err:#}");
            return ExitCode::from(3);
        }
    };

    match baseline::Baseline::write(&args.output, &report.findings) {
        Ok(()) => {
            eprintln!(
                "snoot: wrote baseline {} ({} finding{})",
                args.output.display(),
                report.findings.len(),
                if report.findings.len() == 1 { "" } else { "s" }
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("snoot: cannot write baseline: {err:#}");
            ExitCode::from(3)
        }
    }
}

fn cmd_rules() -> ExitCode {
    for rule in rules::RuleRegistry::all() {
        println!("{}  [{}]  {}", rule.id, rule.severity, rule.title);
        println!("    {}", rule.description);
        println!("    -> {}", rule.remediation);
        println!();
    }
    ExitCode::SUCCESS
}
