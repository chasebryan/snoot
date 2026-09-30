//! snoot — discover classical cryptography and report migration evidence.

mod baseline;
mod engines;
mod ignore;
mod model;
mod reporters;
mod rules;
mod scanner;

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{ensure, Context};
use clap::{Args, Parser, Subcommand};

use model::{OutputFormat, Severity};

#[derive(Debug, Parser)]
#[command(
    name = "snoot",
    version,
    about = "Snoot out the crypto hiding in your codebase."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan a source tree for classical public-key crypto usage
    Scan(ScanArgs),
    /// Record current findings for suppression on later scans
    Init(InitArgs),
    /// List detection rules; see README for coverage
    Rules,
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Output format; repeat for multiple reports (requires --output directory)
    #[arg(long, value_enum, value_name = "FORMAT")]
    format: Vec<OutputFormat>,
    /// Output file for one format, or output directory for multiple formats
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Exit 2 if an unsuppressed finding is at or above SEVERITY
    #[arg(long, value_enum, value_name = "SEVERITY")]
    fail_on: Option<Severity>,
    /// Suppress findings recorded in baseline FILE
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    #[arg(long)]
    no_color: bool,
    /// Findings only: no console banner or summary
    #[arg(long)]
    quiet: bool,
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(long, default_value = ".snoot-baseline.json", value_name = "FILE")]
    output: PathBuf,
    /// Replace an existing baseline
    #[arg(long)]
    force: bool,
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Commands::Scan(args) => cmd_scan(args),
        Commands::Init(args) => cmd_init(args),
        Commands::Rules => cmd_rules(),
    };
    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("snoot: {err:#}");
            ExitCode::from(3)
        }
    }
}

fn output_name(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Console => "snoot.txt",
        OutputFormat::Json => "snoot.json",
        OutputFormat::Sarif => "snoot.sarif",
        OutputFormat::Cbom => "snoot.cdx.json",
    }
}

/// Do not overwrite the scan input or a baseline while writing a report.
fn check_output(path: &Path, source: &Path, baseline: Option<&Path>) -> anyhow::Result<()> {
    if let Ok(output) = path.canonicalize() {
        ensure!(
            source.canonicalize().ok().as_ref() != Some(&output),
            "output {} is also the scan input",
            path.display()
        );
        if let Some(baseline) = baseline {
            ensure!(
                baseline.canonicalize().ok().as_ref() != Some(&output),
                "output {} is also the baseline",
                path.display()
            );
        }
    }
    Ok(())
}

fn cmd_scan(args: ScanArgs) -> anyhow::Result<ExitCode> {
    let mut formats = args.format;
    if formats.is_empty() {
        formats.push(OutputFormat::Console);
    }
    let mut unique = Vec::new();
    for format in formats {
        if !unique.contains(&format) {
            unique.push(format);
        }
    }
    let multiple = unique.len() > 1;
    ensure!(
        !multiple || args.output.is_some(),
        "multiple formats require --output DIRECTORY; each report is written separately"
    );
    if multiple {
        let directory = args.output.as_ref().unwrap();
        ensure!(
            !directory.exists() || directory.is_dir(),
            "multiple formats require an output directory: {}",
            directory.display()
        );
    }
    let outputs: Vec<Option<PathBuf>> = unique
        .iter()
        .map(|format| {
            args.output.as_ref().map(|path| {
                if multiple {
                    path.join(output_name(*format))
                } else {
                    path.clone()
                }
            })
        })
        .collect();
    for path in outputs.iter().flatten() {
        check_output(path, &args.path, args.baseline.as_deref())?;
    }
    let report = scanner::scan(&scanner::ScanOptions {
        root: args.path,
        baseline: args.baseline,
        excluded_paths: outputs.iter().flatten().cloned().collect(),
        ..Default::default()
    })?;
    let color = !args.no_color
        && args.output.is_none()
        && std::env::var_os("NO_COLOR").is_none()
        && std::io::stdout().is_terminal();
    let rendered: Vec<String> = unique
        .iter()
        .map(|format| match format {
            OutputFormat::Console => Ok(reporters::console::render(&report, color, args.quiet)),
            OutputFormat::Json => reporters::json::render(&report),
            OutputFormat::Sarif => reporters::sarif::render(&report),
            OutputFormat::Cbom => reporters::cbom::render(&report),
        })
        .collect::<anyhow::Result<_>>()?;
    if multiple {
        let directory = args.output.as_ref().unwrap();
        std::fs::create_dir_all(directory)
            .with_context(|| format!("creating report directory {}", directory.display()))?;
    }
    for (out, path) in rendered.iter().zip(outputs) {
        if let Some(path) = path {
            std::fs::write(&path, out).with_context(|| format!("writing {}", path.display()))?;
        } else {
            writeln!(std::io::stdout().lock(), "{out}").context("writing report to stdout")?;
        }
    }
    if let Some(minimum) = args.fail_on {
        if report
            .findings
            .iter()
            .any(|finding| finding.severity.at_least(minimum))
        {
            if !args.quiet {
                eprintln!("snoot: findings at or above '{minimum}' (--fail-on {minimum})");
            }
            return Ok(ExitCode::from(2));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_init(args: InitArgs) -> anyhow::Result<ExitCode> {
    check_output(&args.output, &args.path, None)?;
    ensure!(
        args.force || !args.output.exists(),
        "baseline {} already exists; use --force to replace it",
        args.output.display()
    );
    let report = scanner::scan(&scanner::ScanOptions {
        root: args.path,
        excluded_paths: vec![args.output.clone()],
        ..Default::default()
    })?;
    baseline::Baseline::write(&args.output, &report.findings, args.force)?;
    eprintln!(
        "snoot: recorded {} findings in {}",
        report.findings.len(),
        args.output.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_rules() -> anyhow::Result<ExitCode> {
    let mut out = std::io::stdout().lock();
    for rule in rules::RuleRegistry::all() {
        writeln!(
            out,
            "{}  [{}]  {}\n    {}\n    -> {}\n",
            rule.id, rule.severity, rule.title, rule.description, rule.remediation
        )?;
    }
    Ok(ExitCode::SUCCESS)
}
