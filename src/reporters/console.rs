//! Console reporter: colored human output, grouped by severity.
//!
//! Layout follows DESIGN.md §4: one line per finding
//! (`ID  severity  title  path:line`), a one-line remediation hint, then a
//! summary with counts and scan stats. Respects `--no-color` (and NO_COLOR via
//! the `colored` crate's global override here).

use colored::Colorize;

use crate::model::Severity;
use crate::scanner::ScanReport;

/// Render the report as human-readable text.
///
/// `color`: honor ANSI colors. `quiet`: findings only, no banner or summary.
pub fn render(report: &ScanReport, color: bool, quiet: bool) -> String {
    colored::control::set_override(color);

    let mut out = String::new();

    if !quiet {
        out.push_str(
            &format!(
                "snoot v{} — snooting out hidden crypto in {}\n\n",
                env!("CARGO_PKG_VERSION"),
                report.root.display()
            )
            .bold(),
        );
    }

    if report.findings.is_empty() {
        if !quiet {
            out.push_str("No new findings from the supported detectors.\n");
        }
    } else {
        for finding in &report.findings {
            let sev = finding.severity.to_string();
            let sev_colored = match finding.severity {
                Severity::Critical => sev.red().bold(),
                Severity::High => sev.red(),
                Severity::Medium => sev.yellow(),
                Severity::Low => sev.blue(),
                Severity::Info => sev.dimmed(),
            };
            let loc = match finding.location.line {
                Some(line) => format!("{}:{line}", finding.location.path),
                None => finding.location.path.clone(),
            };
            out.push_str(&format!(
                "{:<10} {:<8} {:<42} {}\n",
                finding.rule_id.bold(),
                sev_colored,
                truncate(&finding.title, 42),
                loc.dimmed()
            ));
            out.push_str(&format!(
                "           {} {}\n",
                "->".dimmed(),
                truncate(&finding.remediation, 100)
            ));
        }
    }

    if !quiet {
        out.push('\n');
        out.push_str(&summary_line(report));
    }

    out
}

fn summary_line(report: &ScanReport) -> String {
    let n = report.findings.len();
    if n == 0 {
        return format!(
            "0 findings · {} suppressed · {} files scanned · {} skipped · {}ms\n",
            report.stats.findings_suppressed,
            report.stats.files_scanned,
            report.stats.files_skipped,
            report.stats.elapsed_ms
        );
    }
    let mut parts = Vec::new();
    for sev in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = report.findings.iter().filter(|f| f.severity == sev).count();
        if count > 0 {
            parts.push(format!("{count} {sev}"));
        }
    }
    format!(
        "{} finding{} ({}) · {} suppressed · {} files scanned · {} skipped · {}ms\n",
        n,
        if n == 1 { "" } else { "s" },
        parts.join(", "),
        report.stats.findings_suppressed,
        report.stats.files_scanned,
        report.stats.files_skipped,
        report.stats.elapsed_ms
    )
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!(
            "{}…",
            s.chars().take(max.saturating_sub(1)).collect::<String>()
        )
    }
}
