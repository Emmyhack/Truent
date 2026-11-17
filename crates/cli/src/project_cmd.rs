//! Project lifecycle commands: configuration initialization and report conversion.

use super::FormatArg;
use anyhow::{Context, Result};
use clap::Parser;
use serde_json::json;
use std::path::PathBuf;

use crate::ui::render_init_success;
use truent_report::html_escape;

/// Arguments for the `report` subcommand.
#[derive(Parser)]
pub(crate) struct ReportArgs {
    /// Input results file.
    #[arg(long)]
    input: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: FormatArg,

    /// Output file.
    #[arg(long)]
    output: Option<PathBuf>,
}

/// Arguments for the `init` subcommand.
#[derive(Parser)]
pub(crate) struct InitArgs {
    /// Project directory.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Replace an existing .truent.toml file.
    #[arg(long)]
    force: bool,
}

pub(crate) fn report(args: ReportArgs, quiet: bool) -> Result<()> {
    let input_content = std::fs::read_to_string(&args.input)
        .with_context(|| format!("Failed to read input file: {}", args.input.display()))?;

    let analysis_data =
        if input_content.trim().starts_with('{') || input_content.trim().starts_with('[') {
            serde_json::from_str::<serde_json::Value>(&input_content)
                .unwrap_or_else(|_| json!({"content": input_content}))
        } else {
            json!({"content": input_content})
        };

    let report_output = match args.format {
        FormatArg::Json => json!({
            "report_type": "analysis",
            "source": args.input.display().to_string(),
            "data": analysis_data,
            "format": "json"
        })
        .to_string(),
        FormatArg::Html => format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Report</title>
    <style>
        body {{ font-family: monospace; margin: 20px; }}
        pre {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>Report</h1>
    <p><strong>Source:</strong> {}</p>
    <pre>{}</pre>
</body>
</html>"#,
            html_escape(&args.input.display().to_string()),
            html_escape(&serde_json::to_string_pretty(&analysis_data).unwrap_or_default())
        ),
        FormatArg::Text => serde_json::to_string_pretty(&analysis_data).unwrap_or_default(),
    };

    if !quiet {
        eprintln!(
            "✓ Generating {} report from {}",
            match args.format {
                FormatArg::Text => "text",
                FormatArg::Json => "JSON",
                FormatArg::Html => "HTML",
            },
            args.input.display()
        );
    }

    if let Some(output_path) = args.output {
        std::fs::write(&output_path, &report_output)
            .with_context(|| format!("Failed to write report: {}", output_path.display()))?;
        if !quiet {
            eprintln!("✓ Report written to {}", output_path.display());
        }
    } else {
        println!("{report_output}");
    }

    if !quiet {
        eprintln!("✓ Report generated successfully");
    }
    Ok(())
}

pub(crate) fn init(args: InitArgs, quiet: bool) -> Result<()> {
    std::fs::create_dir_all(&args.path).with_context(|| {
        format!(
            "Failed to create project directory: {}",
            args.path.display()
        )
    })?;

    let config_path = args.path.join(".truent.toml");
    if config_path.exists() && !args.force {
        anyhow::bail!(
            "Configuration already exists: {} (use --force to replace it)",
            config_path.display()
        );
    }
    let config_content = r#"# Truent Configuration
[project]
name = "my_contracts"
version = "0.1.0"

[chains]
enabled = ["evm"]

[invariants]
# Add your invariant checks here
"#;

    std::fs::write(&config_path, config_content)
        .with_context(|| format!("Failed to write configuration: {}", config_path.display()))?;

    if !quiet {
        println!("{}", render_init_success(&args.path));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_report_escapes_untrusted_input() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("results.json");
        let output = dir.path().join("report.html");
        std::fs::write(&input, r#"{"message":"</pre><script>alert(1)</script>"}"#).unwrap();

        report(
            ReportArgs {
                input,
                format: FormatArg::Html,
                output: Some(output.clone()),
            },
            true,
        )
        .unwrap();

        let html = std::fs::read_to_string(output).unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn init_preserves_existing_configuration_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".truent.toml");
        std::fs::write(&config, "custom = true\n").unwrap();

        let error = init(
            InitArgs {
                path: dir.path().to_path_buf(),
                force: false,
            },
            true,
        )
        .unwrap_err();

        assert!(error.to_string().contains("already exists"));
        assert_eq!(std::fs::read_to_string(config).unwrap(), "custom = true\n");
    }

    #[test]
    fn init_force_replaces_existing_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".truent.toml");
        std::fs::write(&config, "custom = true\n").unwrap();

        init(
            InitArgs {
                path: dir.path().to_path_buf(),
                force: true,
            },
            true,
        )
        .unwrap();

        let generated = std::fs::read_to_string(config).unwrap();
        assert!(generated.contains("[project]"));
        assert!(!generated.contains("custom = true"));
    }
}
