//! `truent skills` — discover, inspect and run external security skill
//! libraries.
//!
//! Truent's engine answers questions about smart-contract source and bytecode.
//! Most security work needs different tools entirely — `aws`, `kubectl`,
//! `tshark`, a SIEM — and this is how Truent reaches them: by hosting skill
//! libraries that already encode that expertise, rather than by pretending to
//! reimplement it.
//!
//! The honesty contract carries over from findings to skills. Truent's own
//! skills are `ENGINE-BACKED`; everything from a third-party source is
//! `ADVISORY` and labelled as such on every line that mentions it.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::Command;

use truent_skills::{
    builtin_skills_dir, clone_source, default_root, source_revision, suggested_sources,
    update_source, Catalog, Preflight, Skill, SkillSource, SourceRegistry, Trust,
};

/// Arguments for the `skills` subcommand.
#[derive(Parser)]
pub struct SkillsArgs {
    #[command(subcommand)]
    pub command: SkillsCommand,

    /// Cache directory for cloned sources.
    #[arg(long, global = true, value_name = "DIR")]
    pub root: Option<PathBuf>,
}

/// `truent skills` subcommands.
#[derive(Subcommand)]
pub enum SkillsCommand {
    /// Manage skill libraries.
    Source(SourceArgs),
    /// List available skills.
    List(ListArgs),
    /// Search skills by keyword, tag or framework ID.
    Search(SearchArgs),
    /// Show a skill's instructions and metadata.
    Show(ShowArgs),
    /// Report which skills are runnable on this machine.
    Doctor(DoctorArgs),
    /// Run a skill's script.
    Run(RunArgs),
}

/// Arguments for `skills source`.
#[derive(Parser)]
pub struct SourceArgs {
    #[command(subcommand)]
    pub command: SourceCommand,
}

/// `truent skills source` subcommands.
#[derive(Subcommand)]
pub enum SourceCommand {
    /// Register and clone a skill library (`owner/repo` or a git URL).
    Add(SourceAddArgs),
    /// List registered libraries.
    List,
    /// Pull upstream changes for one or all libraries.
    Update(SourceUpdateArgs),
    /// Unregister a library and delete its checkout.
    Remove(SourceRemoveArgs),
    /// Show libraries Truent suggests.
    Suggest,
}

/// Arguments for `skills source add`.
#[derive(Parser)]
pub struct SourceAddArgs {
    /// `owner/repo`, or a full git URL.
    pub spec: String,
    /// Local name for the source. Defaults to the repository name.
    #[arg(long)]
    pub name: Option<String>,
    /// Subdirectory within the repository holding the skills.
    #[arg(long, default_value = "skills")]
    pub skills_dir: String,
}

/// Arguments for `skills source update`.
#[derive(Parser)]
pub struct SourceUpdateArgs {
    /// Source to update. Omit to update all.
    pub name: Option<String>,
}

/// Arguments for `skills source remove`.
#[derive(Parser)]
pub struct SourceRemoveArgs {
    /// Source to remove.
    pub name: String,
}

/// Arguments for `skills list`.
#[derive(Parser)]
pub struct ListArgs {
    /// Only skills from this source.
    #[arg(long)]
    pub source: Option<String>,
    /// Only skills in this subdomain.
    #[arg(long)]
    pub subdomain: Option<String>,
    /// Group by subdomain instead of listing every skill.
    #[arg(long)]
    pub summary: bool,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    pub format: SkillsFormat,
}

/// Arguments for `skills search`.
#[derive(Parser)]
pub struct SearchArgs {
    /// Terms to match. All must match (AND).
    #[arg(required = true)]
    pub terms: Vec<String>,
    /// Only skills from this source.
    #[arg(long)]
    pub source: Option<String>,
    /// Only skills in this subdomain.
    #[arg(long)]
    pub subdomain: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    pub format: SkillsFormat,
}

/// Arguments for `skills show`.
#[derive(Parser)]
pub struct ShowArgs {
    /// Skill name, optionally `source:name`.
    pub name: String,
    /// Print only the metadata, not the instructions.
    #[arg(long)]
    pub metadata_only: bool,
}

/// Arguments for `skills doctor`.
#[derive(Parser)]
pub struct DoctorArgs {
    /// Check one skill instead of summarising all of them.
    pub name: Option<String>,
    /// Only skills from this source.
    #[arg(long)]
    pub source: Option<String>,
}

/// Arguments for `skills run`.
#[derive(Parser)]
pub struct RunArgs {
    /// Skill name, optionally `source:name`.
    pub name: String,
    /// Script to run, relative to the skill directory. Defaults to its single
    /// or conventionally-named entry point.
    #[arg(long)]
    pub script: Option<String>,
    /// Skip the confirmation prompt. Required in non-interactive use.
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Print the command that would run, without running it.
    #[arg(long)]
    pub dry_run: bool,
    /// Arguments passed through to the script, after `--`.
    #[arg(last = true)]
    pub args: Vec<String>,
}

/// Output formats for skill listings.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum SkillsFormat {
    /// Human-readable.
    Text,
    /// Machine-readable JSON.
    Json,
}

/// Entry point for `truent skills`.
pub fn run(args: SkillsArgs, quiet: bool) -> Result<()> {
    let root = args.root.clone().unwrap_or_else(default_root);

    match args.command {
        SkillsCommand::Source(sa) => source_cmd(sa, &root, quiet),
        SkillsCommand::List(la) => list_cmd(la, &root),
        SkillsCommand::Search(sa) => search_cmd(sa, &root),
        SkillsCommand::Show(sa) => show_cmd(sa, &root),
        SkillsCommand::Doctor(da) => doctor_cmd(da, &root),
        SkillsCommand::Run(ra) => run_cmd(ra, &root, quiet),
    }
}

fn load_catalog(root: &std::path::Path) -> Result<Catalog> {
    let builtin = builtin_skills_dir();
    let catalog = Catalog::load(root, builtin.as_deref())?;
    // Problems are printed, never swallowed: a source that failed to index is
    // the most likely explanation for "my skill isn't showing up".
    for (path, err) in &catalog.errors {
        eprintln!("⚠ {}: {}", path.display(), err);
    }
    Ok(catalog)
}

fn source_cmd(args: SourceArgs, root: &std::path::Path, quiet: bool) -> Result<()> {
    match args.command {
        SourceCommand::Add(a) => {
            let url = SkillSource::resolve_url(&a.spec)?;
            let name = a.name.unwrap_or_else(|| SkillSource::default_name(&a.spec));
            let source = SkillSource {
                name: name.clone(),
                url: url.clone(),
                skills_dir: a.skills_dir,
            };

            if !quiet {
                eprintln!("Cloning {url} …");
            }
            clone_source(&source, root).with_context(|| format!("cloning {url}"))?;

            let mut reg = SourceRegistry::load(root)?;
            reg.upsert(source.clone())?;
            reg.save(root)?;

            let catalog = Catalog::load(root, None)?;
            let count = catalog.skills().iter().filter(|s| s.source == name).count();
            let rev = source_revision(&source, root).unwrap_or_else(|| "?".into());

            println!("✓ Added source '{name}' ({count} skills) at {rev}");
            println!();
            println!("  Skills from this source are ADVISORY: Truent can run them and relay");
            println!("  what they report, but cannot reproduce or verify it the way it does");
            println!("  its own engine-backed findings.");
            println!();
            println!("  truent skills list --source {name} --summary");
            Ok(())
        }
        SourceCommand::List => {
            let reg = SourceRegistry::load(root)?;
            if reg.sources.is_empty() {
                println!("No skill sources registered.");
                println!();
                println!("Add one with:  truent skills source add <owner/repo>");
                println!("Suggestions:   truent skills source suggest");
                return Ok(());
            }
            let catalog = Catalog::load(root, None)?;
            println!("{:<28} {:>7}  {:<9} URL", "SOURCE", "SKILLS", "REV");
            for s in &reg.sources {
                let count = catalog
                    .skills()
                    .iter()
                    .filter(|k| k.source == s.name)
                    .count();
                let rev = source_revision(s, root).unwrap_or_else(|| "missing".into());
                println!("{:<28} {:>7}  {:<9} {}", s.name, count, rev, s.url);
            }
            Ok(())
        }
        SourceCommand::Update(a) => {
            let reg = SourceRegistry::load(root)?;
            let targets: Vec<&SkillSource> = match &a.name {
                Some(n) => vec![reg
                    .get(n)
                    .with_context(|| format!("no source named '{n}'"))?],
                None => reg.sources.iter().collect(),
            };
            if targets.is_empty() {
                println!("No sources registered.");
                return Ok(());
            }
            for s in targets {
                update_source(s, root).with_context(|| format!("updating '{}'", s.name))?;
                let rev = source_revision(s, root).unwrap_or_else(|| "?".into());
                println!("✓ {} now at {rev}", s.name);
            }
            Ok(())
        }
        SourceCommand::Remove(a) => {
            let mut reg = SourceRegistry::load(root)?;
            if !reg.remove(&a.name) {
                bail!("no source named '{}'", a.name);
            }
            reg.save(root)?;
            let dir = root.join("sources").join(&a.name);
            if dir.is_dir() {
                std::fs::remove_dir_all(&dir)
                    .with_context(|| format!("removing {}", dir.display()))?;
            }
            println!("✓ Removed source '{}'", a.name);
            Ok(())
        }
        SourceCommand::Suggest => {
            println!("Skill libraries Truent can host:");
            println!();
            for (spec, desc) in suggested_sources() {
                println!("  {spec}");
                for line in textwrap_simple(desc, 72) {
                    println!("      {line}");
                }
                println!("      truent skills source add {spec}");
                println!();
            }
            println!("Any agentskills.io-compatible repository works, not just these.");
            Ok(())
        }
    }
}

fn list_cmd(args: ListArgs, root: &std::path::Path) -> Result<()> {
    let catalog = load_catalog(root)?;
    let found = catalog.search(&[], args.source.as_deref(), args.subdomain.as_deref());

    if args.format == SkillsFormat::Json {
        return print_json(&found);
    }
    if found.is_empty() {
        println!("No skills match.");
        if catalog.is_empty() {
            println!();
            println!("No sources registered. Try: truent skills source suggest");
        }
        return Ok(());
    }

    if args.summary {
        println!("{} skills\n", found.len());
        println!("{:<34} {:>7}", "SUBDOMAIN", "SKILLS");
        for (sd, n) in catalog.subdomain_counts() {
            if args.subdomain.as_deref().is_none_or(|f| f == sd) {
                println!("{:<34} {:>7}", sd, n);
            }
        }
        return Ok(());
    }

    print_skill_table(&found);
    Ok(())
}

fn search_cmd(args: SearchArgs, root: &std::path::Path) -> Result<()> {
    let catalog = load_catalog(root)?;
    let found = catalog.search(
        &args.terms,
        args.source.as_deref(),
        args.subdomain.as_deref(),
    );

    if args.format == SkillsFormat::Json {
        return print_json(&found);
    }
    if found.is_empty() {
        println!("No skills match {:?}.", args.terms.join(" "));
        return Ok(());
    }
    println!("{} match(es) for {:?}\n", found.len(), args.terms.join(" "));
    print_skill_table(&found);
    Ok(())
}

fn show_cmd(args: ShowArgs, root: &std::path::Path) -> Result<()> {
    let catalog = load_catalog(root)?;
    let skill = resolve(&catalog, &args.name)?;

    println!("{}  [{}]", skill.name, skill.trust);
    println!("{:<17}{}", "Source", skill.source);
    if let Some(d) = &skill.domain {
        println!("{:<17}{d}", "Domain");
    }
    if let Some(d) = &skill.subdomain {
        println!("{:<17}{d}", "Subdomain");
    }
    if let Some(v) = &skill.version {
        println!("{:<17}{v}", "Version");
    }
    if let Some(l) = &skill.license {
        println!("{:<17}{l}", "License");
    }
    if !skill.tags.is_empty() {
        println!("{:<17}{}", "Tags", skill.tags.join(", "));
    }
    for (framework, ids) in &skill.frameworks {
        println!("{:<17}{}", framework, ids.join(", "));
    }
    println!("{:<17}{}", "Path", skill.path.display());

    if !skill.scripts.is_empty() {
        println!("{:<17}{}", "Scripts", skill.scripts.len());
        for s in &skill.scripts {
            println!("{:<17}{}", "", s.relative_path);
        }
    }

    let pf = Preflight::check(&skill.detected_tools);
    if !skill.detected_tools.is_empty() {
        println!(
            "{:<17}{} present, {} missing{}",
            "Tools",
            pf.present.len(),
            pf.missing.len(),
            if pf.missing.is_empty() {
                String::new()
            } else {
                format!(" ({})", pf.missing.join(", "))
            }
        );
    }

    println!();
    println!("{}", skill.description);

    if skill.trust == Trust::Advisory {
        println!();
        println!("ADVISORY — from a third-party source. Truent relays what this skill");
        println!("reports; it does not verify it the way it verifies engine findings.");
    }

    if !args.metadata_only {
        let body = std::fs::read_to_string(skill.path.join("SKILL.md"))?;
        println!();
        println!("────────────────────────────────────────────────────────");
        println!("{}", body);
    }
    Ok(())
}

fn doctor_cmd(args: DoctorArgs, root: &std::path::Path) -> Result<()> {
    let catalog = load_catalog(root)?;

    if let Some(name) = &args.name {
        let skill = resolve(&catalog, name)?;
        let pf = Preflight::check(&skill.detected_tools);
        println!("{}  [{}]", skill.name, skill.trust);
        if skill.detected_tools.is_empty() {
            println!("  No external tools detected in this skill's instructions.");
        } else {
            for t in &pf.present {
                println!("  ✓ {t}");
            }
            for t in &pf.missing {
                println!("  ✗ {t}  (not on PATH)");
            }
        }
        if skill.scripts.is_empty() {
            println!("  No script — instructions only; run it through an agent, not `skills run`.");
        }
        println!();
        println!("Tool detection is a heuristic over the instructions, not a declared");
        println!("manifest: absence of a tool here does not prove the skill needs nothing.");
        return Ok(());
    }

    let skills = catalog.search(&[], args.source.as_deref(), None);
    let mut ready = 0usize;
    let mut blocked = 0usize;
    let mut missing_counts: std::collections::BTreeMap<String, usize> = Default::default();

    for s in &skills {
        let pf = Preflight::check(&s.detected_tools);
        if pf.is_satisfied() {
            ready += 1;
        } else {
            blocked += 1;
            for t in pf.missing {
                *missing_counts.entry(t).or_default() += 1;
            }
        }
    }

    println!("{} skills indexed", skills.len());
    println!("  {ready} with every detected tool present");
    println!("  {blocked} needing something not on PATH");
    if !missing_counts.is_empty() {
        let mut v: Vec<(String, usize)> = missing_counts.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        println!("\nMost-needed missing tools:");
        for (tool, n) in v.iter().take(12) {
            println!("  {:<16} blocks {n} skill(s)", tool);
        }
    }
    Ok(())
}

fn run_cmd(args: RunArgs, root: &std::path::Path, quiet: bool) -> Result<()> {
    let catalog = load_catalog(root)?;
    let skill = resolve(&catalog, &args.name)?;

    let script = match &args.script {
        Some(rel) => skill
            .scripts
            .iter()
            .find(|s| s.relative_path == *rel)
            .with_context(|| {
                format!(
                    "'{}' has no script '{rel}' (has: {})",
                    skill.name,
                    skill
                        .scripts
                        .iter()
                        .map(|s| s.relative_path.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?,
        None => skill.primary_script().with_context(|| {
            if skill.scripts.is_empty() {
                format!(
                    "'{}' ships no script — it is instructions for an agent. \
                     Read it with: truent skills show {}",
                    skill.name, skill.name
                )
            } else {
                format!(
                    "'{}' has several scripts and no obvious entry point. \
                     Choose one with --script: {}",
                    skill.name,
                    skill
                        .scripts
                        .iter()
                        .map(|s| s.relative_path.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        })?,
    };

    let interpreter = script
        .interpreter
        .clone()
        .unwrap_or_else(|| "python3".to_string());

    let pf = Preflight::check(&skill.detected_tools);
    let rendered = format!(
        "{} {} {}",
        interpreter,
        script.path.display(),
        args.args.join(" ")
    );

    if args.dry_run {
        println!("{}", rendered.trim_end());
        return Ok(());
    }

    // Running a third-party script is the one irreversible thing this command
    // does — these skills drive cloud APIs, scanners and, in the offensive
    // subdomains, live traffic against a target. Confirm before doing it.
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            bail!(
                "refusing to run a third-party script without confirmation. \
                 Re-run with --yes once you have reviewed it:\n  \
                 truent skills show {} \n  {}",
                skill.name,
                rendered.trim_end()
            );
        }
        println!("About to run a script from source '{}':", skill.source);
        println!();
        println!("  {}", rendered.trim_end());
        println!();
        println!("  Trust:  {}", skill.trust);
        if !pf.missing.is_empty() {
            println!("  Missing tools: {}", pf.missing.join(", "));
        }
        println!();
        println!("This is third-party code. Only run it against systems you are");
        println!(
            "authorised to test. Review it first: truent skills show {}",
            skill.name
        );
        print!("Continue? [y/N] ");
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    if !tool_present(&interpreter) {
        bail!(
            "'{interpreter}' is not on PATH — cannot run {}",
            script.relative_path
        );
    }

    if !quiet {
        eprintln!("▶ {} [{}]", skill.name, skill.trust);
    }

    let status = Command::new(&interpreter)
        .arg(&script.path)
        .args(&args.args)
        .current_dir(&skill.path)
        .status()
        .with_context(|| format!("running {rendered}"))?;

    if !quiet && skill.trust == Trust::Advisory {
        eprintln!();
        eprintln!("⚠ ADVISORY output — produced by a third-party skill, not verified by");
        eprintln!("  Truent's engine. Treat it as a lead, not a proven finding.");
    }

    if !status.success() {
        let code = status.code().unwrap_or(1);
        std::process::exit(code);
    }
    Ok(())
}

fn tool_present(tool: &str) -> bool {
    truent_skills::tool_available(tool)
}

/// Resolve a possibly-ambiguous skill name into one skill.
fn resolve<'a>(catalog: &'a Catalog, name: &str) -> Result<&'a Skill> {
    if let Some(s) = catalog.get(name) {
        // An unqualified name that exists in several sources is ambiguous even
        // though `get` returns the first — say so rather than pick silently.
        if !name.contains(':') {
            let all = catalog.get_all(name);
            if all.len() > 1 {
                bail!(
                    "'{name}' exists in {:?} — qualify it as <source>:{name}",
                    all.iter().map(|s| s.source.as_str()).collect::<Vec<_>>()
                );
            }
        }
        return Ok(s);
    }
    // Offer the closest matches rather than a bare failure.
    let near = catalog.search(&[name.to_string()], None, None);
    if near.is_empty() {
        bail!("no skill named '{name}'");
    }
    bail!(
        "no skill named '{name}'. Did you mean: {}",
        near.iter()
            .take(5)
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn print_skill_table(skills: &[&Skill]) {
    println!("{:<52} {:<14} {:<24} SOURCE", "SKILL", "TRUST", "SUBDOMAIN");
    for s in skills {
        println!(
            "{:<52} {:<14} {:<24} {}",
            truncate(&s.name, 52),
            s.trust.label(),
            truncate(s.subdomain.as_deref().unwrap_or("—"), 24),
            s.source
        );
    }
}

fn print_json(skills: &[&Skill]) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&skills)?);
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let keep: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{keep}…")
    }
}

/// Wrap text to `width` columns without pulling in a dependency for it.
fn textwrap_simple(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
