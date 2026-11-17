//! Read-only catalog commands: historical exploit registry and invariants.

use super::{FormatArg, InvariantsAction, InvariantsArgs, RegistryAction, RegistryArgs};
use anyhow::Result;
use serde_json::json;

pub(super) fn registry(args: RegistryArgs, quiet: bool) -> Result<()> {
    use truent_core::EXPLOIT_REGISTRY;

    match args.action {
        RegistryAction::List { chain, format } => {
            let registry = &*EXPLOIT_REGISTRY;
            let exploits = chain
                .map(|chain| registry.by_chain(&chain))
                .unwrap_or_else(|| registry.all());

            match format {
                FormatArg::Text => {
                    if !quiet {
                        println!(
                            "\n{} Historical DeFi Exploits Mapped to Truent Invariants",
                            exploits.len()
                        );
                        println!("{}", "=".repeat(80));
                        for exploit in &exploits {
                            println!(
                                "\n  {} | {} | {} | ${} loss",
                                exploit.id, exploit.protocol, exploit.date, exploit.loss_usd
                            );
                            println!("    Invariants: {}", exploit.invariant_ids.join(", "));
                        }
                        println!("\n{}", "=".repeat(80));
                        println!("Total loss: ${}", registry.total_loss());
                    }
                }
                FormatArg::Json => {
                    let json_exploits: Vec<_> = exploits.iter().map(|e| json!(e)).collect();
                    println!("{}", serde_json::to_string_pretty(&json_exploits)?);
                }
                FormatArg::Html => anyhow::bail!(
                    "HTML output is not supported by `truent registry list`; use --format text or --format json"
                ),
            }
        }
        RegistryAction::Show { id, format } => {
            let registry = &*EXPLOIT_REGISTRY;
            match registry.get(&id) {
                Some(exploit) => match format {
                    FormatArg::Text => {
                        if !quiet {
                            println!("\n{} - {} ({})", exploit.id, exploit.protocol, exploit.date);
                            println!("{}", "=".repeat(80));
                            println!("Loss: ${}", exploit.loss_usd);
                            println!("Chain: {}", exploit.chain);
                            println!("\nAttack Summary:\n{}\n", exploit.attack_summary);
                            println!("Invariants Violated:");
                            for inv_id in &exploit.invariant_ids {
                                println!("  - {}", inv_id);
                            }
                            println!("\nTx Hash: {}", exploit.tx_hash);
                            println!("Postmortem: {}\n", exploit.postmortem_url);
                        }
                    }
                    FormatArg::Json => {
                        println!("{}", serde_json::to_string_pretty(&exploit)?);
                    }
                    FormatArg::Html => anyhow::bail!(
                        "HTML output is not supported by `truent registry show`; use --format text or --format json"
                    ),
                },
                None if !quiet => eprintln!("✗ Exploit not found: {}", id),
                None => {}
            }
        }
    }
    Ok(())
}

pub(super) fn invariants(args: InvariantsArgs, quiet: bool) -> Result<()> {
    use truent_core::{get_invariant, invariant_count, invariants_for_chain};

    match args.action {
        InvariantsAction::List {
            chain,
            severity: _,
            format,
        } => match format {
            FormatArg::Text => {
                if !quiet {
                    let count = chain
                        .as_ref()
                        .map(|chain| invariants_for_chain(chain).len())
                        .unwrap_or_else(invariant_count);
                    println!("\n {} Compiled Invariants", count);
                    println!("{}", "=".repeat(80));
                    if let Some(chain) = &chain {
                        println!("Chain: {}\n", chain);
                        for invariant in invariants_for_chain(chain) {
                            println!(
                                "  {} | {} | {}",
                                invariant.id, invariant.severity, invariant.description
                            );
                        }
                    } else {
                        println!("(Total across all chains)\n");
                        println!("  Use --chain evm|solana|move|soroban to filter\n");
                    }
                    println!("{}", "=".repeat(80));
                }
            }
            FormatArg::Json => {
                if let Some(chain) = chain {
                    let values: Vec<_> = invariants_for_chain(&chain)
                        .iter()
                        .map(|i| json!({"id": i.id, "severity": i.severity, "chain": i.chain}))
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&values)?);
                }
            }
            FormatArg::Html => anyhow::bail!(
                "HTML output is not supported by `truent invariants list`; use --format text or --format json"
            ),
        },
        InvariantsAction::Show { id, format } => match get_invariant(&id) {
            Some(invariant) => match format {
                FormatArg::Text => {
                    if !quiet {
                        println!("\n{}", invariant.id);
                        println!("{}", "=".repeat(80));
                        println!("Severity: {}", invariant.severity);
                        println!("Chain: {}", invariant.chain);
                        println!("\nDescription:\n{}\n", invariant.description);
                        println!("Message Template: {}\n", invariant.message);
                    }
                }
                FormatArg::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&json!(invariant))?
                ),
                FormatArg::Html => anyhow::bail!(
                    "HTML output is not supported by `truent invariants show`; use --format text or --format json"
                ),
            },
            None if !quiet => eprintln!("✗ Invariant not found: {}", id),
            None => {}
        },
    }
    Ok(())
}
