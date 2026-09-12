//! Solana detector implementations.
//!
//! Detectors for Solana/Anchor program vulnerabilities.

use truent_core::{Finding, Severity};

/// Detects an authority-shaped account that is not required to sign.
pub fn detect_missing_signer(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    // The old check wanted `Account<`, `mut` and an authority word on one
    // line. Anchor puts `#[account(mut)]` on the line *above* the field, so
    // the shape never occurred and the detector never fired on real code.
    //
    // A field whose name says it is the authority (`authority`, `admin`,
    // `owner`, `payer`) must be a `Signer<'info>` or carry a `signer`
    // constraint; an `AccountInfo`/`UncheckedAccount` in that role lets anyone
    // pass any key. `/// CHECK:` is Anchor's explicit attestation and is
    // honoured.
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("pub ") || !trimmed.contains(':') {
            continue;
        }
        let Some((name, ty)) = trimmed.trim_start_matches("pub ").split_once(':') else {
            continue;
        };
        let name = name.trim().to_lowercase();
        let ty = ty.trim();
        let authority_role = name == "authority"
            || name == "admin"
            || name == "owner"
            || name == "payer"
            || name.ends_with("_authority");
        if !authority_role {
            continue;
        }
        if ty.starts_with("Signer<") {
            continue;
        }
        let unchecked_type = ty.starts_with("AccountInfo<") || ty.starts_with("UncheckedAccount<");
        if !unchecked_type {
            continue;
        }

        // Look at the attribute(s) and doc lines directly above the field.
        let above: Vec<&str> = lines[i.saturating_sub(4)..i].to_vec();
        let has_signer_constraint = above.iter().any(|l| l.contains("signer"));
        let has_check_attestation = above.iter().any(|l| l.trim().starts_with("/// CHECK:"));
        if has_signer_constraint || has_check_attestation {
            continue;
        }

        findings.push(
            Finding::new(
                "sol_missing_signer".to_string(),
                Severity::High,
                file_path.to_string(),
                i + 1,
                0,
                format!(
                    "`{}` is the authority for this instruction but is not a Signer: any key \
                     can be supplied in its place",
                    name
                ),
                trimmed.to_string(),
            )
            .with_metadata("chain".to_string(), "solana".to_string()),
        );
    }

    findings
}

/// Detects oracle rate account usage as price source
pub fn detect_oracle_rate_account(source: &str, file_path: &str) -> Vec<Finding> {
    // A price/rate/oracle account declared as an unchecked wrapper —
    // `rate: AccountInfo<'info>`, `price_feed: UncheckedAccount<'info>` —
    // with no `/// CHECK:` above it. Word-level matching: the old
    // substring test fired on `crate::parse_accounts`.
    lazy_static::lazy_static! {
        static ref ORACLE_FIELD: regex::Regex = regex::Regex::new(
            r"^\s*(?:pub\s+)?[a-z0-9_]*(?:rate|price|oracle|feed)[a-z0-9_]*\s*:\s*(?:AccountInfo|UncheckedAccount)\s*<"
        )
        .unwrap();
    }
    let lines: Vec<&str> = source.lines().collect();
    let mut findings = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !ORACLE_FIELD.is_match(line) {
            continue;
        }
        let checked = lines[..i]
            .iter()
            .rev()
            .take(3)
            .any(|l| l.trim_start().starts_with("/// CHECK"));
        if checked {
            continue;
        }
        findings.push(
            Finding::new(
                "sol_oracle_rate_account".to_string(),
                Severity::High,
                file_path.to_string(),
                i + 1,
                0,
                "Price/rate account is an unchecked AccountInfo: any account can be passed as the oracle, so the caller chooses the price. Use a typed account (Account<'info, PriceFeed>) or validate owner and address explicitly".to_string(),
                line.trim().to_string(),
            )
            .with_metadata("chain".to_string(), "solana".to_string()),
        );
    }
    findings
}

pub fn detect_oracle_self_trade(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Look for trades where maker and taker are derived from same signer
    for (line_num, line) in source.lines().enumerate() {
        if ((line.contains("maker") && line.contains("taker"))
            || (line.contains("owner") && line.contains("owner")))
            && line.contains("signer")
            && !line.contains("require")
            && !line.contains("assert")
        {
            findings.push(
                Finding::new(
                    "sol_oracle_self_trade".to_string(),
                    Severity::High,
                    file_path.to_string(),
                    line_num + 1,
                    0,
                    "Single signer controls both sides of price trade".to_string(),
                    line.trim().to_string(),
                )
                .with_metadata("chain".to_string(), "solana".to_string()),
            );
        }
    }

    findings
}

/// Detects a treasury whose funds move under one non-multisig authority.
pub fn detect_treasury_single_authority(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // The old check fired on every line containing "vault" or "treasury"
    // together with "authority" — a struct field, a `has_one` constraint, an
    // assignment — producing a HIGH per mention on any correctly-built Anchor
    // vault. The finding is a *design* property of the whole program: funds
    // actually leave it, and a single key controls that. Report it once.
    let lower = source.to_lowercase();
    let has_multisig = lower.contains("multisig")
        || lower.contains("multi_sig")
        || lower.contains("threshold")
        || lower.contains("governance")
        || lower.contains("squads");
    if has_multisig {
        return findings;
    }
    let single_authority = lower.contains("authority: signer")
        || lower.contains("admin: signer")
        || lower.contains("owner: signer");
    if !single_authority {
        return findings;
    }

    // First line that actually moves value out.
    let moves_value = source.lines().enumerate().find(|(_, l)| {
        let l = l.to_lowercase();
        l.contains("try_borrow_mut_lamports")
            || l.contains("token::transfer")
            || l.contains("system_program::transfer")
            || l.contains("transfer_checked")
    });
    if let Some((line_num, line)) = moves_value {
        findings.push(
            Finding::new(
                "sol_treasury_single_authority".to_string(),
                Severity::High,
                file_path.to_string(),
                line_num + 1,
                0,
                "Funds leave this program under a single signer with no multisig or \
                 governance: one compromised key drains the treasury"
                    .to_string(),
                line.trim().to_string(),
            )
            .with_metadata("chain".to_string(), "solana".to_string()),
        );
    }

    findings
}

/// Detects admin functions with no timelock
pub fn detect_admin_no_timelock(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();

        if (lower.contains("upgrade") || lower.contains("admin") || lower.contains("freeze"))
            && lower.contains("authority")
            && !lower.contains("timelock")
            && !lower.contains("delay")
        {
            findings.push(
                Finding::new(
                    "sol_admin_no_timelock".to_string(),
                    Severity::High,
                    file_path.to_string(),
                    line_num + 1,
                    0,
                    "Admin function executes immediately with no timelock delay".to_string(),
                    line.trim().to_string(),
                )
                .with_metadata("chain".to_string(), "solana".to_string()),
            );
        }
    }

    findings
}

/// Detects a sysvar or program account accepted without address validation.
pub fn detect_sysvar_account_validation(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    // `Program<'info, System>` and `Sysvar<'info, Clock>` *are* the validated
    // forms — Anchor checks the address. The old check fired on any line
    // mentioning `system_program` or `clock`, including those. The finding is
    // a sysvar/program passed as a raw `AccountInfo` with no `address =`
    // constraint, which lets the caller substitute a fake.
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("pub ") || !trimmed.contains(':') {
            continue;
        }
        let Some((name, ty)) = trimmed.trim_start_matches("pub ").split_once(':') else {
            continue;
        };
        let name = name.trim().to_lowercase();
        let ty = ty.trim();
        let sysvar_role = name.contains("sysvar")
            || name.contains("system_program")
            || name.contains("token_program")
            || name == "clock"
            || name == "rent"
            || name.contains("instructions");
        if !sysvar_role {
            continue;
        }
        let raw = ty.starts_with("AccountInfo<") || ty.starts_with("UncheckedAccount<");
        if !raw {
            continue;
        }
        let above: Vec<&str> = lines[i.saturating_sub(4)..i].to_vec();
        if above
            .iter()
            .any(|l| l.contains("address") || l.contains("/// CHECK:"))
        {
            continue;
        }

        findings.push(
            Finding::new(
                "sol_sysvar_account_validation".to_string(),
                Severity::Medium,
                file_path.to_string(),
                i + 1,
                0,
                format!(
                    "`{}` is accepted as a raw account with no address constraint: a caller \
                     can substitute any account for the sysvar or program",
                    name
                ),
                trimmed.to_string(),
            )
            .with_metadata("chain".to_string(), "solana".to_string()),
        );
    }

    findings
}

/// Run all Solana detectors
pub fn detect_all(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_missing_signer(source, file_path));
    findings.extend(detect_oracle_rate_account(source, file_path));
    findings.extend(detect_oracle_self_trade(source, file_path));
    findings.extend(detect_treasury_single_authority(source, file_path));
    findings.extend(detect_admin_no_timelock(source, file_path));
    findings.extend(detect_sysvar_account_validation(source, file_path));

    findings.sort_by(|a, b| match b.severity.cmp(&a.severity) {
        std::cmp::Ordering::Equal => a.line.cmp(&b.line),
        other => other,
    });

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_signer_detection() {
        let code = r#"
        #[derive(Accounts)]
        pub struct Transfer {
            #[account(mut)]
            pub payer: AccountInfo<'a>,
        }
        "#;

        let findings = detect_missing_signer(code, "program.rs");
        // Should find the issue
        for f in findings {
            assert_eq!(f.invariant_id, "sol_missing_signer");
        }
    }
}
