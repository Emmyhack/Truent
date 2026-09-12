/// Solana Account Rent Exemption Detector
///
/// Detects H55 vulnerability: Accounts not properly rent-exempt
///
/// The vulnerability occurs when:
/// 1. Mutable account lacks rent exemption requirement
/// 2. Account can be reclaimed by Solana runtime if rent unpaid
/// 3. State loss or double-spend possible
/// 4. PDA accounts must be properly initialized
///
use lazy_static::lazy_static;
use regex::Regex;
use truent_core::Finding;

lazy_static! {
    /// Where lamports are created or drained by hand.
    static ref RENT_SENSITIVE_OP: Regex = Regex::new(
        r"(?i)create_account(_with_seed)?\s*\(|try_borrow_mut_lamports\s*\(\s*\)\s*\??\s*-=|\.lamports\s*\(\s*\)\s*-|sub_lamports\s*\("
    ).unwrap();
    static ref RENT_EXEMPT_CHECK: Regex =
        Regex::new(r"(?i)rent\.is_exempt|minimum_balance|rent_exempt|Rent::get").unwrap();
}

pub fn detect_solana_rent_exemption(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    // Rent only matters where lamports are created or drained by hand.
    // Anchor's `init` allocates a rent-exempt account itself, and a plain
    // `#[account(mut)]` on an existing account has nothing to do with rent —
    // the old check fired on every one of those, and looked for the rent
    // check in a 100-line window that bled into unrelated code.
    for (line_num, line) in lines.iter().enumerate() {
        if !RENT_SENSITIVE_OP.is_match(line) {
            continue;
        }
        let body = enclosing_body(&lines, line_num);
        if RENT_EXEMPT_CHECK.is_match(&body) {
            continue;
        }

        findings.push(
            Finding::new(
                "sol_rent_exemption_check".to_string(),
                truent_core::Severity::Medium,
                file_path.to_string(),
                line_num + 1,
                0,
                "Lamports are created or withdrawn by hand with no rent-exemption check: an \
                 account left below the rent-exempt minimum can be garbage-collected, losing \
                 its state"
                    .to_string(),
                line.trim().to_string(),
            )
            .with_metadata("exploit_id".to_string(), "H55".to_string())
            .with_metadata(
                "exploit_name".to_string(),
                "Solana Rent Exemption".to_string(),
            )
            .with_metadata(
                "vulnerability_type".to_string(),
                "rent_violation".to_string(),
            )
            .with_metadata("detector".to_string(), "pattern_analysis".to_string())
            .with_metadata(
                "remediation".to_string(),
                "Check Rent::get()?.minimum_balance(len) before creating or draining".to_string(),
            ),
        );
    }

    findings
}

/// The brace-delimited function containing `line_idx`, walking back to its
/// declaration and forward to its closing brace.
fn enclosing_body(lines: &[&str], line_idx: usize) -> String {
    // No enclosing declaration (a bare snippet): the whole text is the body,
    // so a guard on the line *above* the operation is still seen.
    let Some(start) = (0..=line_idx)
        .rev()
        .find(|&i| lines[i].contains("fn ") && lines[i].contains('('))
    else {
        return lines.join("\n");
    };
    let mut depth: i32 = 0;
    let mut opened = false;
    let mut out: Vec<&str> = Vec::new();
    for l in lines.iter().skip(start) {
        out.push(l);
        depth += l.matches('{').count() as i32;
        if depth > 0 {
            opened = true;
        }
        depth -= l.matches('}').count() as i32;
        if opened && depth <= 0 {
            break;
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mutable_existing_account_is_not_a_rent_finding() {
        // This test used to assert the opposite. A `#[account(mut)]` on an
        // account that already exists has nothing to do with rent — the
        // runtime keeps existing accounts rent-exempt — and reporting every
        // one of them fired on every Anchor program in existence.
        let existing = r#"
        #[account(mut)]
        pub user_account: AccountInfo<'info>,
        "#;
        let findings = detect_solana_rent_exemption(existing, "test.rs");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn creating_an_account_without_minimum_balance_is_flagged() {
        // Rent matters where lamports are created or drained by hand.
        let vulnerable = r#"
        pub fn make(ctx: Context<Make>, size: u64) -> Result<()> {
            system_program::create_account(
                CpiContext::new(ctx.accounts.system_program.to_account_info(), cpi),
                1_000,
                size,
                &program_id,
            )?;
            Ok(())
        }
        "#;
        let findings = detect_solana_rent_exemption(vulnerable, "test.rs");
        assert!(!findings.is_empty());
    }

    #[test]
    fn draining_lamports_without_a_rent_check_is_flagged() {
        let vulnerable = r#"
        pub fn drain(ctx: Context<Drain>, amount: u64) -> Result<()> {
            **ctx.accounts.vault.to_account_info().try_borrow_mut_lamports()? -= amount;
            Ok(())
        }
        "#;
        assert!(!detect_solana_rent_exemption(vulnerable, "test.rs").is_empty());
    }

    #[test]
    fn test_with_rent_exempt_check() {
        let safe = r#"
        #[account(mut)]
        pub user_account: AccountInfo<'info>,
        
        let is_exempt = rent.is_exempt(user_account.lamports(), user_account.data.len());
        require!(is_exempt, "Not rent exempt");
        "#;
        let findings = detect_solana_rent_exemption(safe, "test.rs");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_pda_creation() {
        let safe = r#"
        let required_lamports = rent.minimum_balance(account_size);
        system_program::create_account(
            CpiContext::new(...),
            required_lamports,
            account_size,
            &bumps.pda,
        )?;
        "#;
        let findings = detect_solana_rent_exemption(safe, "test.rs");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_transfer_with_seed() {
        let safe = r#"
        let rent_exempt = rent.minimum_balance(MY_ACCOUNT_SIZE);
        system_program::transfer_with_seed(
            CpiContext::new(...),
            rent_exempt,
            MY_ACCOUNT_SIZE,
            &seed,
            &bump,
        )?;
        "#;
        let findings = detect_solana_rent_exemption(safe, "test.rs");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_immutable_account() {
        let ignored = r#"
        pub account: AccountInfo<'info>,
        "#;
        let findings = detect_solana_rent_exemption(ignored, "test.rs");
        assert!(findings.is_empty()); // Immutable accounts don't need rent check
    }
}
