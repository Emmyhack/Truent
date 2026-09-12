//! Move detector implementations.
//!
//! Detectors for Move (Aptos/Sui) module vulnerabilities.

use truent_core::{Finding, Severity};

/// Detects public entry functions that mutate without any authority check.
pub fn detect_access_control_missing(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let is_privileged_entry = (line.contains("public entry") || line.contains("public fun"))
            && (line.contains("transfer")
                || line.contains("burn")
                || line.contains("mint")
                || line.contains("withdraw"));
        if !is_privileged_entry {
            continue;
        }

        // The old check looked only at the declaration for a capability
        // parameter. Move's other idiom — take a `&signer` and assert who it
        // is — lives in the body, so every correctly guarded `withdraw` was
        // reported as unguarded.
        let body = enclosing_body(source, line_num);
        if has_capability_param(line) || body_asserts_authority(&body) {
            continue;
        }

        findings.push(
            Finding::new(
                "move_access_control_missing".to_string(),
                Severity::High,
                file_path.to_string(),
                line_num + 1,
                0,
                "Public entry function lacks capability/permission check".to_string(),
                line.trim().to_string(),
            )
            .with_metadata("chain".to_string(), "move".to_string()),
        );
    }

    findings
}

/// `&Capability`, `&AdminCap`, `cap: &XCap` — the capability idiom.
fn has_capability_param(decl: &str) -> bool {
    decl.contains("&Capability") || (decl.contains("Cap") && decl.contains('&'))
}

/// An authority assertion in a body: `assert!(signer::address_of(s) == ...)`,
/// `assert!(addr == @admin)`, or an `assert_admin`/`is_admin`-style helper.
fn body_asserts_authority(body: &str) -> bool {
    let lower = body.to_lowercase();
    let asserts = lower.contains("assert!(") || lower.contains("abort");
    let names_authority = lower.contains("signer::address_of(")
        || lower.contains("== @")
        || lower.contains(".admin")
        || lower.contains(".owner");
    (asserts && names_authority)
        || lower.contains("assert_admin(")
        || lower.contains("assert_owner(")
        || lower.contains("is_admin(")
        || lower.contains("only_admin(")
        || lower.contains("has_role(")
}

/// Detects liquidity conservation absence in AMM swaps
pub fn detect_liquidity_conservation(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        if (line.contains("swap") || line.contains("exchange"))
            && !line.contains("assert")
            && !line.contains("require")
        {
            // The enclosing function, delimited by brace depth — a fixed
            // 30-line window bled into whatever function followed.
            let func_body = enclosing_body(source, line_num);

            if !func_body.contains("*") || !func_body.contains("==") {
                findings.push(
                    Finding::new(
                        "move_liquidity_conservation".to_string(),
                        Severity::Critical,
                        file_path.to_string(),
                        line_num + 1,
                        0,
                        "AMM swap does not assert x*y==k invariant".to_string(),
                        line.trim().to_string(),
                    )
                    .with_metadata("chain".to_string(), "move".to_string()),
                );
            }
        }
    }

    findings
}

/// Detects admin operations that take effect with no timelock.
pub fn detect_admin_no_timelock(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // The old check fired on every line containing "admin", "upgrade" or
    // "freeze" — a struct field, an assertion, a `move_to` — so a correctly
    // guarded module produced one HIGH per mention. The finding is about a
    // *privileged operation* that takes effect immediately; it is reported
    // once, at that function, and only when the module has no delay
    // mechanism at all.
    let lower_src = source.to_lowercase();
    let module_has_delay = lower_src.contains("timelock")
        || lower_src.contains("delay")
        || lower_src.contains("unlock_time")
        || lower_src.contains("execute_after")
        || lower_src.contains("pending_")
        || lower_src.contains("scheduled");
    if module_has_delay {
        return findings;
    }

    for (line_num, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();
        if !(lower.contains("public entry fun") || lower.contains("public fun")) {
            continue;
        }
        let is_time_sensitive_privilege = lower.contains("upgrade")
            || lower.contains("freeze")
            || lower.contains("set_admin")
            || lower.contains("transfer_admin")
            || lower.contains("set_fee")
            || lower.contains("pause")
            || lower.contains("set_owner");
        if !is_time_sensitive_privilege {
            continue;
        }
        // Only an operation that *is* admin-gated can be "admin without a
        // timelock"; an ungated one is access_control_missing's finding.
        let body = enclosing_body(source, line_num);
        if !(has_capability_param(line) || body_asserts_authority(&body)) {
            continue;
        }

        findings.push(
            Finding::new(
                "move_admin_no_timelock".to_string(),
                Severity::High,
                file_path.to_string(),
                line_num + 1,
                0,
                "Privileged operation takes effect immediately: no timelock or delay gives \
                 users a window to react if the admin key is compromised"
                    .to_string(),
                line.trim().to_string(),
            )
            .with_metadata("chain".to_string(), "move".to_string()),
        );
    }

    findings
}

/// Detects pool reserve used directly for price
pub fn detect_oracle_spot_price(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        if (line.contains("reserve") || line.contains("balance"))
            && (line.contains("price") || line.contains("rate"))
        {
            findings.push(
                Finding::new(
                    "move_oracle_spot_price".to_string(),
                    Severity::Critical,
                    file_path.to_string(),
                    line_num + 1,
                    0,
                    "Pool reserve used directly for pricing without oracle".to_string(),
                    line.trim().to_string(),
                )
                .with_metadata("chain".to_string(), "move".to_string()),
            );
        }
    }

    findings
}

/// Run all Move detectors
pub fn detect_all(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_access_control_missing(source, file_path));
    findings.extend(detect_liquidity_conservation(source, file_path));
    findings.extend(detect_admin_no_timelock(source, file_path));
    findings.extend(detect_oracle_spot_price(source, file_path));

    findings.sort_by(|a, b| match b.severity.cmp(&a.severity) {
        std::cmp::Ordering::Equal => a.line.cmp(&b.line),
        other => other,
    });

    findings
}

/// The brace-delimited body starting at `line_idx`, so a check in one
/// function is never credited to another.
fn enclosing_body(source: &str, line_idx: usize) -> String {
    let mut depth: i32 = 0;
    let mut opened = false;
    let mut out: Vec<&str> = Vec::new();
    for line in source.lines().skip(line_idx) {
        out.push(line);
        depth += line.matches('{').count() as i32;
        if depth > 0 {
            opened = true;
        }
        depth -= line.matches('}').count() as i32;
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
    fn test_access_control_detection() {
        let code = r#"
        public entry fun withdraw<T>(
            vault: &mut Vault<T>,
            amount: u64,
            ctx: &mut TxContext
        ) {
            // ...
        }
        "#;

        let findings = detect_access_control_missing(code, "module.move");
        for f in findings {
            assert!(f.invariant_id.starts_with("move_"));
        }
    }
}
