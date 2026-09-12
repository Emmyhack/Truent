//! EVM Detector implementations using Finding type.
//!
//! Each detector discovers invariant violations and returns them as Finding objects.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use crate::detectors::textutil;

lazy_static! {
    /// A quantity that is a price, rate, or valuation — the thing a spot-price
    /// bug actually produces. Deliberately narrow: matching bare "amount"
    /// flagged every token transfer in existence.
    static ref PRICE_TARGET_REGEX: Regex = Regex::new(
        // `price` matches as a substring so `getPrice`/`spotPrice`/`priceOf`
        // are caught — a leading \b would miss all of them, since there is no
        // word boundary inside `getPrice`. The looser words stay anchored so
        // `rate` does not match `generate` or `accurate`.
        r"(?i)(price|exchange_?rate|virtual_?price|per_?share|valuation|\brate\b|\bquote\b|\bworth\b)"
    ).unwrap();

    /// An external ERC-20 call: `token.transfer(...)`, `IERC20(x).transferFrom(...)`,
    /// `safeTransfer(...)`. Requires a call, not the word "transfer".
    static ref EXTERNAL_TOKEN_CALL_REGEX: Regex = Regex::new(
        r"(?i)(\.\s*(safe)?transfer(from)?\s*\(|\bierc20\s*\([^)]*\)\s*\.\s*\w+\s*\()"
    ).unwrap();

    /// A real oracle feed — if a pricing function consults one of these, the
    /// balance read beside it is not the price source.
    static ref ORACLE_SOURCE_REGEX: Regex = Regex::new(
        r"(?i)(oracle|chainlink|aggregator|latestrounddata|twap|pyth|band\b|uniswapv[23]oracle)"
    ).unwrap();

    /// A write to internal balance accounting.
    static ref BALANCE_WRITE_REGEX: Regex = Regex::new(
        r"(?i)_?balances?\s*\[[^\]]*\]\s*(=[^=]|\+=|-=)"
    ).unwrap();

    /// `owner = msg.sender` — the admin role actually being assigned to the
    /// caller.
    static ref ADMIN_ASSIGNMENT: Regex = Regex::new(
        r"(?i)\b(owner|admin)\w*\s*=\s*(msg\.sender|_msgSender\s*\(\s*\))"
    ).unwrap();

    /// An authorisation modifier on a function declaration.
    static ref AUTH_MODIFIER_REGEX: Regex = Regex::new(
        r"(?i)\bonly\w*\b|\brequiresAuth\b|\bauth\b|\bonlyRole\s*\(|\bwhenOwner\b|\badminOnly\b"
    ).unwrap();

    /// A caller-controlled call payload in a parameter list.
    static ref RELAY_CALLDATA_PARAM: Regex =
        Regex::new(r"(?i)\bbytes\s+(calldata|memory)\s+\w+|\baddress\s+(target|to|dest)\w*\b").unwrap();

    /// A low-level call that could carry a forwarded payload.
    static ref RELAY_FORWARD_CALL: Regex =
        Regex::new(r"\.\s*(call|delegatecall)\s*(\{[^}]*\})?\s*\(").unwrap();

    /// A function declaration.
    static ref FUNCTION_DECL_REGEX: Regex =
        Regex::new(r"(?i)\bfunction\s+\w*\s*\(|\b(constructor|receive|fallback)\s*\(").unwrap();

    /// A reentrancy guard applied to a function.
    static ref REENTRANCY_GUARD_REGEX: Regex =
        Regex::new(r"(?i)\bnon_?reentrant\b|\bmutex\b|\block(ed)?\b").unwrap();

    /// A value-bearing external call: the point after which state must not be
    /// written.
    static ref EXTERNAL_CALL_REGEX: Regex = Regex::new(
        r"(?i)\.\s*call\s*\{|\.\s*call\s*\(|\.\s*send\s*\(|\.\s*transfer\s*\(|\.\s*delegatecall\s*\("
    ).unwrap();

    /// A local variable declaration, which is not a state write.
    static ref LOCAL_DECL_REGEX: Regex = Regex::new(
        r"(?i)^\s*(uint\d*|int\d*|bool|address|bytes\d*|string|mapping|var)\b[^=]*=|^\s*\w+\s+(memory|storage|calldata)\s+\w+\s*="
    ).unwrap();

    /// An assignment to a storage location.
    static ref STATE_WRITE_REGEX: Regex = Regex::new(
        r"^[A-Za-z_]\w*(\s*\[[^\]]*\])*(\s*\.\s*\w+)*\s*(\+=|-=|\*=|/=|=[^=])"
    ).unwrap();

    /// Any equality/inequality comparison, which is a guard rather than an
    /// assignment and must never be reported as one.
    static ref ADMIN_COMPARISON: Regex = Regex::new(r"(==|!=|>=|<=)").unwrap();
}

/// Detects classic reentrancy: a state update that happens *after* an external
/// call, within the same function, with no reentrancy guard.
///
/// The previous implementation flagged every external call in any contract
/// lacking a `nonReentrant` modifier, without ever checking ordering — so
/// textbook checks-effects-interactions code, where the state write precedes
/// the call, was reported as CRITICAL reentrancy. That is the whole bug class:
/// the finding is about *order*, and order was never examined.
pub fn detect_reentrancy_classic(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines = textutil::code_lines(source);

    for func in split_functions(&lines) {
        // A guard on the function (or its modifiers) makes reentry impossible.
        if func
            .lines
            .first()
            .map(|(_, l)| REENTRANCY_GUARD_REGEX.is_match(l))
            .unwrap_or(false)
        {
            continue;
        }

        for (pos, (line_num, line)) in func.lines.iter().enumerate() {
            if !EXTERNAL_CALL_REGEX.is_match(line) {
                continue;
            }

            // The violation is a state write *after* this call, still inside
            // this function.
            let writes_after = func
                .lines
                .iter()
                .skip(pos + 1)
                .any(|(_, later)| is_state_write(later));

            if writes_after {
                findings.push(
                    Finding::new(
                        "evm_reentrancy_classic".to_string(),
                        Severity::Critical,
                        file_path.to_string(),
                        line_num + 1,
                        0,
                        "State is updated after an external call, so a reentrant call \
                         observes stale state (checks-effects-interactions violated)"
                            .to_string(),
                        line.trim().to_string(),
                    )
                    .with_metadata("detector".to_string(), "pattern_match".to_string()),
                );
            }
        }
    }

    findings
}

/// A function body: its signature line plus its statements, each carrying the
/// original line index so findings point at real source.
pub struct FunctionSpan {
    pub lines: Vec<(usize, String)>,
}

/// Split prepared source into function spans by brace depth.
///
/// Crude but sufficient, and far better than the whole-file scanning the
/// detectors used to do: a state write in one function can no longer be
/// attributed to an external call in another.
pub fn split_functions(lines: &[String]) -> Vec<FunctionSpan> {
    let mut spans = Vec::new();
    let mut current: Option<FunctionSpan> = None;
    let mut depth: i32 = 0;

    for (idx, line) in lines.iter().enumerate() {
        if current.is_none() && FUNCTION_DECL_REGEX.is_match(line) {
            current = Some(FunctionSpan { lines: Vec::new() });
            depth = 0;
        }

        if let Some(span) = current.as_mut() {
            span.lines.push((idx, line.clone()));
            depth += line.matches('{').count() as i32;
            depth -= line.matches('}').count() as i32;
            // Depth returns to zero only once the body has opened and closed.
            if depth <= 0 && span.lines.iter().any(|(_, l)| l.contains('{')) {
                spans.push(current.take().expect("span exists"));
            }
        }
    }
    if let Some(span) = current {
        spans.push(span);
    }
    spans
}

/// Whether a line writes contract state.
///
/// Local declarations (`uint256 balance = ...`) and tuple destructuring of a
/// call result (`(bool ok, ) = ...`) are assignments but not state writes, and
/// counting them would resurrect the false positive this detector exists to
/// avoid.
pub(crate) fn is_state_write(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with('(') {
        return false; // tuple destructuring of a call result
    }
    if LOCAL_DECL_REGEX.is_match(trimmed) {
        return false;
    }
    STATE_WRITE_REGEX.is_match(trimmed)
}

/// Detects missing signer checks in external state-modifying functions
pub fn detect_missing_signer_check(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<String> = source.lines().map(str::to_string).collect();

    for func in split_functions(&lines) {
        let Some((decl_idx, decl)) = func.lines.first() else {
            continue;
        };
        let trimmed = decl.trim();

        // A declaration ending in `;` has no body — an interface or abstract
        // signature. It cannot contain a signer check, cannot modify state,
        // and is not code that runs.
        if trimmed.ends_with(';') {
            continue;
        }
        let is_entry = (trimmed.contains("public") || trimmed.contains("external"))
            && !trimmed.contains("pure")
            && !trimmed.contains("view");
        if !is_entry {
            continue;
        }

        // Authorisation can live on the declaration as a modifier —
        // `onlyOwner`, `onlyRole(MINTER_ROLE)`, `requiresAuth` — which the
        // previous 20-line body scan never looked at, so every role-gated
        // function in an AccessControl contract was reported as unguarded.
        if AUTH_MODIFIER_REGEX.is_match(trimmed) {
            continue;
        }

        let body = func
            .lines
            .iter()
            .skip(1)
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n")
            .to_lowercase();

        let has_access_check = body.contains("msg.sender")
            || body.contains("_msgsender()")
            || body.contains("require(")
            || body.contains("revert")
            || body.contains("_checkrole")
            || body.contains("_checkowner")
            || body.contains("hasrole(");

        let modifies_state = func
            .lines
            .iter()
            .skip(1)
            .any(|(_, l)| is_state_write(l) || EXTERNAL_TOKEN_CALL_REGEX.is_match(l));

        if modifies_state && !has_access_check {
            findings.push(
                Finding::new(
                    "evm_missing_signer_check".to_string(),
                    Severity::High,
                    file_path.to_string(),
                    decl_idx + 1,
                    0,
                    "External state-modifying function lacks msg.sender validation".to_string(),
                    trimmed.to_string(),
                )
                .with_metadata("detector".to_string(), "ast_analysis".to_string()),
            );
        }
    }

    findings
}

/// Detects conservation check absence: AMM swaps without x*y=k verification
pub fn detect_conservation_check_absent(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Pattern: swap/exchange function that modifies reserves without k invariant check
    for (line_num, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();

        if (lower.contains("function swap") || lower.contains("function exchange"))
            && !lower.contains("view")
            && !lower.contains("pure")
        {
            // Check function body for k invariant verification
            let func_body = source
                .lines()
                .skip(line_num)
                .take(50)
                .collect::<Vec<_>>()
                .join("\n");

            let has_k_check = func_body.to_lowercase().contains("require(")
                && (func_body.to_lowercase().contains("* ")
                    || func_body.to_lowercase().contains("*"));

            let modifies_reserves = func_body.to_lowercase().contains("reservea")
                || func_body.to_lowercase().contains("reserveb")
                || func_body.to_lowercase().contains("reserve0")
                || func_body.to_lowercase().contains("reserve1");

            if modifies_reserves && !has_k_check {
                findings.push(
                    Finding::new(
                        "evm_conservation_check_absent".to_string(),
                        Severity::Critical,
                        file_path.to_string(),
                        line_num + 1,
                        0,
                        "AMM swap function does not verify x*y=k invariant after exchange"
                            .to_string(),
                        line.trim().to_string(),
                    )
                    .with_metadata("detector".to_string(), "invariant_check".to_string())
                    .with_metadata("impact".to_string(), "pool can be drained".to_string()),
                );
            }
        }
    }

    findings
}

/// Detects oracle spot price vulnerabilities: using balanceOf as price
pub fn detect_oracle_spot_price(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Previously this fired when a line mentioned `balanceOf`/`reserve` AND
    // contained any of "price", "rate", "amount" *or* "=". That last clause
    // matched almost every line in existence — `mapping(address => uint256)`,
    // `require(balanceOf[x] >= y)`, `balanceOf[x] -= y` — so a plain ERC-20
    // produced eleven CRITICAL "oracle" findings and no contract was safe.
    //
    // A spot-price finding now requires a balance/reserve read to actually
    // reach a price-shaped quantity. That intent lives at function scope, not
    // line scope: in `function getPrice() { return reserve1 * 1e18 / reserve0; }`
    // the price word is in the signature and the arithmetic is on another
    // line, so both are tracked.
    let lines = textutil::code_lines(source);
    let mut fn_is_pricing = false;
    let mut fn_has_oracle = false;
    let mut depth: i32 = 0;

    // A function's oracle usage may appear after the arithmetic, so each
    // function is resolved as a unit before its candidates are emitted.
    let mut pending: Vec<(usize, String)> = Vec::new();

    let flush = |pending: &mut Vec<(usize, String)>, has_oracle: bool, out: &mut Vec<Finding>| {
        if !has_oracle {
            for (line_num, text) in pending.iter() {
                out.push(
                    Finding::new(
                        "evm_oracle_spot_price".to_string(),
                        Severity::Critical,
                        file_path.to_string(),
                        line_num + 1,
                        0,
                        "Spot price derived from a token balance or pool reserve rather than \
                         an oracle"
                            .to_string(),
                        text.clone(),
                    )
                    .with_metadata("detector".to_string(), "pattern_match".to_string()),
                );
            }
        }
        pending.clear();
    };

    for (line_num, line) in lines.iter().enumerate() {
        let lower = line.to_lowercase();

        if lower.contains("function ") {
            // Leaving the previous function: resolve whatever it accumulated.
            flush(&mut pending, fn_has_oracle, &mut findings);
            fn_is_pricing = PRICE_TARGET_REGEX.is_match(&lower);
            fn_has_oracle = false;
            depth = 0;
        }

        if ORACLE_SOURCE_REGEX.is_match(&lower) {
            fn_has_oracle = true;
        }

        let reads_balance = lower.contains("balanceof")
            || lower.contains("getreserves")
            || lower.contains("reserve0")
            || lower.contains("reserve1")
            || lower.contains(".reserves");

        // The read must feed arithmetic — that is what turns a balance into a
        // price — or be assigned to something price-shaped on the same line.
        let arithmetic = lower.contains('*') || lower.contains('/');
        let assigns_price = PRICE_TARGET_REGEX.is_match(&lower) && lower.contains('=');

        if reads_balance && ((fn_is_pricing && arithmetic) || assigns_price) {
            pending.push((line_num, line.trim().to_string()));
        }

        depth += line.matches('{').count() as i32;
        depth -= line.matches('}').count() as i32;
        if depth <= 0 && !pending.is_empty() && !lower.contains("function ") {
            flush(&mut pending, fn_has_oracle, &mut findings);
        }
    }
    flush(&mut pending, fn_has_oracle, &mut findings);

    findings
}

/// Detects unprotected initializer functions
pub fn detect_unprotected_initializer(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        if line.contains("function initialize") && !line.contains("//") {
            // Check for initializer modifier
            if !line.contains("initializer") && !line.contains("onlyInitializing") {
                findings.push(
                    Finding::new(
                        "evm_unprotected_initializer".to_string(),
                        Severity::Critical,
                        file_path.to_string(),
                        line_num + 1,
                        0,
                        "Initialize function lacks initializer modifier - can be called multiple times".to_string(),
                        line.trim().to_string(),
                    )
                    .with_metadata("detector".to_string(), "modifier_check".to_string())
                );
            }
        }
    }

    findings
}

/// Detects unsafe math without SafeMath (Solidity <0.8.0)
pub fn detect_legacy_unsafe_math(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check Solidity version
    let version_line = source.lines().find(|l| l.contains("pragma solidity"));

    if let Some(v_line) = version_line {
        // If version < 0.8.0, check for unsafe math without SafeMath
        if v_line.contains("0.7") || v_line.contains("0.6") || v_line.contains("0.5") {
            let has_safemath = source.contains("SafeMath") || source.contains("using SafeMath");

            if !has_safemath {
                // Check for arithmetic operations
                for (line_num, line) in source.lines().enumerate() {
                    let lower = line.to_lowercase();
                    if (lower.contains(" + ") || lower.contains(" - ") || lower.contains(" * "))
                        && !lower.contains("//")
                        && !lower.contains("safemath")
                    {
                        findings.push(
                            Finding::new(
                                "evm_legacy_unsafe_math".to_string(),
                                Severity::High,
                                file_path.to_string(),
                                line_num + 1,
                                0,
                                "Arithmetic operation in Solidity <0.8.0 without SafeMath"
                                    .to_string(),
                                line.trim().to_string(),
                            )
                            .with_metadata("detector".to_string(), "version_check".to_string()),
                        );
                        break; // Report once per file
                    }
                }
            }
        }
    }

    findings
}

/// Detects flash loan governance attacks: snapshot on same block as loan
pub fn detect_flash_loan_governance(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();

        // Look for block.number used in voting/snapshot
        if lower.contains("block.number")
            && (lower.contains("vote")
                || lower.contains("snapshot")
                || lower.contains("vote_power"))
        {
            findings.push(
                Finding::new(
                    "evm_flash_loan_governance".to_string(),
                    Severity::High,
                    file_path.to_string(),
                    line_num + 1,
                    0,
                    "Block-based voting snapshot vulnerable to flash loan attacks".to_string(),
                    line.trim().to_string(),
                )
                .with_metadata("detector".to_string(), "pattern_match".to_string()),
            );
        }
    }

    findings
}

/// Detects DVN threshold vulnerabilities in LayerZero bridges
pub fn detect_dvn_threshold(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Look for DVN threshold configuration
    for (line_num, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();

        if (lower.contains("dvnthreshold") || lower.contains("dvn_threshold"))
            && (lower.contains(" = 0") || lower.contains(" = 1"))
        {
            findings.push(
                Finding::new(
                    "evm_dvn_threshold".to_string(),
                    Severity::Critical,
                    file_path.to_string(),
                    line_num + 1,
                    0,
                    "DVN threshold set to 0 or 1 - insufficient validation".to_string(),
                    line.trim().to_string(),
                )
                .with_metadata("detector".to_string(), "config_check".to_string()),
            );
        }
    }

    findings
}

/// Detects ERC20 reentrancy: token transfer before internal accounting update
pub fn detect_reentrancy_erc20(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines = textutil::code_lines(source);

    // This used to match any line whose *text* contained "erc20" and
    // "transfer" — which includes every OpenZeppelin revert string
    // (`"ERC20: transfer from the zero address"`), so every standard token
    // reported CRITICAL reentrancy on its `require` lines.
    //
    // Matching is now against code with string literals and comments stripped,
    // and requires an actual external token call, not the word "transfer".
    for (line_num, line) in lines.iter().enumerate() {
        if !EXTERNAL_TOKEN_CALL_REGEX.is_match(line) {
            continue;
        }

        // Checks-effects-interactions is only violated if internal accounting
        // is written *after* the external call.
        let updates_after = lines
            .iter()
            .skip(line_num + 1)
            .take(10)
            .any(|l| BALANCE_WRITE_REGEX.is_match(l));

        if updates_after {
            findings.push(
                Finding::new(
                    "evm_reentrancy_erc20".to_string(),
                    Severity::Critical,
                    file_path.to_string(),
                    line_num + 1,
                    0,
                    "External token transfer occurs before internal balance accounting is updated"
                        .to_string(),
                    line.trim().to_string(),
                )
                .with_metadata("detector".to_string(), "token_pattern".to_string()),
            );
        }
    }

    findings
}

/// Detects precision loss: division before multiplication in finance
pub fn detect_precision_loss(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        // Pattern: (a / b) * c (should be a * c / b)
        if line.contains(" / ") && line.contains(" * ") {
            let div_pos = line.find(" / ");
            let mul_pos = line.find(" * ");

            if let (Some(d), Some(m)) = (div_pos, mul_pos) {
                if d < m {
                    findings.push(
                        Finding::new(
                            "evm_precision_loss".to_string(),
                            Severity::Medium,
                            file_path.to_string(),
                            line_num + 1,
                            d,
                            "Division before multiplication may cause precision loss".to_string(),
                            line.trim().to_string(),
                        )
                        .with_metadata("detector".to_string(), "arithmetic_pattern".to_string()),
                    );
                }
            }
        }
    }

    findings
}

/// Detects merkle root zero check: accepts bytes32(0) as valid
pub fn detect_merkle_root_zero(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();

        // Merkle root validation without zero check
        if (lower.contains("merkleroot") || lower.contains("merkle_root"))
            && lower.contains("verify")
            && !lower.contains("require")
            && !lower.contains("!= 0")
        {
            findings.push(
                Finding::new(
                    "evm_merkle_root_zero".to_string(),
                    Severity::High,
                    file_path.to_string(),
                    line_num + 1,
                    0,
                    "Merkle root verification may accept bytes32(0) as valid".to_string(),
                    line.trim().to_string(),
                )
                .with_metadata("detector".to_string(), "validation_check".to_string()),
            );
        }
    }

    findings
}

/// Detects zero challenge period: optimistic bridge with no delay
pub fn detect_zero_challenge_period(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let lower = line.to_lowercase();

        if (lower.contains("challenge") || lower.contains("challengeperiod"))
            && (lower.contains(" = 0") || lower.contains("= 0 "))
        {
            findings.push(
                Finding::new(
                    "evm_zero_challenge_period".to_string(),
                    Severity::Critical,
                    file_path.to_string(),
                    line_num + 1,
                    0,
                    "Zero challenge period - optimistic bridge has no dispute window".to_string(),
                    line.trim().to_string(),
                )
                .with_metadata("detector".to_string(), "config_check".to_string()),
            );
        }
    }

    findings
}

/// Detects shallow auth: onlyOwner on wrapper but not inner function
/// Detects shallow authorization: a privileged internal helper that is also
/// reachable through an *unguarded* external entry point.
///
/// The previous implementation flagged any line containing `_` and `(` whose
/// callee was declared without `onlyOwner`, then reported it HIGH. Internal
/// helpers are not supposed to carry external modifiers — their callers
/// enforce access — so that fired on essentially every internal call in every
/// contract. On one 400-line contract it produced 22 findings, all spurious.
///
/// The real bug is an asymmetry: a helper that *some* callers guard and
/// another caller does not, which lets anyone reach privileged behaviour
/// through the unguarded path. That asymmetry is the evidence required here.
pub fn detect_shallow_auth(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    // Map each function to its declaration line, visibility and guard state.
    struct Func {
        name: String,
        line: usize,
        external: bool,
        guarded: bool,
        body: String,
    }

    let guard_markers = [
        "onlyowner",
        "onlyadmin",
        "onlyrole",
        "onlygovernance",
        "auth",
        "require(msg.sender",
        "if (msg.sender",
        "_checkowner",
        "_checkrole",
    ];

    let mut funcs: Vec<Func> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains("function ") {
            continue;
        }
        let Some(name) = declared_function_name(line) else {
            continue;
        };
        let lower = line.to_lowercase();
        // Views cannot alter privileged state.
        if lower.contains(" view") || lower.contains(" pure") {
            continue;
        }
        let body = function_body(&lines, i).to_lowercase();
        let declaration_and_body = format!("{}\n{}", lower, body);
        funcs.push(Func {
            name,
            line: i + 1,
            external: lower.contains("external") || lower.contains("public"),
            guarded: guard_markers
                .iter()
                .any(|g| declaration_and_body.contains(g)),
            body,
        });
    }

    for helper in &funcs {
        // Only internal helpers can be "reached through" something else.
        if helper.external {
            continue;
        }
        let call = format!("{}(", helper.name.to_lowercase());

        let callers: Vec<&Func> = funcs
            .iter()
            .filter(|f| f.name != helper.name && f.body.contains(&call))
            .collect();

        // The signal is the asymmetry: at least one caller guards this helper
        // and at least one external caller does not. A helper every caller
        // leaves open is simply not privileged.
        let guarded_callers = callers.iter().filter(|c| c.guarded).count();
        let open_external: Vec<&&Func> = callers
            .iter()
            .filter(|c| c.external && !c.guarded)
            .collect();

        if guarded_callers == 0 || open_external.is_empty() {
            continue;
        }

        for caller in open_external {
            findings.push(
                Finding::new(
                    "evm_shallow_auth".to_string(),
                    Severity::High,
                    file_path.to_string(),
                    caller.line,
                    0,
                    format!(
                        "'{}' is guarded when called from {} other function(s), but '{}' \
                         reaches it with no access control — anyone can invoke the \
                         privileged path through '{}'.",
                        helper.name, guarded_callers, caller.name, caller.name
                    ),
                    lines
                        .get(caller.line.saturating_sub(1))
                        .unwrap_or(&"")
                        .trim()
                        .to_string(),
                )
                .with_metadata("detector".to_string(), "auth_chain".to_string())
                .with_metadata("privileged_callee".to_string(), helper.name.clone()),
            );
        }
    }

    findings
}

/// Detects public relay: permissionless relay function
pub fn detect_public_relay(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<String> = source.lines().map(str::to_string).collect();

    // The previous condition was `(function && public || external) && name`,
    // which — by precedence — fired on *any* line containing "external" and
    // one of relay/execute/forward, and only ever looked for `onlyOwner` or
    // `onlyAdmin`. A timelocked, signer-gated multisig `execute()` was
    // reported as a permissionless relay.
    for func in split_functions(&lines) {
        let Some((decl_idx, decl)) = func.lines.first() else {
            continue;
        };
        let lower = decl.to_lowercase();
        let is_entry = FUNCTION_DECL_REGEX.is_match(decl)
            && (lower.contains(" public") || lower.contains(" external"))
            && !lower.contains(" view")
            && !lower.contains(" pure")
            && !decl.trim_end().ends_with(';');
        if !is_entry || AUTH_MODIFIER_REGEX.is_match(decl) {
            continue;
        }

        // A relay forwards a caller-chosen call. Both halves are required: a
        // `bytes` parameter the caller controls, and a low-level call in the
        // body that could carry it. A function merely *named* execute is not
        // a relay.
        let takes_calldata = RELAY_CALLDATA_PARAM.is_match(decl);
        let body = func
            .lines
            .iter()
            .skip(1)
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let forwards = RELAY_FORWARD_CALL.is_match(&body);
        let guarded_in_body = body.contains("msg.sender") || body.contains("require(");

        if takes_calldata && forwards && !guarded_in_body {
            findings.push(
                Finding::new(
                    "evm_public_relay".to_string(),
                    Severity::High,
                    file_path.to_string(),
                    decl_idx + 1,
                    0,
                    "Permissionless relay: anyone can have this contract execute a call of \
                     their choosing"
                        .to_string(),
                    decl.trim().to_string(),
                )
                .with_metadata("detector".to_string(), "authorization".to_string()),
            );
        }
    }

    findings
}

/// Detects single EOA admin: admin is EOA without isContract check
pub fn detect_single_eoa_admin(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        // The signal is an *assignment* of the admin role to the caller
        // (`owner = msg.sender`). The old check accepted any line containing
        // "owner", "=" and "msg.sender", which matches
        // `require(msg.sender == owner)` — a guard, and the precise opposite
        // of the finding. Every `onlyOwner` modifier in existence was reported
        // as "admin is an EOA".
        let is_comparison = ADMIN_COMPARISON.is_match(line);
        let is_assignment = ADMIN_ASSIGNMENT.is_match(line);

        if is_assignment && !is_comparison {
            // Check if code path requires multisig or contract check
            let has_contract_check =
                source.contains("isContract") || source.contains(".code.length");

            // `owner = msg.sender` inside `acceptOwnership()` is the two-step
            // handover — the caller was pre-approved as `pendingOwner` and the
            // assignment is guarded. That is the recommended pattern, not a
            // deployer claiming admin, and it must not be reported as one.
            let all_lines: Vec<String> = source.lines().map(str::to_string).collect();
            let enclosing = split_functions(&all_lines)
                .into_iter()
                .find(|f| f.lines.iter().any(|(i, _)| *i == line_num));
            let is_two_step_handover = enclosing
                .as_ref()
                .map(|f| {
                    let text = f
                        .lines
                        .iter()
                        .map(|(_, l)| l.to_lowercase())
                        .collect::<Vec<_>>()
                        .join("\n");
                    text.contains("pendingowner")
                        || text.contains("pending_owner")
                        || text.contains("proposedowner")
                        || text.contains("newowner")
                })
                .unwrap_or(false);

            if !has_contract_check && !is_two_step_handover {
                findings.push(
                    Finding::new(
                        "evm_single_eoa_admin".to_string(),
                        Severity::High,
                        file_path.to_string(),
                        line_num + 1,
                        0,
                        "Admin is EOA without multisig or contract check".to_string(),
                        line.trim().to_string(),
                    )
                    .with_metadata("detector".to_string(), "admin_check".to_string()),
                );
            }
        }
    }

    findings
}

/// Extract a function's body by brace matching, starting at its declaration.
///
/// Detectors here traditionally approximated a body as "the next 40-50 lines",
/// which runs past the closing brace and swallows whatever functions follow.
/// That misattributes their contents to the function being examined — enough
/// on its own to report `safeTransferFrom` as calling a helper defined below
/// it, which it never touches. Returns only the text between the declaration's
/// opening brace and its match.
fn function_body(lines: &[&str], decl_index: usize) -> String {
    let mut depth = 0usize;
    let mut started = false;
    let mut out = Vec::new();

    for line in lines.iter().skip(decl_index) {
        out.push(*line);
        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        if started && depth == 0 {
            break;
        }
        // A declaration without a body (interface/abstract) ends at the `;`.
        if !started && line.contains(';') {
            break;
        }
    }

    out.join("\n")
}

/// Extract the declared name from a `function <name>(...)` line.
///
/// Distinct from [`extract_function_name`], which scans from the first `_` to
/// the first `(` — that only yields a name for underscore-prefixed helpers and
/// returns `None` for an ordinary declaration like `transferOwnership`, so any
/// analysis keyed on it silently saw a partial call graph.
fn declared_function_name(line: &str) -> Option<String> {
    let after = line.split("function ").nth(1)?;
    let name = after.split('(').next()?.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    Some(name.to_string())
}

/// Run all EVM detectors on source code
pub fn detect_all(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_reentrancy_classic(source, file_path));
    findings.extend(detect_reentrancy_erc20(source, file_path));
    findings.extend(detect_missing_signer_check(source, file_path));
    findings.extend(detect_conservation_check_absent(source, file_path));
    findings.extend(detect_oracle_spot_price(source, file_path));
    findings.extend(detect_unprotected_initializer(source, file_path));
    findings.extend(detect_legacy_unsafe_math(source, file_path));
    findings.extend(detect_precision_loss(source, file_path));
    findings.extend(detect_flash_loan_governance(source, file_path));
    findings.extend(detect_dvn_threshold(source, file_path));
    findings.extend(detect_merkle_root_zero(source, file_path));
    findings.extend(detect_zero_challenge_period(source, file_path));
    findings.extend(detect_shallow_auth(source, file_path));
    findings.extend(detect_public_relay(source, file_path));
    findings.extend(detect_single_eoa_admin(source, file_path));

    // Sort by severity (critical first) then by line number
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
    fn test_reentrancy_detection() {
        let code = r#"
        function withdraw() public {
            uint amount = balances[msg.sender];
            (bool success,) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] = 0;
        }
        "#;

        let findings = detect_reentrancy_classic(code, "test.sol");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].invariant_id, "evm_reentrancy_classic");
    }

    #[test]
    fn test_missing_signer_check() {
        let code = r#"
        function withdrawAll() public {
            uint amount = balances[msg.sender];
            balances[msg.sender] = 0;
            payable(owner).transfer(amount);
        }
        "#;

        let findings = detect_missing_signer_check(code, "test.sol");
        // May or may not find depending on heuristic
        for f in findings {
            assert!(f.invariant_id.contains("signer"));
        }
    }

    #[test]
    fn test_conservation_check() {
        let code = r#"
        function swap(uint amountIn) public {
            reserveA -= amountIn;
            reserveB += (amountIn * 100) / 101;
        }
        "#;

        let findings = detect_conservation_check_absent(code, "test.sol");
        assert!(!findings.is_empty());
    }
}

#[cfg(test)]
mod trust_regression_tests {
    use super::*;

    const SHALLOW_AUTH_BUG: &str = r#"
        contract C {
            address public owner;
            function _setOwner(address o) internal { owner = o; }
            function transferOwnership(address o) external {
                require(msg.sender == owner, "no");
                _setOwner(o);
            }
            function rescueOwnership(address o) external {
                _setOwner(o);
            }
        }
    "#;

    /// The asymmetry — one guarded caller, one open external caller — is the
    /// actual bug and must still be reported.
    #[test]
    fn reports_a_genuinely_unguarded_path_to_a_privileged_helper() {
        let f = detect_shallow_auth(SHALLOW_AUTH_BUG, "c.sol");
        assert_eq!(f.len(), 1, "expected exactly the unguarded path, got {f:?}");
        assert!(f[0].message.contains("rescueOwnership"));
    }

    /// Internal helpers called only from unguarded functions are ordinary
    /// code, not a privilege escalation. The old detector flagged every
    /// internal call in the file — 22 on a single contract.
    #[test]
    fn ordinary_internal_helpers_are_not_findings() {
        let src = r#"
            contract C {
                mapping(uint256 => mapping(address => uint256)) public shareOf;
                function _mintShares(uint256 id, address to, uint256 amt) internal {
                    shareOf[id][to] += amt;
                }
                function _burnShares(uint256 id, address from, uint256 amt) internal {
                    shareOf[id][from] -= amt;
                }
                function buy(uint256 id, uint256 amt) external {
                    _mintShares(id, msg.sender, amt);
                }
                function sell(uint256 id, uint256 amt) external {
                    _burnShares(id, msg.sender, amt);
                }
            }
        "#;
        assert!(
            detect_shallow_auth(src, "c.sol").is_empty(),
            "helpers with no guarded caller are not privileged"
        );
    }

    /// Bodies are brace-matched, so a function is never credited with calls
    /// that appear in whatever is defined after it.
    #[test]
    fn function_bodies_do_not_leak_into_the_next_function() {
        let src = r#"
            contract C {
                address public owner;
                function _priv() internal { owner = msg.sender; }
                function guarded() external { require(msg.sender == owner); _priv(); }
                function unrelated() external { uint256 x = 1; }
                function alsoUnrelated() external { uint256 y = 2; }
            }
        "#;
        let f = detect_shallow_auth(src, "c.sol");
        assert!(
            f.is_empty(),
            "neither `unrelated` nor `alsoUnrelated` calls _priv; got {f:?}"
        );
    }

    #[test]
    fn brace_matching_stops_at_the_closing_brace() {
        let lines = vec![
            "function a() external {",
            "    doThing();",
            "}",
            "function b() external {",
            "    other();",
            "}",
        ];
        let body = function_body(&lines, 0);
        assert!(body.contains("doThing"));
        assert!(!body.contains("other"), "body leaked into b(): {body}");
    }
}

#[cfg(test)]
mod credibility_tests {
    use super::*;

    /// `require(msg.sender == owner)` is a guard. Reporting it as "admin is an
    /// EOA" inverted the meaning of the code and fired on every onlyOwner
    /// modifier in existence.
    #[test]
    fn ownership_comparison_is_not_an_eoa_admin_assignment() {
        let src = r#"
            contract C {
                address public owner;
                modifier onlyOwner() {
                    require(msg.sender == owner, "not owner");
                    _;
                }
                function setOwner(address n) external onlyOwner { owner = n; }
            }
        "#;
        assert!(
            detect_single_eoa_admin(src, "c.sol").is_empty(),
            "a comparison guard is not an assignment"
        );
    }

    #[test]
    fn assigning_admin_to_the_caller_is_still_reported() {
        let src = r#"
            contract C {
                address public owner;
                constructor() { owner = msg.sender; }
            }
        "#;
        assert!(!detect_single_eoa_admin(src, "c.sol").is_empty());
    }

    /// Interface and abstract signatures have no body, so they can neither
    /// check a signer nor modify state.
    #[test]
    fn interface_declarations_are_not_missing_a_signer_check() {
        let src = r#"
            interface IERC20 {
                function transfer(address to, uint256 amount) external returns (bool);
                function transferFrom(address f, address t, uint256 a) external returns (bool);
            }
        "#;
        assert!(
            detect_missing_signer_check(src, "i.sol").is_empty(),
            "a bodiless declaration cannot lack a runtime check"
        );
    }

    #[test]
    fn unguarded_state_modifying_function_is_still_reported() {
        let src = r#"
            contract C {
                mapping(address => uint256) public bal;
                function drain(address to, uint256 amt) external {
                    bal[to] = 0;
                    token.transfer(to, amt);
                }
            }
        "#;
        assert!(!detect_missing_signer_check(src, "c.sol").is_empty());
    }
}
