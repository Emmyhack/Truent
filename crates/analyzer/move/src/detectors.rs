//! Move detectors for Aptos and Sui, built on the AST model in [`crate::ast`]
//! and the privilege analysis in [`crate::privilege`].
//!
//! Each detector documents the loss class it was written against. Every
//! finding is a *lead*: a pattern traced through real syntax, never a proof.

use truent_core::{Finding, Severity};

use crate::ast::{
    base_type_name, idents, root_ident, struct_of_expr, type_mentions, Dialect, FnDef, ModuleDef,
    MoveFile,
};
use crate::privilege::{analyze, body_mentions_any, module_has_delay, Privilege};

fn finding(
    id: &str,
    severity: Severity,
    file: &str,
    line: usize,
    message: String,
    snippet: String,
    dialect: Dialect,
) -> Finding {
    Finding::new(
        id.to_string(),
        severity,
        file.to_string(),
        line,
        0,
        message,
        snippet,
    )
    .with_metadata("chain".to_string(), "move".to_string())
    .with_metadata("dialect".to_string(), dialect.label().to_string())
}

fn signature(f: &FnDef) -> String {
    let vis = match f.visibility {
        crate::ast::Visibility::Private => "",
        crate::ast::Visibility::Public => "public ",
        crate::ast::Visibility::Package => "public(package) ",
        crate::ast::Visibility::Friend => "public(friend) ",
        crate::ast::Visibility::Script => "public(script) ",
    };
    let entry = if f.is_entry { "entry " } else { "" };
    format!("{vis}{entry}fun {}", f.name)
}

fn name_has(name: &str, needles: &[&str]) -> bool {
    let n = name.to_lowercase();
    needles.iter().any(|x| n.contains(x))
}

// ---------------------------------------------------------------------------
// 1. Access control
// ---------------------------------------------------------------------------

/// A transaction-reachable function changes a protocol parameter held in
/// shared or global state with no authorization check.
///
/// Fund movements, authority changes, upgrades and resource removal are the
/// shared cross-chain rule's territory (`unauthorized_privileged_mutation`);
/// this detector owns the configuration writes — fee, rate, pause flag,
/// oracle address, allowlist — that the shared rule does not model.
pub fn detect_access_control_missing(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (m, f) in file.functions() {
        if !f.is_reachable() {
            continue;
        }
        let a = analyze(m, f, file.dialect);
        if a.is_guarded() {
            continue;
        }
        let Some(cfg) = a
            .mutations
            .iter()
            .find(|x| x.privilege == Privilege::Config)
        else {
            continue;
        };
        out.push(finding(
            "move_access_control_missing",
            Severity::High,
            path,
            f.line,
            format!(
                "`{}` is callable by any transaction and writes `{}` in shared state with no \
                 capability parameter and no sender check",
                f.name, cfg.what
            ),
            signature(f),
            file.dialect,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// 2. Admin without timelock
// ---------------------------------------------------------------------------

const TIME_SENSITIVE: &[&str] = &[
    "upgrade",
    "freeze",
    "pause",
    "set_admin",
    "transfer_admin",
    "set_owner",
    "transfer_owner",
    "set_fee",
    "set_oracle",
    "set_rate",
    "migrate",
    "set_treasury",
    "emergency",
    "set_config",
    "update_config",
];

/// An admin-gated operation that takes effect immediately. A compromised
/// admin key drains the protocol before anyone can react.
pub fn detect_admin_no_timelock(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (m, f) in file.functions() {
        if !f.is_reachable() || !name_has(&f.name, TIME_SENSITIVE) || module_has_delay(m) {
            continue;
        }
        let a = analyze(m, f, file.dialect);
        if !a.is_guarded() || a.mutations.is_empty() {
            continue;
        }
        out.push(finding(
            "move_admin_no_timelock",
            Severity::High,
            path,
            f.line,
            format!(
                "`{}` is admin-gated but takes effect in the same transaction: no timelock or \
                 delay gives users a window to exit if the admin key is compromised",
                f.name
            ),
            signature(f),
            file.dialect,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// 3. Liquidity conservation
// ---------------------------------------------------------------------------

/// A swap moves value on both sides of a pool and never asserts the pool
/// invariant afterwards.
pub fn detect_liquidity_conservation(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (m, f) in file.functions() {
        if f.is_test() || !name_has(&f.name, &["swap", "exchange", "trade"]) {
            continue;
        }
        let Some(body) = f.body() else { continue };
        let a = analyze(m, f, file.dialect);
        let pool_roots: Vec<String> = f
            .params
            .iter()
            .filter(|p| p.is_mut_ref)
            .map(|p| p.name.clone())
            .chain(a.shared_roots.iter().cloned())
            .collect();
        let moves = body
            .calls
            .iter()
            .filter(|c| {
                matches!(
                    c.method.as_str(),
                    "split" | "take" | "extract" | "join" | "merge" | "deposit" | "withdraw"
                ) && c
                    .subject()
                    .map(|s| pool_roots.contains(&root_ident(s)))
                    .unwrap_or(false)
            })
            .count()
            + body
                .assigns
                .iter()
                .filter(|x| pool_roots.contains(&root_ident(&x.lhs)))
                .count();
        if moves < 2 {
            continue;
        }
        let checks_invariant = body.asserts().any(|x| x.args.contains('*'))
            || body.calls.iter().any(|c| {
                name_has(
                    &c.method,
                    &[
                        "invariant",
                        "check_k",
                        "assert_k",
                        "verify_k",
                        "conserv",
                        "assert_lp",
                    ],
                )
            });
        if checks_invariant {
            continue;
        }
        out.push(finding(
            "move_liquidity_conservation",
            Severity::Critical,
            path,
            f.line,
            format!(
                "`{}` moves value on both sides of the pool and never asserts the pool invariant \
                 (x*y >= k or an equivalent) afterwards",
                f.name
            ),
            signature(f),
            file.dialect,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// 4. Spot price from reserves
// ---------------------------------------------------------------------------

const ORACLE_SIGNALS: &[&str] = &[
    "twap",
    "oracle",
    "pyth",
    "switchboard",
    "supra",
    "chainlink",
    "price_feed",
    "cumulative",
    "observation",
    "ema",
];

/// A price is computed as a ratio of two live reserves or balances. A flash
/// loan moves the reserves and the price within one transaction.
pub fn detect_oracle_spot_price(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (m, f) in file.functions() {
        if f.is_test() {
            continue;
        }
        let Some(body) = f.body() else { continue };
        let price_context = name_has(&f.name, &["price", "rate", "quote", "value_of", "spot"])
            || body.lets.iter().any(|l| {
                l.names
                    .iter()
                    .any(|n| name_has(n, &["price", "rate", "quote"]))
            });
        if !price_context {
            continue;
        }
        let reserve_like = |e: &str| {
            let t = e.to_lowercase();
            [
                "reserve",
                "balance",
                "supply",
                "liquidity",
                ".value()",
                "value(&",
            ]
            .iter()
            .any(|s| t.contains(s))
        };
        let Some(div) = body
            .binops
            .iter()
            .find(|b| b.op == "/" && reserve_like(&b.lhs) && reserve_like(&b.rhs))
        else {
            continue;
        };
        if ORACLE_SIGNALS.iter().any(|s| m.text_lower.contains(s)) {
            continue;
        }
        out.push(finding(
            "move_oracle_spot_price",
            Severity::Critical,
            path,
            div.line,
            format!(
                "`{}` derives a price from live reserves (`{} / {}`); a flash loan can move both \
                 in the same transaction",
                f.name,
                div.lhs.trim(),
                div.rhs.trim()
            ),
            format!("{} / {}", div.lhs.trim(), div.rhs.trim()),
            file.dialect,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// 5. Capability handed to the caller
// ---------------------------------------------------------------------------

fn is_cap_struct(name: &str, m: &ModuleDef) -> bool {
    crate::privilege::is_capability_type(name, m) && m.struct_def(name).is_some()
}

/// A reachable, unguarded function creates a capability object and gives it
/// to a caller-chosen address (Sui `transfer::transfer`) or to the calling
/// signer (Aptos `move_to`). Anyone can make themselves admin.
pub fn detect_capability_transferred_to_caller(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (m, f) in file.functions() {
        if !f.is_reachable() || f.name == "init" || f.name == "init_module" {
            continue;
        }
        let Some(body) = f.body() else { continue };
        let a = analyze(m, f, file.dialect);
        if a.is_guarded() {
            continue;
        }
        for c in &body.calls {
            let grants = match c.method.as_str() {
                "transfer" | "public_transfer" => c.args.len() >= 2,
                "move_to" => c.args.len() >= 2,
                _ => false,
            };
            if !grants {
                continue;
            }
            let obj = if c.method == "move_to" {
                &c.args[1]
            } else {
                &c.args[0]
            };
            let Some(name) = struct_of_expr(obj, f, body) else {
                continue;
            };
            if !is_cap_struct(&name, m) {
                continue;
            }
            out.push(finding(
                "move_capability_transferred_to_caller",
                Severity::Critical,
                path,
                c.line,
                format!(
                    "`{}` is callable by anyone and hands out `{}`, a capability this module \
                     treats as authorization",
                    f.name, name
                ),
                c.callee.clone(),
                file.dialect,
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 6. Capability with `store`
// ---------------------------------------------------------------------------

/// A capability struct declares `store`, so it can be wrapped in any object
/// and transferred with `public_transfer` by whoever holds it, outside the
/// module's control.
pub fn detect_capability_with_store(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for m in &file.modules {
        for s in &m.structs {
            if !(s.name.ends_with("Cap") || s.name.ends_with("Capability")) {
                continue;
            }
            if s.has_ability("key") && s.has_ability("store") {
                out.push(finding(
                    "move_capability_with_store",
                    Severity::Low,
                    path,
                    s.line,
                    format!(
                        "`{}` has `key, store`: it can be wrapped in other objects and moved with \
                         `public_transfer` without this module's involvement",
                        s.name
                    ),
                    format!("struct {} has {}", s.name, s.abilities.join(", ")),
                    file.dialect,
                ));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 7. Hot potato with abilities
// ---------------------------------------------------------------------------

/// A receipt returned by a borrow / flash-loan style function can be
/// dropped or stored, so the borrower never has to bring it back.
pub fn detect_hot_potato_has_abilities(file: &MoveFile, path: &str) -> Vec<Finding> {
    const NAMES: &[&str] = &[
        "Receipt",
        "Potato",
        "FlashLoan",
        "Loan",
        "Promise",
        "Ticket",
        "Borrow",
    ];
    let mut out = Vec::new();
    for m in &file.modules {
        for s in &m.structs {
            if !NAMES.iter().any(|n| s.name.ends_with(n)) || s.abilities.is_empty() {
                continue;
            }
            let returned_by = m.functions.iter().find(|f| {
                f.ret
                    .as_deref()
                    .map(|r| type_mentions(r, &s.name))
                    .unwrap_or(false)
                    && name_has(
                        &f.name,
                        &[
                            "flash", "borrow", "loan", "begin", "start", "open", "request",
                        ],
                    )
            });
            let Some(f) = returned_by else { continue };
            out.push(finding(
                "move_hot_potato_has_abilities",
                Severity::High,
                path,
                s.line,
                format!(
                    "`{}` is returned by `{}` as the obligation to repay, but declares `{}`: the \
                     holder can discard or keep it instead of returning it",
                    s.name,
                    f.name,
                    s.abilities.join(", ")
                ),
                format!("struct {} has {}", s.name, s.abilities.join(", ")),
                file.dialect,
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 8. Weak randomness
// ---------------------------------------------------------------------------

const TIME_SOURCES: &[&str] = &[
    "timestamp::now_seconds",
    "timestamp::now_microseconds",
    "clock::timestamp_ms",
    ".timestamp_ms(",
    "epoch_timestamp_ms",
    "tx_context::epoch",
    ".epoch(",
    "get_current_block_height",
    "get_transaction_hash",
    "get_script_hash",
    "fresh_object_address",
    "id_to_bytes",
    "id_bytes",
];

/// Randomness derived from a timestamp, block height, epoch or object id —
/// all readable or influenceable by the caller before the transaction runs.
pub fn detect_weak_randomness(file: &MoveFile, path: &str) -> Vec<Finding> {
    const RANDOM_NAMES: &[&str] = &[
        "rand", "random", "lottery", "roll", "draw", "winner", "seed", "dice", "shuffle", "pick",
        "luck", "raffle", "entropy", "nonce",
    ];
    let mut out = Vec::new();
    for (_, f) in file.functions() {
        if f.is_test() {
            continue;
        }
        let Some(body) = f.body() else { continue };
        let random_context = name_has(&f.name, RANDOM_NAMES)
            || body
                .lets
                .iter()
                .any(|l| l.names.iter().any(|n| name_has(n, RANDOM_NAMES)));
        if !random_context {
            continue;
        }
        let uses_time = TIME_SOURCES.iter().any(|s| body.text.contains(s));
        let mixes = body.binops.iter().any(|b| b.op == "%") || body.text.contains("hash::");
        if !(uses_time && mixes) {
            continue;
        }
        out.push(finding(
            "move_weak_randomness",
            Severity::High,
            path,
            f.line,
            format!(
                "`{}` derives a random value from a timestamp, epoch, block height or object id, \
                 which a caller can read or steer before submitting",
                f.name
            ),
            signature(f),
            file.dialect,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// 9. Randomness in a public function
// ---------------------------------------------------------------------------

/// The on-chain randomness APIs must be consumed from a private `entry`
/// function. A `public` function can be composed with a check-and-abort in
/// the same transaction, letting the caller re-roll until it wins.
pub fn detect_randomness_public_function(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (_, f) in file.functions() {
        if f.is_test() || f.visibility != crate::ast::Visibility::Public {
            continue;
        }
        let Some(body) = f.body() else { continue };
        let uses = body.text.contains("randomness::")
            || body.text.contains("random::new_generator")
            || body.text.contains("new_generator(")
            || f.params.iter().any(|p| p.base_type() == "Random");
        if !uses {
            continue;
        }
        out.push(finding(
            "move_randomness_public_function",
            Severity::High,
            path,
            f.line,
            format!(
                "`{}` consumes on-chain randomness but is `public`: a caller can wrap it in a \
                 transaction that inspects the outcome and aborts on a loss",
                f.name
            ),
            signature(f),
            file.dialect,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// 10. Privileged handle exposed
// ---------------------------------------------------------------------------

/// A public function returns a signer or a capability reference taken from
/// protocol state. Whoever calls it acts as the protocol.
pub fn detect_privileged_handle_exposed(file: &MoveFile, path: &str) -> Vec<Finding> {
    const HANDLES: &[&str] = &[
        "signer",
        "SignerCapability",
        "ExtendRef",
        "MintRef",
        "BurnRef",
        "TransferRef",
        "TreasuryCap",
        "UpgradeCap",
        "DenyCap",
    ];
    let mut out = Vec::new();
    for (m, f) in file.functions() {
        if !f.is_reachable() {
            continue;
        }
        let Some(ret) = f.ret.as_deref() else {
            continue;
        };
        let exposed = HANDLES
            .iter()
            .find(|h| type_mentions(ret, h))
            .map(|s| s.to_string())
            .or_else(|| {
                m.structs
                    .iter()
                    .map(|s| s.name.clone())
                    .find(|n| is_cap_struct(n, m) && type_mentions(ret, n) && ret.contains('&'))
            });
        let Some(handle) = exposed else { continue };
        // Returning the caller's own signer-derived handle is not a leak;
        // returning one that came from stored state is.
        let a = analyze(m, f, file.dialect);
        if a.is_guarded() {
            continue;
        }
        out.push(finding(
            "move_privileged_handle_exposed",
            Severity::Critical,
            path,
            f.line,
            format!(
                "`{}` is callable by anyone and returns `{}`; the caller can act with the \
                 protocol's own authority",
                f.name, handle
            ),
            signature(f),
            file.dialect,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// 11. Divide before multiply
// ---------------------------------------------------------------------------

/// Integer division truncates; multiplying its result magnifies the loss.
pub fn detect_divide_before_multiply(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (_, f) in file.functions() {
        if f.is_test() {
            continue;
        }
        let Some(body) = f.body() else { continue };
        for b in body
            .binops
            .iter()
            .filter(|b| b.op == "*" && (b.lhs_is_div || b.rhs_is_div))
        {
            out.push(finding(
                "move_divide_before_multiply",
                Severity::Medium,
                path,
                b.line,
                format!(
                    "`{}` multiplies the result of an integer division; reorder to multiply first \
                     so truncation is not magnified",
                    f.name
                ),
                format!("{} * {}", b.lhs.trim(), b.rhs.trim()),
                file.dialect,
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 12. Unconstrained type argument
// ---------------------------------------------------------------------------

/// A generic function accepts `Coin<T>` / `Balance<T>` for any `T`, reads
/// its amount, and credits a store that is not keyed by `T`. A worthless
/// token counts the same as the real one.
pub fn detect_unconstrained_type_argument(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (_, f) in file.functions() {
        if !f.is_reachable() || f.type_params.is_empty() {
            continue;
        }
        let Some(body) = f.body() else { continue };
        let type_checked = body.text.contains("type_name::")
            || body.text.contains("type_info::")
            || body.text.contains("type_of<")
            || body.text.contains("with_defining_ids");
        if type_checked {
            continue;
        }
        for tp in &f.type_params {
            let carries_value = f.params.iter().any(|p| {
                type_mentions(&p.ty, tp)
                    && ["Coin", "Balance", "FungibleAsset", "Object"]
                        .iter()
                        .any(|w| type_mentions(&p.ty, w))
            });
            if !carries_value {
                continue;
            }
            let reads_amount = body.calls.iter().any(|c| {
                matches!(
                    c.method.as_str(),
                    "value" | "amount" | "into_balance" | "balance"
                )
            });
            let untyped_store = f.params.iter().find(|p| {
                p.is_mut_ref
                    && !type_mentions(&p.ty, tp)
                    && (body.assigns.iter().any(|x| root_ident(&x.lhs) == p.name)
                        || body.calls.iter().any(|c| {
                            matches!(c.method.as_str(), "join" | "merge" | "add" | "deposit")
                                && c.subject()
                                    .map(|s| root_ident(s) == p.name)
                                    .unwrap_or(false)
                        }))
            });
            let Some(store) = untyped_store else { continue };
            if !reads_amount {
                continue;
            }
            out.push(finding(
                "move_unconstrained_type_argument",
                Severity::Medium,
                path,
                f.line,
                format!(
                    "`{}` accepts any `{}` and credits `{}` (typed `{}`), which is not keyed by \
                     `{}`; nothing stops a worthless token being counted as the real one",
                    f.name, tp, store.name, store.ty, tp
                ),
                signature(f),
                file.dialect,
            ));
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 13. Unbounded vector growth
// ---------------------------------------------------------------------------

/// Anyone can append to a vector held in shared state that the module later
/// walks; enough entries and every transaction over it runs out of gas.
pub fn detect_unbounded_vector_growth(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (m, f) in file.functions() {
        if !f.is_reachable() {
            continue;
        }
        let Some(body) = f.body() else { continue };
        let a = analyze(m, f, file.dialect);
        if a.is_guarded() {
            continue;
        }
        let Some(push) = body.calls.iter().find(|c| {
            c.method == "push_back"
                && c.subject()
                    .map(|s| a.shared_roots.contains(&root_ident(s)))
                    .unwrap_or(false)
        }) else {
            continue;
        };
        let capped = body.asserts().any(|x| {
            ["length", "len(", "size", "count"]
                .iter()
                .any(|s| x.args.contains(s))
        });
        if capped {
            continue;
        }
        let module_iterates = m.text_lower.contains("while (")
            || m.text_lower.contains("for (")
            || m.text_lower.contains("for_each")
            || m.text_lower.contains(".do!(")
            || m.text_lower.contains(".do_ref!(")
            || m.text_lower.contains("loop ");
        if !module_iterates {
            continue;
        }
        out.push(finding(
            "move_unbounded_vector_growth",
            Severity::Medium,
            path,
            push.line,
            format!(
                "`{}` lets any caller append to `{}` in shared state with no size cap, and the \
                 module iterates over it elsewhere",
                f.name,
                push.subject().map(str::trim).unwrap_or("")
            ),
            push.callee.clone(),
            file.dialect,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// 14. Stale oracle price
// ---------------------------------------------------------------------------

/// A price feed is read without checking how old the reading is.
pub fn detect_oracle_stale_price(file: &MoveFile, path: &str) -> Vec<Finding> {
    const UNSAFE_READS: &[&str] = &[
        "get_price_unsafe",
        "pyth::get_price(",
        "get_price_unchecked",
        "latest_value",
        "latest_result",
        "get_ema_price_unsafe",
        "read_price(",
    ];
    const STALENESS: &[&str] = &[
        "no_older_than",
        "staleness",
        "max_age",
        "publish_time",
        "stale",
        "timestamp",
        "age",
        "expir",
    ];
    let mut out = Vec::new();
    for (_, f) in file.functions() {
        if f.is_test() {
            continue;
        }
        let Some(body) = f.body() else { continue };
        let Some(read) = UNSAFE_READS.iter().find(|r| body.text.contains(*r)) else {
            continue;
        };
        if body_mentions_any(body, STALENESS) {
            continue;
        }
        out.push(finding(
            "move_oracle_stale_price",
            Severity::Medium,
            path,
            f.line,
            format!(
                "`{}` reads a price with `{}` and never checks its age; a paused or lagging feed \
                 is used as if current",
                f.name,
                read.trim_end_matches('(')
            ),
            signature(f),
            file.dialect,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// 15. Single-step admin transfer
// ---------------------------------------------------------------------------

/// Admin is reassigned in one call. A typo in the address transfers the
/// protocol to nobody, permanently.
pub fn detect_admin_transfer_single_step(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (m, f) in file.functions() {
        if !f.is_reachable() {
            continue;
        }
        let two_step = [
            "pending", "accept", "claim", "two_step", "proposed", "nominate",
        ]
        .iter()
        .any(|s| m.text_lower.contains(s));
        if two_step {
            continue;
        }
        let a = analyze(m, f, file.dialect);
        if !a.is_guarded() {
            continue;
        }
        let Some(mu) = a.mutations.iter().find(|x| {
            x.privilege == Privilege::Authority
                && ["admin", "owner", "authority", "governor"]
                    .iter()
                    .any(|w| x.what.to_lowercase().ends_with(w))
        }) else {
            continue;
        };
        out.push(finding(
            "move_admin_transfer_single_step",
            Severity::Medium,
            path,
            mu.line,
            format!(
                "`{}` reassigns `{}` in a single step; a wrong address hands the protocol to \
                 nobody with no way back",
                f.name, mu.what
            ),
            mu.what.clone(),
            file.dialect,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// 16. Unbounded parameter
// ---------------------------------------------------------------------------

/// A fee, rate or threshold is written straight from an argument with no
/// upper bound.
pub fn detect_unbounded_parameter(file: &MoveFile, path: &str) -> Vec<Finding> {
    const BOUNDED: &[&str] = &[
        "fee",
        "rate",
        "bps",
        "ratio",
        "percent",
        "pct",
        "threshold",
        "slippage",
        "multiplier",
        "penalty",
        "commission",
        "apr",
        "apy",
        "ltv",
        "haircut",
        "factor",
        "discount",
    ];
    let mut out = Vec::new();
    for (m, f) in file.functions() {
        if !f.is_reachable() {
            continue;
        }
        let Some(body) = f.body() else { continue };
        let a = analyze(m, f, file.dialect);
        if a.mutations.is_empty() {
            continue;
        }
        for asg in &body.assigns {
            if !a.shared_roots.contains(&root_ident(&asg.lhs)) {
                continue;
            }
            let field = asg.lhs.rsplit('.').next().unwrap_or("").to_lowercase();
            if !BOUNDED.iter().any(|b| field.contains(b)) {
                continue;
            }
            let Some(param) = idents(&asg.rhs)
                .into_iter()
                .find(|i| f.param(i).map(|p| !p.is_ref).unwrap_or(false))
            else {
                continue;
            };
            let validated = body.asserts().any(|x| idents(&x.args).contains(&param))
                || body.calls.iter().any(|c| {
                    name_has(
                        &c.method,
                        &["validate", "check", "assert", "ensure", "bounded", "clamp"],
                    ) && c.args.iter().any(|x| idents(x).contains(&param))
                });
            if validated {
                continue;
            }
            out.push(finding(
                "move_unbounded_parameter",
                Severity::Medium,
                path,
                asg.line,
                format!(
                    "`{}` writes `{}` from `{}` with no upper bound; a mistaken or malicious \
                     value takes effect unchecked",
                    f.name,
                    asg.lhs.trim(),
                    param
                ),
                format!("{} = {}", asg.lhs.trim(), asg.rhs.trim()),
                file.dialect,
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Every AST-based detector.
pub fn detect_all(file: &MoveFile, path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(detect_access_control_missing(file, path));
    findings.extend(detect_admin_no_timelock(file, path));
    findings.extend(detect_liquidity_conservation(file, path));
    findings.extend(detect_oracle_spot_price(file, path));
    findings.extend(detect_capability_transferred_to_caller(file, path));
    findings.extend(detect_capability_with_store(file, path));
    findings.extend(detect_hot_potato_has_abilities(file, path));
    findings.extend(detect_weak_randomness(file, path));
    findings.extend(detect_randomness_public_function(file, path));
    findings.extend(detect_privileged_handle_exposed(file, path));
    findings.extend(detect_divide_before_multiply(file, path));
    findings.extend(detect_unconstrained_type_argument(file, path));
    findings.extend(detect_unbounded_vector_growth(file, path));
    findings.extend(detect_oracle_stale_price(file, path));
    findings.extend(detect_admin_transfer_single_step(file, path));
    findings.extend(detect_unbounded_parameter(file, path));
    findings
}

/// Struct name for a parameter type, exposed for tests.
pub fn param_struct(ty: &str) -> String {
    base_type_name(ty)
}
