//! Who may call a function, what shared state it touches, and whether an
//! authorization check stands between the two.
//!
//! This is the one place the Aptos and Sui object models are reconciled:
//!
//! * **Aptos** keeps resources in global storage. `borrow_global_mut<T>(addr)`
//!   at a fixed or caller-supplied address is protocol state; the same call at
//!   `signer::address_of(account)` is the caller's own resource and needs no
//!   further check.
//! * **Sui** passes objects by reference. A `&mut T` parameter whose type the
//!   module shares (`transfer::share_object`) is protocol state any
//!   transaction can pass in; an owned object can only be passed by its owner,
//!   which is the authorization.
//!
//! Every detector that reasons about privilege builds on [`analyze`].

use std::collections::BTreeSet;

use truent_ir::semantic::{AuthCheckKind, AuthorizationCheck, MutationKind};

use crate::ast::{idents, root_ident, Body, Dialect, FnDef, ModuleDef};

/// A state change that only a trusted party should be able to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Privilege {
    /// Value leaves protocol custody, is created, or is destroyed.
    Fund,
    /// Who controls the protocol changes.
    Authority,
    /// Code changes.
    Upgrade,
    /// A resource or object is removed from storage.
    Close,
    /// A protocol parameter changes (fee, limit, pause flag, allowlist...).
    Config,
}

impl Privilege {
    /// The shared-IR kind, for the mutations the cross-chain rule covers.
    pub fn ir_kind(&self) -> Option<MutationKind> {
        match self {
            Privilege::Fund => Some(MutationKind::FundTransfer),
            Privilege::Authority => Some(MutationKind::AuthorityChange),
            Privilege::Upgrade => Some(MutationKind::Upgrade),
            Privilege::Close => Some(MutationKind::AccountClose),
            Privilege::Config => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Privilege::Fund => "moves, mints or burns funds",
            Privilege::Authority => "changes who controls the protocol",
            Privilege::Upgrade => "changes code",
            Privilege::Close => "removes a resource from storage",
            Privilege::Config => "changes a protocol parameter",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Mutation {
    pub privilege: Privilege,
    pub line: usize,
    /// The expression that was written or the call that moved value.
    pub what: String,
}

#[derive(Debug, Clone, Default)]
pub struct Analysis {
    /// Roots (parameter or local names) that denote shared / global protocol
    /// state inside this function.
    pub shared_roots: BTreeSet<String>,
    /// Roots that denote the caller's own resource (Aptos:
    /// `borrow_global_mut<T>(signer::address_of(account))`).
    pub scoped_roots: BTreeSet<String>,
    pub guards: Vec<AuthorizationCheck>,
    pub mutations: Vec<Mutation>,
    /// The body reads the transaction sender's identity anywhere.
    pub has_identity: bool,
}

impl Analysis {
    pub fn is_guarded(&self) -> bool {
        !self.guards.is_empty()
    }

    pub fn worst(&self) -> Option<&Privilege> {
        let rank = |p: &Privilege| match p {
            Privilege::Fund | Privilege::Authority | Privilege::Upgrade => 3,
            Privilege::Close => 2,
            Privilege::Config => 1,
        };
        self.mutations
            .iter()
            .map(|m| &m.privilege)
            .max_by_key(|p| rank(p))
    }
}

pub const IDENTITY_EXPRS: &[&str] = &[
    "signer::address_of(",
    "address_of(",
    "tx_context::sender(",
    ".sender()",
];

const AUTHORITY_FIELDS: &[&str] = &[
    "admin",
    "owner",
    "authority",
    "governor",
    "governance",
    "operator",
    "minter",
    "pauser",
    "manager",
    "controller",
    "treasury",
    "recipient",
    "beneficiary",
    "fee_to",
    "fee_recipient",
    "signer_cap",
    "upgrade_cap",
    "pending_admin",
    "pending_owner",
];

const BALANCE_FIELDS: &[&str] = &[
    "balance",
    "balances",
    "reserve",
    "reserves",
    "reserve_a",
    "reserve_b",
    "reserve_x",
    "reserve_y",
    "supply",
    "total_supply",
    "total",
    "funds",
    "liquidity",
    "pool",
    "vault",
    "deposits",
    "collateral",
    "debt",
    "shares",
    "value",
    "amount",
    "coins",
    "tokens",
    "assets",
    "principal",
    "stake",
    "staked",
];

const CONFIG_COLLECTIONS: &[&str] = &[
    "whitelist",
    "allowlist",
    "blacklist",
    "denylist",
    "roles",
    "admins",
    "operators",
    "oracles",
    "config",
    "params",
    "settings",
    "fees",
    "limits",
    "caps",
    "minters",
    "guardians",
    "keepers",
    "relayers",
    "validators",
];

/// Calls that move value out of, create, or destroy funds held by their
/// subject.
const FUND_OUT_METHODS: &[&str] = &[
    "extract",
    "extract_all",
    "split",
    "take",
    "withdraw",
    "withdraw_with_ref",
    "transfer_with_ref",
    "mint",
    "mint_to",
    "mint_and_transfer",
    "mint_internal",
    "burn",
    "burn_from",
    "burn_internal",
    "decrease_supply",
    "increase_supply",
    "destroy",
    "destroy_zero",
    "into_coin",
    "sweep",
    "drain",
];

const UPGRADE_METHODS: &[&str] = &[
    "authorize_upgrade",
    "commit_upgrade",
    "publish_package_txn",
    "publish_package",
    "upgrade",
    "set_upgrade_policy",
    "freeze_code_object",
];

const AUTH_HELPER_STEMS: &[&str] = &[
    "assert", "ensure", "check", "require", "only", "verify", "validate", "must", "is_", "has_",
];
const AUTH_HELPER_TOPICS: &[&str] = &[
    "admin",
    "owner",
    "auth",
    "role",
    "permission",
    "acl",
    "governance",
    "governor",
    "manager",
    "operator",
    "whitelist",
    "allowlist",
    "access",
    "caller",
    "sender",
    "signer",
    "privilege",
    "guardian",
    "keeper",
];

/// A parameter type that can only be supplied by a trusted holder.
pub fn is_capability_type(base: &str, module: &ModuleDef) -> bool {
    const EXACT: &[&str] = &[
        "ExtendRef",
        "MintRef",
        "BurnRef",
        "TransferRef",
        "MutatorRef",
        "DeleteRef",
        "SignerCapability",
        "TreasuryCap",
        "UpgradeCap",
        "DenyCap",
        "Publisher",
        "ConstructorRef",
    ];
    const SUFFIXES: &[&str] = &[
        "Cap",
        "Capability",
        "Admin",
        "Owner",
        "Auth",
        "Role",
        "Permission",
        "Witness",
        "Ticket",
        "Refs",
    ];
    if EXACT.contains(&base) || SUFFIXES.iter().any(|s| base.ends_with(s)) {
        return true;
    }
    // A marker object: `key` and no payload beyond its id.
    module
        .struct_def(base)
        .map(|s| {
            s.has_ability("key")
                && s.fields
                    .iter()
                    .all(|(name, _)| name == "id" || name == "dummy_field")
        })
        .unwrap_or(false)
}

/// Whether a callee name looks like an authorization helper.
pub fn is_auth_helper(method: &str) -> bool {
    let m = method.to_lowercase();
    if matches!(
        m.as_str(),
        "has_role" | "is_admin" | "is_owner" | "is_authorized" | "assert_admin" | "assert_owner"
    ) {
        return true;
    }
    AUTH_HELPER_STEMS.iter().any(|s| m.starts_with(s))
        && AUTH_HELPER_TOPICS.iter().any(|t| m.contains(t))
}

fn mentions_identity(expr: &str) -> bool {
    IDENTITY_EXPRS.iter().any(|i| expr.contains(i))
}

/// Locals that hold the sender's identity (`let who = ctx.sender();`).
fn identity_aliases(body: &Body) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for _ in 0..2 {
        for l in &body.lets {
            if mentions_identity(&l.rhs) || idents(&l.rhs).iter().any(|i| out.contains(i)) {
                out.extend(l.names.iter().cloned());
            }
        }
    }
    out
}

fn is_identity(expr: &str, aliases: &BTreeSet<String>) -> bool {
    mentions_identity(expr) || idents(expr).iter().any(|i| aliases.contains(i))
}

/// `*b` / `&mut x.f` / `(x.f)` → `x.f`.
fn bare(expr: &str) -> &str {
    expr.trim()
        .trim_start_matches(|c: char| c == '*' || c == '&' || c == '(' || c.is_whitespace())
        .trim_start_matches("mut ")
        .trim_end_matches(')')
        .trim()
}

fn field_of(expr: &str) -> String {
    expr.trim_end()
        .rsplit('.')
        .next()
        .unwrap_or("")
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or("")
        .to_lowercase()
}

fn is_named(field: &str, set: &[&str]) -> bool {
    set.iter()
        .any(|s| field == *s || field.starts_with(&format!("{s}_")))
}

/// Analyze one function.
pub fn analyze(module: &ModuleDef, f: &FnDef, dialect: Dialect) -> Analysis {
    let mut a = Analysis::default();
    let Some(body) = f.body() else {
        return a;
    };
    let aliases = identity_aliases(body);
    a.has_identity = mentions_identity(&body.text);

    // ---- guards from the signature ------------------------------------
    for p in &f.params {
        let base = p.base_type();
        if is_capability_type(&base, module) {
            a.guards.push(AuthorizationCheck {
                kind: AuthCheckKind::RoleOrCapability,
                source: base,
            });
        }
    }

    // ---- shared and scoped roots ---------------------------------------
    for p in &f.params {
        if p.is_mut_ref && module.shared_types.contains(&p.base_type()) {
            a.shared_roots.insert(p.name.clone());
        }
    }
    let global_calls = body
        .calls
        .iter()
        .filter(|c| c.method == "borrow_global_mut" || c.method == "borrow_global");
    for c in global_calls {
        let scoped = c
            .args
            .first()
            .map(|x| is_identity(x, &aliases))
            .unwrap_or(false);
        if c.method == "borrow_global_mut" {
            if scoped {
                a.scoped_roots.insert("borrow_global_mut".to_string());
            } else {
                a.shared_roots.insert("borrow_global_mut".to_string());
            }
        }
        for l in &body.lets {
            if l.rhs.trim_start().starts_with(&c.callee)
                || l.rhs.contains(&format!("{}<", c.method))
            {
                for n in &l.names {
                    if scoped {
                        a.scoped_roots.insert(n.clone());
                    } else if c.method == "borrow_global_mut" {
                        a.shared_roots.insert(n.clone());
                    }
                }
            }
        }
    }
    // Propagate through `let y = &mut x.field` / `borrow_mut(&mut x...)`.
    for _ in 0..2 {
        for l in &body.lets {
            let ids = idents(&l.rhs);
            if is_identity(&l.rhs, &aliases) {
                continue;
            }
            if ids.iter().any(|i| a.shared_roots.contains(i)) {
                for n in &l.names {
                    a.shared_roots.insert(n.clone());
                }
            }
        }
    }
    // Sui: a value taken out of shared state stays "shared" for the purpose
    // of transferring it away.
    for c in body
        .calls
        .iter()
        .filter(|c| FUND_OUT_METHODS.contains(&c.method.as_str()))
    {
        let Some(subject) = c.subject() else { continue };
        if a.shared_roots.contains(&root_ident(subject)) {
            for l in &body.lets {
                if l.rhs.contains(&c.callee) {
                    for n in &l.names {
                        a.shared_roots.insert(n.clone());
                    }
                }
            }
        }
    }

    // ---- guards from the body -----------------------------------------
    let asserts_identity = body.asserts().any(|m| {
        is_identity(&m.args, &aliases)
            || m.args.contains("== @")
            || m.args.contains("==@")
            || AUTHORITY_FIELDS
                .iter()
                .any(|f| m.args.contains(&format!(".{f}")))
    });
    if asserts_identity || (body.aborts > 0 && a.has_identity) {
        a.guards.push(AuthorizationCheck {
            kind: AuthCheckKind::Signer,
            source: "assert!(sender == stored authority)".to_string(),
        });
    }
    for c in &body.calls {
        if is_auth_helper(&c.method) {
            a.guards.push(AuthorizationCheck {
                kind: AuthCheckKind::RoleOrCapability,
                source: c.callee.clone(),
            });
        }
    }
    if a.has_identity && !a.guards.iter().any(|g| g.kind == AuthCheckKind::Signer) {
        // The sender's identity is used as a key or argument somewhere other
        // than an event: the mutation is scoped to the caller's own entry.
        let keyed = body.calls.iter().any(|c| {
            !c.method.contains("emit")
                && !c.method.starts_with("address_of")
                && !c.method.starts_with("sender")
                && c.args.iter().any(|x| is_identity(x, &aliases))
        });
        if keyed {
            a.guards.push(AuthorizationCheck {
                kind: AuthCheckKind::Signer,
                source: "sender-scoped access".to_string(),
            });
        }
    }

    // A function that hands back an ability-less struct of this module is a
    // flash-loan / borrow pattern: the receipt must come back in the same
    // transaction, which is the authorization.
    if let Some(ret) = f.ret.as_deref() {
        if let Some(potato) = module
            .structs
            .iter()
            .find(|s| s.abilities.is_empty() && crate::ast::type_mentions(ret, &s.name))
        {
            a.guards.push(AuthorizationCheck {
                kind: AuthCheckKind::RoleOrCapability,
                source: format!("hot potato {}", potato.name),
            });
        }
    }

    // ---- mutations -----------------------------------------------------
    for asg in &body.assigns {
        let root = root_ident(&asg.lhs);
        let global_direct = asg.lhs.trim_start().starts_with("borrow_global_mut")
            && !is_identity(&asg.lhs, &aliases);
        if !a.shared_roots.contains(&root) && !global_direct {
            continue;
        }
        let field = field_of(&asg.lhs);
        let lhs = bare(&asg.lhs);
        let rhs = bare(&asg.rhs);
        let privilege = if is_named(&field, AUTHORITY_FIELDS) {
            Privilege::Authority
        } else if let Some(tail) = rhs.strip_prefix(lhs) {
            // `x.f = x.f <op> ...`
            let tail = tail.trim_start();
            if tail.starts_with('-') && is_named(&field, BALANCE_FIELDS) {
                Privilege::Fund
            } else if tail.starts_with('+') {
                // Accumulation on protocol state (deposits, counters) is the
                // ordinary path any user may take.
                continue;
            } else {
                Privilege::Config
            }
        } else {
            Privilege::Config
        };
        a.mutations.push(Mutation {
            privilege,
            line: asg.line,
            what: asg.lhs.trim().to_string(),
        });
    }

    for c in &body.calls {
        let Some(subject) = c.subject() else { continue };
        let root = root_ident(subject);
        let on_shared = a.shared_roots.contains(&root)
            || (subject.trim_start().starts_with("borrow_global_mut")
                && !is_identity(subject, &aliases));
        let m = c.method.as_str();
        if FUND_OUT_METHODS.contains(&m) && on_shared {
            // Sui `coin::split(&mut c, ..)` on a caller's own coin is not
            // privileged; the receiver has to be shared state, checked above.
            a.mutations.push(Mutation {
                privilege: Privilege::Fund,
                line: c.line,
                what: c.callee.clone(),
            });
        } else if UPGRADE_METHODS.contains(&m)
            && (on_shared
                || c.args
                    .iter()
                    .any(|x| a.shared_roots.contains(&root_ident(x))))
        {
            a.mutations.push(Mutation {
                privilege: Privilege::Upgrade,
                line: c.line,
                what: c.callee.clone(),
            });
        } else if (m == "transfer" || m == "public_transfer")
            && c.args.len() >= 2
            && a.shared_roots.contains(&root_ident(&c.args[0]))
        {
            // Value that came out of shared state, sent to a caller-chosen
            // address.
            let to = root_ident(&c.args[1]);
            if f.param(&to).is_some() {
                a.mutations.push(Mutation {
                    privilege: Privilege::Fund,
                    line: c.line,
                    what: c.callee.clone(),
                });
            }
        } else if m == "move_from" {
            if let Some(arg) = c.args.first() {
                if !is_identity(arg, &aliases) {
                    a.mutations.push(Mutation {
                        privilege: Privilege::Close,
                        line: c.line,
                        what: c.callee.clone(),
                    });
                }
            }
        } else if m == "delete" && on_shared {
            a.mutations.push(Mutation {
                privilege: Privilege::Close,
                line: c.line,
                what: c.callee.clone(),
            });
        } else if matches!(
            m,
            "add" | "insert" | "upsert" | "remove" | "set" | "update" | "push_back" | "borrow_mut"
        ) && on_shared
            && is_named(&field_of(subject), CONFIG_COLLECTIONS)
        {
            a.mutations.push(Mutation {
                privilege: Privilege::Config,
                line: c.line,
                what: c.callee.clone(),
            });
        }
    }

    // Aptos: `move_to(account, Cap { .. })` for an arbitrary signer is a
    // grant; handled by the capability detector, not here.
    let _ = dialect;

    a
}

/// Whether the module contains any delay mechanism at all.
pub fn module_has_delay(module: &ModuleDef) -> bool {
    [
        "timelock",
        "time_lock",
        "delay",
        "unlock_time",
        "execute_after",
        "pending_",
        "scheduled",
        "cooldown",
        "eta",
        "effective_at",
    ]
    .iter()
    .any(|s| module.text_lower.contains(s))
}

pub fn body_mentions_any(body: &Body, needles: &[&str]) -> bool {
    let t = body.text_lower();
    needles.iter().any(|n| t.contains(n))
}
