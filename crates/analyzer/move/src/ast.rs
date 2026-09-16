//! A structural model of one Move source file, built on the vendored
//! tree-sitter grammar (Sui Move 2024 plus the Aptos extensions: `acquires`,
//! `inline`, `for` loops, scripts and address blocks).
//!
//! Every detector in this crate reads this model rather than raw text, so a
//! comment, a string literal or an unusual line break can neither raise nor
//! hide a finding. If the grammar cannot produce a clean parse, [`parse`]
//! returns `None` and the caller degrades to the regex fallback explicitly —
//! it never trusts a tree with error nodes.

use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

/// Which Move network's conventions a file follows.
///
/// The two dialects share a language but not an object model: Aptos keeps
/// resources in global storage addressed by account (`borrow_global_mut`,
/// `move_to`, `&signer`), Sui passes objects by reference and distinguishes
/// owned from shared objects (`transfer::share_object`, `TxContext`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Aptos,
    Sui,
    /// Neither framework is referenced (core Move, or a framework-free
    /// module).
    Core,
}

impl Dialect {
    pub fn label(self) -> &'static str {
        match self {
            Dialect::Aptos => "aptos",
            Dialect::Sui => "sui",
            Dialect::Core => "move",
        }
    }
}

/// Function visibility as declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Private,
    Public,
    /// `public(package)` — Sui: callable from the same package only.
    Package,
    /// `public(friend)` — Aptos: callable from declared friend modules only.
    Friend,
    /// `public(script)` — legacy Aptos script visibility.
    Script,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    /// The declared type, verbatim (`&mut Vault<SUI>`).
    pub ty: String,
    pub is_ref: bool,
    pub is_mut_ref: bool,
}

impl Param {
    /// The bare struct or primitive name: `&mut vault::Vault<SUI>` → `Vault`.
    pub fn base_type(&self) -> String {
        base_type_name(&self.ty)
    }
}

/// A function or method call inside a body.
#[derive(Debug, Clone)]
pub struct Call {
    /// Full callee text without type arguments: `coin::extract`, or for
    /// method syntax the receiver plus method: `v.balance.split`.
    pub callee: String,
    /// The last path segment / the method name: `extract`, `split`.
    pub method: String,
    /// Receiver text for method-style calls (`v.balance`), `None` otherwise.
    pub receiver: Option<String>,
    /// Argument texts, verbatim.
    pub args: Vec<String>,
    pub line: usize,
}

impl Call {
    /// The expression the call primarily acts on: the receiver for method
    /// calls, otherwise the first argument.
    pub fn subject(&self) -> Option<&str> {
        self.receiver
            .as_deref()
            .or_else(|| self.args.first().map(String::as_str))
    }
}

#[derive(Debug, Clone)]
pub struct Assign {
    pub lhs: String,
    pub rhs: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct LetBinding {
    pub names: Vec<String>,
    pub rhs: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct MacroCall {
    /// `assert`, `vector::do_ref`, ...
    pub name: String,
    pub args: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct BinOp {
    pub op: String,
    pub lhs: String,
    pub rhs: String,
    /// The left / right operand is itself a division (possibly parenthesised).
    pub lhs_is_div: bool,
    pub rhs_is_div: bool,
    pub line: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Body {
    pub text: String,
    pub calls: Vec<Call>,
    pub assigns: Vec<Assign>,
    pub lets: Vec<LetBinding>,
    pub macros: Vec<MacroCall>,
    pub binops: Vec<BinOp>,
    pub aborts: usize,
    pub has_loop: bool,
    /// `return <expr>` operands plus the block's tail expression.
    pub returns: Vec<String>,
}

impl Body {
    pub fn text_lower(&self) -> String {
        self.text.to_lowercase()
    }

    pub fn asserts(&self) -> impl Iterator<Item = &MacroCall> {
        self.macros.iter().filter(|m| m.name == "assert")
    }

    /// Calls whose method name satisfies `pred`.
    pub fn calls_where<'a>(
        &'a self,
        pred: impl Fn(&str) -> bool + 'a,
    ) -> impl Iterator<Item = &'a Call> + 'a {
        self.calls.iter().filter(move |c| pred(&c.method))
    }
}

#[derive(Debug, Clone)]
pub struct FnDef {
    pub name: String,
    pub line: usize,
    pub visibility: Visibility,
    pub is_entry: bool,
    pub is_native: bool,
    pub is_inline: bool,
    pub is_macro: bool,
    /// Attribute texts: `#[view]`, `#[test]`, `#[randomness]`, ...
    pub attrs: Vec<String>,
    pub type_params: Vec<String>,
    pub params: Vec<Param>,
    pub ret: Option<String>,
    pub acquires: Vec<String>,
    pub body: Option<Body>,
}

impl FnDef {
    pub fn has_attr(&self, name: &str) -> bool {
        self.attrs.iter().any(|a| {
            let inner = a.trim_start_matches("#[").trim_end_matches(']');
            inner
                .split(',')
                .any(|item| item.trim().split(['(', '=']).next().map(str::trim) == Some(name))
        })
    }

    pub fn is_test(&self) -> bool {
        self.has_attr("test") || self.has_attr("test_only")
    }

    /// Callable from outside the module by an arbitrary transaction sender:
    /// an `entry` function or a plain `public` one. `public(package)` and
    /// `public(friend)` are reachable only from trusted code, and test
    /// functions never ship.
    pub fn is_reachable(&self) -> bool {
        !self.is_test()
            && !self.is_macro
            && (self.is_entry || self.visibility == Visibility::Public)
    }

    pub fn param(&self, name: &str) -> Option<&Param> {
        self.params.iter().find(|p| p.name == name)
    }

    pub fn body(&self) -> Option<&Body> {
        self.body.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: String,
    pub line: usize,
    pub abilities: Vec<String>,
    pub fields: Vec<(String, String)>,
    pub type_params: Vec<String>,
    pub attrs: Vec<String>,
}

impl StructDef {
    pub fn has_ability(&self, a: &str) -> bool {
        self.abilities.iter().any(|x| x == a)
    }
}

#[derive(Debug, Clone)]
pub struct ModuleDef {
    pub name: String,
    pub line: usize,
    pub structs: Vec<StructDef>,
    pub functions: Vec<FnDef>,
    pub uses: Vec<String>,
    /// The module's source text, lowercased, for module-wide signal checks.
    pub text_lower: String,
    /// Sui: struct names passed to `transfer::share_object` /
    /// `public_share_object` anywhere in the module. A `&mut` parameter of one
    /// of these types is shared state any transaction can pass in.
    pub shared_types: BTreeSet<String>,
}

impl ModuleDef {
    pub fn struct_def(&self, name: &str) -> Option<&StructDef> {
        self.structs.iter().find(|s| s.name == name)
    }

    pub fn function(&self, name: &str) -> Option<&FnDef> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Whether any function in the module returns a value of struct `name`.
    pub fn is_returned(&self, name: &str) -> bool {
        self.functions.iter().any(|f| {
            f.ret
                .as_deref()
                .map(|r| type_mentions(r, name))
                .unwrap_or(false)
        })
    }
}

#[derive(Debug, Clone)]
pub struct MoveFile {
    pub dialect: Dialect,
    pub modules: Vec<ModuleDef>,
}

impl MoveFile {
    pub fn functions(&self) -> impl Iterator<Item = (&ModuleDef, &FnDef)> {
        self.modules
            .iter()
            .flat_map(|m| m.functions.iter().map(move |f| (m, f)))
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a Move file. Returns `None` when the grammar reports any error node.
pub fn parse(source: &str) -> Option<MoveFile> {
    let mut parser = Parser::new();
    parser
        .set_language(crate::tree_sitter_grammar::language())
        .expect("the vendored grammar must load - this is a static, compiled-in constant");
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }

    let mut modules = Vec::new();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "module_definition" | "address_module_definition" => {
                modules.push(read_module(child, source));
            }
            "module_extension_definition" => {
                if let Some(m) = child.child_by_field_name("module") {
                    modules.push(read_module(m, source));
                }
            }
            "script_definition" => {
                let mut m = read_items(child, source, "script".to_string(), child);
                m.name = "script".to_string();
                modules.push(m);
            }
            "address_block" => {
                let mut c2 = child.walk();
                for inner in child.children(&mut c2) {
                    if inner.kind() == "address_module_definition" {
                        modules.push(read_module(inner, source));
                    }
                }
            }
            _ => {}
        }
    }

    Some(MoveFile {
        dialect: detect_dialect(source),
        modules,
    })
}

/// Framework fingerprinting. Counts idioms rather than trusting a single
/// import so a file that merely mentions the other framework in a comment
/// is not misclassified.
pub fn detect_dialect(source: &str) -> Dialect {
    let sui = [
        "sui::",
        "TxContext",
        "UID",
        "public struct",
        "object::new(",
        "transfer::",
        "share_object",
    ]
    .iter()
    .map(|s| source.matches(s).count())
    .sum::<usize>();
    let aptos = [
        "aptos_framework",
        "aptos_std",
        "acquires",
        "borrow_global",
        "move_to(",
        "&signer",
        "signer::address_of",
        "init_module",
    ]
    .iter()
    .map(|s| source.matches(s).count())
    .sum::<usize>();
    if sui == 0 && aptos == 0 {
        Dialect::Core
    } else if sui > aptos {
        Dialect::Sui
    } else {
        Dialect::Aptos
    }
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

fn read_module(node: Node<'_>, source: &str) -> ModuleDef {
    let name = node
        .child_by_field_name("module_identity")
        .map(|n| text(n, source).to_string())
        .unwrap_or_else(|| "module".to_string());
    let body = node.child_by_field_name("module_body").unwrap_or(node);
    read_items(body, source, name, node)
}

fn read_items(body: Node<'_>, source: &str, name: String, whole: Node<'_>) -> ModuleDef {
    let mut structs = Vec::new();
    let mut functions = Vec::new();
    let mut uses = Vec::new();
    let mut pending_attrs: Vec<String> = Vec::new();

    let mut cursor = body.walk();
    for item in body.children(&mut cursor) {
        match item.kind() {
            "annotation" => pending_attrs.push(text(item, source).to_string()),
            "function_definition" | "native_function_definition" | "macro_function_definition" => {
                functions.push(read_function(
                    item,
                    source,
                    std::mem::take(&mut pending_attrs),
                ));
            }
            "struct_definition" | "native_struct_definition" => {
                structs.push(read_struct(
                    item,
                    source,
                    std::mem::take(&mut pending_attrs),
                ));
            }
            "use_declaration" => {
                uses.push(text(item, source).to_string());
                pending_attrs.clear();
            }
            "line_comment" | "block_comment" | "newline" => {}
            _ => pending_attrs.clear(),
        }
    }

    let mut module = ModuleDef {
        name,
        line: whole.start_position().row + 1,
        structs,
        functions,
        uses,
        text_lower: text(whole, source).to_lowercase(),
        shared_types: BTreeSet::new(),
    };
    module.shared_types = find_shared_types(&module);
    module
}

fn read_struct(node: Node<'_>, source: &str, attrs: Vec<String>) -> StructDef {
    let name = node
        .child_by_field_name("name")
        .map(|n| text(n, source).to_string())
        .unwrap_or_default();
    let mut abilities = Vec::new();
    for field in ["ability_declarations", "postfix_ability_declarations"] {
        if let Some(decls) = node.child_by_field_name(field) {
            let mut c = decls.walk();
            for a in decls.children(&mut c) {
                if a.kind() == "ability" {
                    abilities.push(text(a, source).to_string());
                }
            }
        }
    }
    let mut fields = Vec::new();
    if let Some(sf) = node.child_by_field_name("struct_fields") {
        walk(sf, &mut |n| {
            if n.kind() == "field_annotation" {
                let f = n
                    .child_by_field_name("field")
                    .map(|x| text(x, source).to_string())
                    .unwrap_or_default();
                let t = n
                    .child_by_field_name("type")
                    .map(|x| text(x, source).to_string())
                    .unwrap_or_default();
                fields.push((f, t));
            }
        });
    }
    StructDef {
        name,
        line: node.start_position().row + 1,
        abilities,
        fields,
        type_params: read_type_params(node, source),
        attrs,
    }
}

fn read_type_params(node: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(tp) = node.child_by_field_name("type_parameters") {
        let mut c = tp.walk();
        for p in tp.children(&mut c) {
            if p.kind() == "type_parameter" {
                // `phantom T: key + store` → `T`
                let t = text(p, source);
                let ident = t
                    .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
                    .find(|w| !w.is_empty() && *w != "phantom")
                    .unwrap_or("");
                out.push(ident.to_string());
            }
        }
    }
    out
}

fn read_function(node: Node<'_>, source: &str, attrs: Vec<String>) -> FnDef {
    let is_macro = node.kind() == "macro_function_definition";
    let mut visibility = Visibility::Private;
    let mut is_entry = false;
    let mut is_native = node.kind() == "native_function_definition";
    let mut is_inline = false;
    let mut c = node.walk();
    for child in node.children(&mut c) {
        if child.kind() == "modifier" {
            let m: String = text(child, source).split_whitespace().collect();
            match m.as_str() {
                "public" => visibility = Visibility::Public,
                "public(package)" => visibility = Visibility::Package,
                "public(friend)" => visibility = Visibility::Friend,
                "public(script)" => visibility = Visibility::Script,
                "entry" => is_entry = true,
                "native" => is_native = true,
                "inline" => is_inline = true,
                _ => {}
            }
        }
    }

    let name = node
        .child_by_field_name("name")
        .map(|n| text(n, source).to_string())
        .unwrap_or_default();

    let mut params = Vec::new();
    if let Some(ps) = node.child_by_field_name("parameters") {
        walk(ps, &mut |n| {
            if n.kind() == "function_parameter" {
                let pname = n
                    .child_by_field_name("name")
                    .map(|x| text(x, source).to_string())
                    .unwrap_or_default();
                let ty = n
                    .child_by_field_name("type")
                    .map(|x| {
                        text(x, source)
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                let is_mut_ref = ty.starts_with("&mut");
                let is_ref = ty.starts_with('&');
                params.push(Param {
                    name: pname,
                    ty,
                    is_ref,
                    is_mut_ref,
                });
            }
        });
    }

    let ret = node.child_by_field_name("return_type").map(|r| {
        text(r, source)
            .trim_start_matches(':')
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    });

    let mut acquires = Vec::new();
    if let Some(a) = node.child_by_field_name("acquires") {
        walk(a, &mut |n| {
            if n.kind() == "access_specifier" {
                acquires.push(text(n, source).to_string());
            }
        });
    }

    let body = node
        .child_by_field_name("body")
        .map(|b| read_body(b, source));

    FnDef {
        name,
        line: node.start_position().row + 1,
        visibility,
        is_entry,
        is_native,
        is_inline,
        is_macro,
        attrs,
        type_params: read_type_params(node, source),
        params,
        ret,
        acquires,
        body,
    }
}

fn read_body(block: Node<'_>, source: &str) -> Body {
    let mut body = Body {
        text: text(block, source).to_string(),
        ..Default::default()
    };

    // Method-style calls (`v.balance.split(x)`) are a `dot_expression`
    // whose `access` is a `call_expression`; that inner call must not also be
    // recorded as a free call named `split`.
    let mut method_call_ids: Vec<usize> = Vec::new();

    walk(block, &mut |n| match n.kind() {
        "dot_expression" => {
            let access = n.child_by_field_name("access");
            let expr = n.child_by_field_name("expr");
            if let (Some(call), Some(recv)) = (access, expr) {
                if call.kind() == "call_expression" {
                    method_call_ids.push(call.id());
                    let method = callee_name(call, source);
                    let receiver = text(recv, source).to_string();
                    body.calls.push(Call {
                        callee: format!("{receiver}.{method}"),
                        method: last_segment(&method),
                        receiver: Some(receiver),
                        args: call_args(call, source),
                        line: n.start_position().row + 1,
                    });
                }
            }
        }
        "call_expression" => {
            if method_call_ids.contains(&n.id()) {
                return;
            }
            let callee = callee_name(n, source);
            body.calls.push(Call {
                method: last_segment(&callee),
                callee,
                receiver: None,
                args: call_args(n, source),
                line: n.start_position().row + 1,
            });
        }
        "macro_call_expression" => {
            let name = n
                .child_by_field_name("access")
                .map(|a| text(a, source).trim_end_matches('!').to_string())
                .unwrap_or_default();
            let args = n
                .child_by_field_name("args")
                .map(|a| text(a, source).to_string())
                .unwrap_or_default();
            body.macros.push(MacroCall {
                name,
                args,
                line: n.start_position().row + 1,
            });
        }
        "assign_expression" => {
            let lhs = n
                .child_by_field_name("lhs")
                .map(|x| text(x, source).to_string())
                .unwrap_or_default();
            let rhs = n
                .child_by_field_name("rhs")
                .map(|x| text(x, source).to_string())
                .unwrap_or_default();
            body.assigns.push(Assign {
                lhs,
                rhs,
                line: n.start_position().row + 1,
            });
        }
        "let_statement" => {
            let binds = n
                .child_by_field_name("binds")
                .map(|x| text(x, source))
                .unwrap_or("");
            let names = binds
                .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
                .filter(|w| !w.is_empty() && *w != "mut" && *w != "_")
                .map(str::to_string)
                .collect();
            let rhs = n
                .child_by_field_name("expr")
                .map(|x| text(x, source).to_string())
                .unwrap_or_default();
            body.lets.push(LetBinding {
                names,
                rhs,
                line: n.start_position().row + 1,
            });
        }
        "binary_expression" => {
            let op = n
                .child_by_field_name("operator")
                .map(|x| text(x, source).to_string())
                .unwrap_or_default();
            let lhs_n = n.child_by_field_name("lhs");
            let rhs_n = n.child_by_field_name("rhs");
            body.binops.push(BinOp {
                op,
                lhs: lhs_n
                    .map(|x| text(x, source).to_string())
                    .unwrap_or_default(),
                rhs: rhs_n
                    .map(|x| text(x, source).to_string())
                    .unwrap_or_default(),
                lhs_is_div: lhs_n.map(|x| is_division(x, source)).unwrap_or(false),
                rhs_is_div: rhs_n.map(|x| is_division(x, source)).unwrap_or(false),
                line: n.start_position().row + 1,
            });
        }
        "abort_expression" => body.aborts += 1,
        "while_expression" | "loop_expression" | "for_expression" => body.has_loop = true,
        "return_expression" => {
            if let Some(r) = n.child_by_field_name("return") {
                body.returns.push(text(r, source).to_string());
            }
        }
        _ => {}
    });

    // Tail expression: the last named child of the block that is not a
    // statement item.
    let count = block.named_child_count();
    if count > 0 {
        if let Some(last) = block.named_child(count - 1) {
            if !matches!(
                last.kind(),
                "block_item" | "use_declaration" | "line_comment" | "block_comment" | "newline"
            ) {
                body.returns.push(text(last, source).to_string());
            }
        }
    }

    body
}

/// Whether an operand node is a division, looking through parentheses.
fn is_division(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "binary_expression" => node
            .child_by_field_name("operator")
            .map(|o| text(o, source) == "/")
            .unwrap_or(false),
        "expression_list" => {
            // `(a / b)` — exactly one inner expression.
            node.named_child_count() == 1
                && node
                    .named_child(0)
                    .map(|inner| is_division(inner, source))
                    .unwrap_or(false)
        }
        _ => false,
    }
}

fn callee_name(call: Node<'_>, source: &str) -> String {
    let mut c = call.walk();
    let name = call
        .children(&mut c)
        .find(|n| n.kind() == "name_expression")
        .map(|n| text(n, source).to_string())
        .unwrap_or_default();
    strip_type_args(&name)
}

fn call_args(call: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(args) = call.child_by_field_name("args") {
        let mut c = args.walk();
        for a in args.children(&mut c) {
            if a.is_named() && !matches!(a.kind(), "line_comment" | "block_comment" | "newline") {
                out.push(text(a, source).to_string());
            }
        }
    }
    out
}

/// `borrow_global_mut<Config>` → `borrow_global_mut`; `a::b<T>::c` → `a::b::c`.
pub fn strip_type_args(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0usize;
    for ch in s.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 && !ch.is_whitespace() => out.push(ch),
            _ => {}
        }
    }
    out
}

/// Type arguments of a callee: `borrow_global_mut<Vault<T>>` → `["Vault<T>"]`.
pub fn type_args_of(s: &str) -> Vec<String> {
    let Some(open) = s.find('<') else {
        return Vec::new();
    };
    let inner = &s[open + 1..s.len().saturating_sub(1)];
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for ch in inner.chars() {
        match ch {
            '<' => {
                depth += 1;
                cur.push(ch);
            }
            '>' => {
                depth = depth.saturating_sub(1);
                cur.push(ch);
            }
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

pub fn last_segment(s: &str) -> String {
    s.rsplit("::")
        .next()
        .unwrap_or(s)
        .rsplit('.')
        .next()
        .unwrap_or(s)
        .to_string()
}

/// `&mut vault::Vault<SUI>` → `Vault`.
pub fn base_type_name(ty: &str) -> String {
    let t = ty.trim_start_matches('&').trim();
    let t = t.strip_prefix("mut").map(str::trim).unwrap_or(t);
    let t = strip_type_args(t);
    last_segment(&t)
}

/// Whether a type text names `name` as a type (not merely as a substring of
/// another identifier).
pub fn type_mentions(ty: &str, name: &str) -> bool {
    ty.split(|ch: char| !ch.is_alphanumeric() && ch != '_')
        .any(|w| w == name)
}

/// The identifier an expression is rooted at: `v.balance` → `v`,
/// `&mut v.x` → `v`, `*v` → `v`, `coin::value(&c)` → `coin`.
pub fn root_ident(expr: &str) -> String {
    expr.trim_start_matches(|ch: char| ch == '&' || ch == '*' || ch == '(' || ch.is_whitespace())
        .strip_prefix("mut ")
        .unwrap_or(expr.trim_start_matches(|ch: char| {
            ch == '&' || ch == '*' || ch == '(' || ch.is_whitespace()
        }))
        .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Identifiers appearing in an expression.
pub fn idents(expr: &str) -> Vec<String> {
    expr.split(|ch: char| !ch.is_alphanumeric() && ch != '_')
        .filter(|w| !w.is_empty() && !w.chars().next().unwrap().is_ascii_digit())
        .map(str::to_string)
        .collect()
}

fn walk<'a>(node: Node<'a>, visit: &mut impl FnMut(Node<'a>)) {
    visit(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, visit);
    }
}

/// Sui: struct types the module shares. `transfer::share_object(x)` where
/// `x` is a pack literal, a local bound to one, or a parameter.
fn find_shared_types(module: &ModuleDef) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for f in &module.functions {
        let Some(body) = f.body() else { continue };
        for c in body
            .calls
            .iter()
            .filter(|c| c.method == "share_object" || c.method == "public_share_object")
        {
            let Some(arg) = c.subject() else { continue };
            if let Some(name) = struct_of_expr(arg, f, body) {
                out.insert(name);
            }
        }
    }
    out
}

/// The struct a value expression is an instance of, when it can be told
/// from this function alone.
pub fn struct_of_expr(expr: &str, f: &FnDef, body: &Body) -> Option<String> {
    let e = expr.trim();
    // Pack literal: `Vault<SUI> { ... }` / `Vault { ... }`.
    if e.contains('{') {
        let head = e.split('{').next().unwrap_or("").trim();
        let name = base_type_name(head);
        if !name.is_empty() && name.chars().next().unwrap().is_ascii_uppercase() {
            return Some(name);
        }
    }
    let root = root_ident(e);
    if let Some(p) = f.param(&root) {
        return Some(p.base_type());
    }
    for l in &body.lets {
        if l.names.contains(&root) && l.rhs.contains('{') {
            return struct_of_expr(&l.rhs, f, body);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const APTOS: &str = r#"
module vault_addr::vault {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};

    struct Config has key { admin: address, fee_bps: u64 }

    #[view]
    public fun fee_bps(): u64 acquires Config { borrow_global<Config>(@vault_addr).fee_bps }

    public entry fun set_fee(account: &signer, fee: u64) acquires Config {
        let c = borrow_global_mut<Config>(@vault_addr);
        assert!(signer::address_of(account) == c.admin, 1);
        c.fee_bps = fee;
    }

    public(friend) fun internal(): u64 { 1 }
    inline fun helper(x: u64): u64 { x * 2 }
}
"#;

    const SUI: &str = r#"
module vault::vault;

use sui::balance::{Self, Balance};
use sui::sui::SUI;

public struct AdminCap has key, store { id: UID }
public struct Vault has key { id: UID, balance: Balance<SUI>, fee_bps: u64 }

fun init(ctx: &mut TxContext) {
    transfer::transfer(AdminCap { id: object::new(ctx) }, ctx.sender());
    transfer::share_object(Vault { id: object::new(ctx), balance: balance::zero(), fee_bps: 30 });
}

public fun set_fee(_: &AdminCap, v: &mut Vault, fee: u64) { v.fee_bps = fee; }

public(package) fun take(v: &mut Vault, amount: u64, ctx: &mut TxContext): Coin<SUI> {
    v.balance.split(amount).into_coin(ctx)
}
"#;

    #[test]
    fn parses_aptos_module_with_acquires_view_friend_and_inline() {
        let file = parse(APTOS).expect("aptos module must parse cleanly");
        assert_eq!(file.dialect, Dialect::Aptos);
        let m = &file.modules[0];
        assert_eq!(m.name, "vault_addr::vault");
        let set_fee = m.function("set_fee").unwrap();
        assert!(set_fee.is_entry);
        assert_eq!(set_fee.visibility, Visibility::Public);
        assert_eq!(set_fee.acquires, vec!["Config"]);
        assert!(set_fee.is_reachable());
        let body = set_fee.body().unwrap();
        assert!(body.calls.iter().any(|c| c.callee == "borrow_global_mut"));
        assert_eq!(body.assigns[0].lhs, "c.fee_bps");
        assert_eq!(body.asserts().count(), 1);

        let view = m.function("fee_bps").unwrap();
        assert!(view.has_attr("view"));
        assert_eq!(
            m.function("internal").unwrap().visibility,
            Visibility::Friend
        );
        assert!(!m.function("internal").unwrap().is_reachable());
        assert!(m.function("helper").unwrap().is_inline);
    }

    #[test]
    fn parses_sui_module_and_finds_shared_types() {
        let file = parse(SUI).expect("sui module must parse cleanly");
        assert_eq!(file.dialect, Dialect::Sui);
        let m = &file.modules[0];
        assert!(m.shared_types.contains("Vault"));
        assert!(!m.shared_types.contains("AdminCap"));
        let cap = m.struct_def("AdminCap").unwrap();
        assert!(cap.has_ability("store"));
        let take = m.function("take").unwrap();
        assert_eq!(take.visibility, Visibility::Package);
        assert!(!take.is_reachable());
        let body = take.body().unwrap();
        let split = body.calls.iter().find(|c| c.method == "split").unwrap();
        assert_eq!(split.receiver.as_deref(), Some("v.balance"));
        assert_eq!(split.args, vec!["amount"]);
        let set_fee = m.function("set_fee").unwrap();
        assert_eq!(set_fee.params[0].base_type(), "AdminCap");
    }

    #[test]
    fn broken_source_is_rejected_rather_than_half_read() {
        assert!(parse("module a::b { public fun x( { }").is_none());
    }

    #[test]
    fn helpers() {
        assert_eq!(base_type_name("&mut vault::Vault<SUI>"), "Vault");
        assert_eq!(
            strip_type_args("borrow_global_mut<Vault<T>>"),
            "borrow_global_mut"
        );
        assert_eq!(
            type_args_of("borrow_global_mut<Vault<T>>"),
            vec!["Vault<T>"]
        );
        assert_eq!(root_ident("&mut v.balance"), "v");
        assert_eq!(root_ident("*v"), "v");
        assert!(type_mentions("&mut TreasuryCap<RICH>", "TreasuryCap"));
        assert!(!type_mentions("MyTreasuryCapHolder", "TreasuryCap"));
    }
}
