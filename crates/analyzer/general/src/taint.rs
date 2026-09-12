//! Intraprocedural taint tracking for Python, JavaScript/TypeScript and Go.
//!
//! The pattern detectors in [`crate::code_patterns`] ask a line-local
//! question: is the argument to this dangerous call *dynamic*? That flags
//! `cur.execute(q)` for any variable `q`, whether `q` came from
//! `request.args` or from a constant declared two lines up. A variable is not
//! the same thing as attacker-controlled input, and treating it as one is the
//! largest remaining source of injection false positives — and, because the
//! line-local view cannot see across lines, of misses too.
//!
//! This module answers the dataflow question instead: does a value that
//! originated at a taint *source* (request data, CLI arguments, standard
//! input, a network read) reach a dangerous *sink*, without passing through a
//! *sanitizer*? It tracks assignments within one function, carrying a set of
//! tainted names forward, so
//!
//! ```python
//! q = request.args["id"]      # tainted
//! sql = "SELECT * FROM t WHERE id = " + q   # tainted (references q)
//! cur.execute(sql)            # sink reached by taint  -> finding
//! ```
//!
//! is caught across three lines, while
//!
//! ```python
//! q = "constant"              # not tainted
//! cur.execute(q)              # no finding
//! ```
//!
//! is not flagged at all — the improvement over the line-local detector runs
//! in both directions.
//!
//! # Honest limits
//!
//! It is intraprocedural (the tainted set is cleared at every function
//! boundary — a value returned from another function is not followed) and
//! lexical (no alias analysis, no field sensitivity). A traced flow is strong
//! evidence but remains a *static inference*, so findings are recorded as
//! leads, not as proven. What it adds over pure pattern matching is that the
//! claim is now "input from X reaches sink Y", with both ends named.

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use truent_core::{Finding, Severity};

use crate::text::{code_lines_hash, code_lines_slash};
use crate::{finding, FileKind};

/// A dangerous call that must not receive attacker-controlled input.
struct Sink {
    call: &'static Regex,
    id: &'static str,
    sev: Severity,
    /// Filled into "…reaches {what}".
    what: &'static str,
    /// Only the first top-level argument is the dangerous one (the query or
    /// code string); later arguments are bound parameters and are safe.
    first_only: bool,
    /// A process-execution sink. Its dangerous scope is the whole argument
    /// list only when a shell interprets it (`shell=True`, `shell: true`,
    /// `exec.Command("sh", "-c", …)`); otherwise it is the command position
    /// alone — an argument array cannot start a second command, so
    /// `spawnSync(bin, process.argv.slice(2))` is a CLI wrapper, not an
    /// injection.
    command: bool,
}

lazy_static! {
    // ---- identifiers & assignment ---------------------------------------
    static ref IDENT: Regex = Regex::new(r"[A-Za-z_$][A-Za-z0-9_$]*").unwrap();
    /// `x = …`, `const x = …`, `x := …`, `self.x = …`; not `==`/`<=`/`!=`.
    static ref ASSIGN: Regex = Regex::new(
        // No look-around in Rust's regex: `=` must be followed by a non-`=`
        // character, which rejects `==`/`===` while `<=`/`>=`/`!=` fail on
        // the left-hand side character class.
        r"^\s*(?:(?:export\s+)?(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$.,\s]*?)\s*(?::=|=)([^=].*)$"
    ).unwrap();

    /// The call hands its arguments to a shell.
    static ref SHELL_OPT: Regex = Regex::new(r"shell\s*[:=]\s*[Tt]rue").unwrap();
    /// The command itself is a shell: `("sh", "-c", …)`, `("bash", ["-c", …])`.
    static ref SHELL_EXEC: Regex = Regex::new(
        r#"^\s*["'](/bin/|/usr/bin/)?(sh|bash|zsh|dash|ksh|cmd(\.exe)?|powershell(\.exe)?)["']\s*,"#
    ).unwrap();

    // ---- Python ---------------------------------------------------------
    static ref PY_DECL: Regex = Regex::new(r"^\s*(async\s+)?def\s").unwrap();
    static ref PY_SRC: Regex = Regex::new(
        r"\brequest\.(args|form|values|json|data|files|cookies|headers|get_json)\b|\bflask\.request\b|\bself\.request\b|\brequest\.GET\b|\brequest\.POST\b|\bsys\.argv\b|\binput\s*\(|\bsys\.stdin\b"
    ).unwrap();
    static ref PY_SAN: Regex = Regex::new(
        r"\bint\s*\(|\bfloat\s*\(|\bbool\s*\(|shlex\.quote|\bre\.escape|html\.escape|markupsafe|bleach\.|\bescape\s*\(|\buuid\.|\.isdigit\s*\(|\.isalnum\s*\(|is_safe_url|url_has_allowed_host_and_scheme|safe_redirect|url_for\s*\("
    ).unwrap();
    static ref PY_SQL: Regex = Regex::new(r"\.(execute|executemany|executescript|raw|extra)\s*\(").unwrap();
    static ref PY_CMD: Regex = Regex::new(r"\b(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output|check_call))\s*\(").unwrap();
    static ref PY_EVAL: Regex = Regex::new(r"\b(eval|exec)\s*\(").unwrap();
    static ref PY_REDIRECT: Regex = Regex::new(r"\b(redirect|HttpResponseRedirect|RedirectResponse)\s*\(").unwrap();
    static ref PY_LOG: Regex = Regex::new(r"\b(logger?|logging|log|app\.logger|current_app\.logger)\.(info|debug|warning|warn|error|critical|exception)\s*\(").unwrap();

    // ---- JavaScript / TypeScript ----------------------------------------
    static ref JS_DECL: Regex = Regex::new(
        r"^\s*(async\s+)?(function\b|(export\s+)?(async\s+)?(function|const|let|var)\s+\w+\s*=\s*(async\s*)?(function|\()|[A-Za-z_$][\w$]*\s*\([^)]*\)\s*(=>|\{)|[A-Za-z_$][\w$]*\s*:\s*(async\s*)?(function|\())"
    ).unwrap();
    static ref JS_SRC: Regex = Regex::new(
        r"\breq(uest)?\.(query|body|params|headers|cookies|url|originalUrl)\b|\bprocess\.argv\b|\blocation\.(search|hash|href|pathname)\b|\bwindow\.name\b|\bdocument\.(URL|documentURI|cookie|referrer)\b|\.on\s*\(\s*['\x22]data['\x22]"
    ).unwrap();
    static ref JS_SAN: Regex = Regex::new(
        r"\bparseInt\s*\(|\bparseFloat\s*\(|\bNumber\s*\(|encodeURIComponent\s*\(|\bescape\s*\(|validator\.|\.escape\s*\(|mysql\.escape|pool\.escape|DOMPurify\.sanitize|isSafeUrl|safeRedirect|startsWith\s*\(\s*['\x22]/['\x22]|ALLOWED_REDIRECTS|allowedRedirects"
    ).unwrap();
    static ref JS_SQL: Regex = Regex::new(r"\.(query|execute|raw)\s*\(").unwrap();
    static ref JS_CMD: Regex = Regex::new(r"\b(exec|execSync|spawn|spawnSync)\s*\(").unwrap();
    static ref JS_EVAL: Regex = Regex::new(r"\beval\s*\(|new\s+Function\s*\(").unwrap();
    static ref JS_XSS: Regex = Regex::new(r"\.(innerHTML|outerHTML)\s*=|document\.write(ln)?\s*\(").unwrap();
    static ref JS_REDIRECT: Regex = Regex::new(r"\bres\.redirect\s*\(|\blocation\.(href|assign|replace)\s*[=(]|window\.location\s*=").unwrap();
    static ref JS_LOG: Regex = Regex::new(r"\b(console|logger?|log|winston|pino)\.(log|info|debug|warn|error|trace)\s*\(").unwrap();

    // ---- Go -------------------------------------------------------------
    static ref GO_DECL: Regex = Regex::new(r"^\s*func\s").unwrap();
    static ref GO_SRC: Regex = Regex::new(
        r"\br\.(URL\.Query|FormValue|PostFormValue|Form|Header\.Get|Cookie)\b|\bos\.Args\b|\bmux\.Vars\s*\(|\bio(util)?\.ReadAll\s*\(|\br\.Body\b"
    ).unwrap();
    static ref GO_SAN: Regex = Regex::new(
        r"strconv\.(Atoi|ParseInt|ParseFloat|ParseBool)|template\.HTMLEscape|template\.JSEscape|url\.QueryEscape|url\.PathEscape|isSafeRedirect|allowedHosts"
    ).unwrap();
    static ref GO_SQL: Regex = Regex::new(r"\.(Query|QueryRow|QueryContext|Exec|ExecContext)\s*\(").unwrap();
    static ref GO_CMD: Regex = Regex::new(r"\bexec\.Command(Context)?\s*\(").unwrap();
    static ref GO_REDIRECT: Regex = Regex::new(r"\bhttp\.Redirect\s*\(|\.Redirect\s*\(\s*\d{3}\s*,").unwrap();
    static ref GO_LOG: Regex = Regex::new(r"\blog\.(Printf|Println|Print|Info|Infof|Debug|Debugf|Warn|Warnf|Error|Errorf)\s*\(").unwrap();
}

/// Run taint tracking over one file. Returns findings where a source value
/// reaches a sink.
pub fn detect(source: &str, file_path: &str, kind: FileKind) -> Vec<Finding> {
    let (lines, decl, src, san, sinks): (Vec<String>, &Regex, &Regex, &Regex, Vec<Sink>) =
        match kind {
            FileKind::Python => (
                code_lines_hash(source),
                &PY_DECL,
                &PY_SRC,
                &PY_SAN,
                vec![
                    Sink {
                        call: &PY_SQL,
                        id: "gen_sql_injection",
                        sev: Severity::High,
                        what: "a SQL query",
                        first_only: true,
                        command: false,
                    },
                    Sink {
                        call: &PY_CMD,
                        id: "gen_command_injection",
                        sev: Severity::High,
                        what: "a shell command",
                        first_only: true,
                        command: true,
                    },
                    Sink {
                        call: &PY_EVAL,
                        id: "gen_code_injection",
                        sev: Severity::Critical,
                        what: "the interpreter (eval/exec)",
                        first_only: true,
                        command: false,
                    },
                    Sink {
                        call: &PY_REDIRECT,
                        id: "gen_open_redirect",
                        sev: Severity::Medium,
                        what: "a redirect target",
                        first_only: true,
                        command: false,
                    },
                    Sink {
                        call: &PY_LOG,
                        id: "gen_log_injection",
                        sev: Severity::Low,
                        what: "a log message",
                        first_only: true,
                        command: false,
                    },
                ],
            ),
            FileKind::JavaScript => (
                code_lines_slash(source),
                &JS_DECL,
                &JS_SRC,
                &JS_SAN,
                vec![
                    Sink {
                        call: &JS_SQL,
                        id: "gen_sql_injection",
                        sev: Severity::High,
                        what: "a SQL query",
                        first_only: true,
                        command: false,
                    },
                    Sink {
                        call: &JS_CMD,
                        id: "gen_command_injection",
                        sev: Severity::High,
                        what: "a shell command",
                        first_only: true,
                        command: true,
                    },
                    Sink {
                        call: &JS_EVAL,
                        id: "gen_code_injection",
                        sev: Severity::Critical,
                        what: "the interpreter (eval/Function)",
                        first_only: true,
                        command: false,
                    },
                    Sink {
                        call: &JS_XSS,
                        id: "gen_xss_sink",
                        sev: Severity::High,
                        what: "the DOM as HTML",
                        first_only: false,
                        command: false,
                    },
                    Sink {
                        call: &JS_REDIRECT,
                        id: "gen_open_redirect",
                        sev: Severity::Medium,
                        what: "a redirect target",
                        first_only: true,
                        command: false,
                    },
                    Sink {
                        call: &JS_LOG,
                        id: "gen_log_injection",
                        sev: Severity::Low,
                        what: "a log message",
                        first_only: true,
                        command: false,
                    },
                ],
            ),
            FileKind::Go => (
                code_lines_slash(source),
                &GO_DECL,
                &GO_SRC,
                &GO_SAN,
                vec![
                    Sink {
                        call: &GO_SQL,
                        id: "gen_sql_injection",
                        sev: Severity::High,
                        what: "a SQL query",
                        first_only: true,
                        command: false,
                    },
                    Sink {
                        call: &GO_CMD,
                        id: "gen_command_injection",
                        sev: Severity::High,
                        what: "a shell command",
                        first_only: true,
                        command: true,
                    },
                    Sink {
                        call: &GO_REDIRECT,
                        id: "gen_open_redirect",
                        sev: Severity::Medium,
                        what: "a redirect target",
                        first_only: false,
                        command: false,
                    },
                    Sink {
                        call: &GO_LOG,
                        id: "gen_log_injection",
                        sev: Severity::Low,
                        what: "a log message",
                        first_only: true,
                        command: false,
                    },
                ],
            ),
            _ => return Vec::new(),
        };

    let mut tainted: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        // A function boundary resets the scope: taint does not cross calls.
        if decl.is_match(line) {
            tainted.clear();
        }

        // 1. A sink on this line, reached by a tainted value or a source used
        //    inline, is a finding — checked before the assignment on the same
        //    line so `x = sink(request.args[...])` still reports the sink.
        for s in &sinks {
            if let Some(m) = s.call.find(line) {
                let rest = &line[m.end()..];
                let args = dangerous_args(s, rest);
                let via_source = src.is_match(args) && !san.is_match(args);
                let via_var = references_tainted(args, &tainted) && !san.is_match(args);
                if via_source || via_var {
                    let origin = if via_source {
                        "external input".to_string()
                    } else {
                        format!("tainted value `{}`", first_tainted(args, &tainted))
                    };
                    out.push(finding(
                        s.id,
                        s.sev,
                        file_path,
                        idx,
                        format!(
                            "{origin} reaches {}: a value derived from untrusted input is used \
                             without a sanitizer, so an attacker who controls that input controls the sink",
                            s.what
                        ),
                        line,
                    ));
                }
            }
        }

        // 2. Assignment: update the tainted set.
        if let Some(c) = ASSIGN.captures(line) {
            let rhs = c.get(2).map(|m| m.as_str()).unwrap_or("");
            let sanitized = san.is_match(rhs);
            let becomes_tainted =
                !sanitized && (src.is_match(rhs) || references_tainted(rhs, &tainted));
            for name in lhs_names(c.get(1).map(|m| m.as_str()).unwrap_or("")) {
                if becomes_tainted {
                    tainted.insert(name);
                } else {
                    // Reassignment from a clean/constant value clears taint.
                    tainted.remove(&name);
                }
            }
        }
    }

    out
}

/// The part of a call's argument list that the sink actually interprets.
fn dangerous_args<'a>(s: &Sink, rest: &'a str) -> &'a str {
    if s.command {
        if SHELL_OPT.is_match(rest) || SHELL_EXEC.is_match(rest) {
            return rest;
        }
        let first = first_arg(rest);
        // A list/array literal: the command is its first element; the rest
        // are arguments, which cannot start a command without a shell.
        if let Some(inner) = first.trim_start().strip_prefix('[') {
            return first_arg(inner);
        }
        return first;
    }
    if s.first_only {
        first_arg(rest)
    } else {
        rest
    }
}

/// The first top-level argument of a call: up to the first comma that is not
/// nested in parentheses, brackets, braces or a string literal.
fn first_arg(rest: &str) -> &str {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in rest.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    return &rest[..i];
                }
                depth -= 1;
            }
            ',' if depth == 0 => return &rest[..i],
            _ => {}
        }
    }
    rest
}

/// Left-hand-side names of an assignment, handling tuple unpacking
/// (`a, b = …`) and dropping the object of `self.x`/`obj.attr` to `x`.
fn lhs_names(lhs: &str) -> Vec<String> {
    lhs.split(',')
        .filter_map(|p| {
            let p = p
                .trim()
                .trim_end_matches(|c: char| c == ':' || c.is_whitespace());
            // Keep the last dotted segment: `self.x` -> `x` is what a later
            // reference to `self.x` will also reduce to via IDENT matching.
            p.rsplit('.').next().map(str::to_string)
        })
        .filter(|s| {
            !s.is_empty()
                && s.chars()
                    .next()
                    .map(|c| c.is_alphabetic() || c == '_')
                    .unwrap_or(false)
        })
        .collect()
}

/// Whether `text` references any tainted identifier as a whole word.
fn references_tainted(text: &str, tainted: &HashSet<String>) -> bool {
    !tainted.is_empty() && IDENT.find_iter(text).any(|m| tainted.contains(m.as_str()))
}

/// The first tainted identifier referenced in `text` (for the message).
fn first_tainted(text: &str, tainted: &HashSet<String>) -> String {
    IDENT
        .find_iter(text)
        .map(|m| m.as_str())
        .find(|w| tainted.contains(*w))
        .unwrap_or("input")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.invariant_id.as_str()).collect()
    }

    #[test]
    fn python_multiline_sql_flow_is_caught() {
        let src = "\
def handler():
    q = request.args['id']
    sql = \"SELECT * FROM users WHERE id = \" + q
    cur.execute(sql)
";
        let f = detect(src, "app.py", FileKind::Python);
        assert!(ids(&f).contains(&"gen_sql_injection"), "{:?}", ids(&f));
        assert!(
            f[0].line == 4,
            "must point at the execute() line, got {}",
            f[0].line
        );
    }

    #[test]
    fn python_constant_variable_is_not_flagged() {
        // The exact false positive the line-local detector produces: a
        // variable argument whose value is a constant.
        let src = "\
def handler():
    q = \"SELECT 1\"
    cur.execute(q)
";
        assert!(detect(src, "app.py", FileKind::Python).is_empty());
    }

    #[test]
    fn python_sanitized_input_is_not_flagged() {
        let src = "\
def handler():
    q = int(request.args['id'])
    cur.execute(\"SELECT * FROM t WHERE id = %d\" % q)
";
        assert!(
            detect(src, "app.py", FileKind::Python).is_empty(),
            "int() sanitizes the value"
        );
    }

    #[test]
    fn taint_does_not_cross_function_boundaries() {
        let src = "\
def a():
    q = request.args['id']

def b():
    cur.execute(q)
";
        // `q` in b() is a different scope; without interprocedural analysis we
        // must not claim a flow we cannot see.
        assert!(detect(src, "app.py", FileKind::Python).is_empty());
    }

    #[test]
    fn reassignment_to_constant_clears_taint() {
        let src = "\
def h():
    q = request.args['id']
    q = \"safe\"
    cur.execute(q)
";
        assert!(detect(src, "app.py", FileKind::Python).is_empty());
    }

    #[test]
    fn python_inline_source_at_sink() {
        let src = "def h():\n    os.system(\"ping \" + request.args['host'])\n";
        assert!(ids(&detect(src, "app.py", FileKind::Python)).contains(&"gen_command_injection"));
    }

    #[test]
    fn js_request_body_to_query() {
        let src = "\
function handler(req, res) {
  const name = req.body.name;
  const sql = `SELECT * FROM u WHERE n = '${name}'`;
  db.query(sql);
}
";
        assert!(ids(&detect(src, "h.js", FileKind::JavaScript)).contains(&"gen_sql_injection"));
    }

    #[test]
    fn js_innerhtml_xss_flow() {
        let src = "\
function show(req) {
  let msg = req.query.msg;
  el.innerHTML = msg;
}
";
        assert!(ids(&detect(src, "h.js", FileKind::JavaScript)).contains(&"gen_xss_sink"));
    }

    #[test]
    fn js_parseint_sanitizes() {
        let src = "\
function h(req) {
  const id = parseInt(req.query.id, 10);
  db.query('SELECT * FROM t WHERE id = ' + id);
}
";
        assert!(detect(src, "h.js", FileKind::JavaScript).is_empty());
    }

    #[test]
    fn go_form_value_to_shell_exec() {
        let src = "\
func handler(w http.ResponseWriter, r *http.Request) {
    host := r.FormValue(\"host\")
    exec.Command(\"sh\", \"-c\", \"ping -c 1 \"+host)
}
";
        assert!(ids(&detect(src, "h.go", FileKind::Go)).contains(&"gen_command_injection"));
    }

    #[test]
    fn argument_arrays_without_a_shell_are_not_command_injection() {
        // The exact false positive found on Truent's own npm wrapper: argv
        // forwarded as an argument array. No shell, no second command.
        let js = "\
function main() {
  const args = process.argv.slice(2);
  spawnSync(binaryPath, args, { stdio: 'inherit' });
}
";
        assert!(detect(js, "cli.js", FileKind::JavaScript).is_empty());
        let go = "\
func h(w http.ResponseWriter, r *http.Request) {
    host := r.FormValue(\"host\")
    exec.Command(\"ping\", \"-c\", \"1\", host).Run()
}
";
        assert!(
            detect(go, "h.go", FileKind::Go).is_empty(),
            "argument, not command"
        );
        let py = "\
def h():
    host = request.args['host']
    subprocess.run([\"ping\", \"-c\", \"1\", host])
";
        assert!(detect(py, "h.py", FileKind::Python).is_empty());
    }

    #[test]
    fn shell_forms_are_command_injection() {
        let js = "\
function h(req) {
  const d = req.query.dir;
  execSync('ls ' + d);
  spawn('sh', ['-c', 'ls ' + d]);
}
";
        let f = detect(js, "h.js", FileKind::JavaScript);
        assert_eq!(
            f.iter()
                .filter(|f| f.invariant_id == "gen_command_injection")
                .count(),
            2
        );
        let py = "\
def h():
    host = request.args['host']
    subprocess.run(\"ping \" + host, shell=True)
    os.system(\"ping \" + host)
";
        let f = detect(py, "h.py", FileKind::Python);
        assert_eq!(
            f.iter()
                .filter(|f| f.invariant_id == "gen_command_injection")
                .count(),
            2
        );
    }

    #[test]
    fn go_strconv_sanitizes() {
        let src = "\
func handler(w http.ResponseWriter, r *http.Request) {
    id, _ := strconv.Atoi(r.FormValue(\"id\"))
    db.Query(\"SELECT * FROM t WHERE id = $1\", id)
}
";
        assert!(detect(src, "h.go", FileKind::Go).is_empty());
    }

    #[test]
    fn parameterized_query_with_bound_tainted_value_is_clean() {
        // The correct pattern: a literal query, the tainted value passed as a
        // bound parameter. Only the query argument is inspected.
        let src = "\
def h():
    uid = request.args['id']
    cur.execute(\"SELECT * FROM t WHERE id = %s\", (uid,))
";
        assert!(detect(src, "app.py", FileKind::Python).is_empty());
        let js = "\
function h(req) {
  const uid = req.params.id;
  db.query('SELECT * FROM t WHERE id = ?', [uid]);
}
";
        assert!(detect(js, "h.js", FileKind::JavaScript).is_empty());
    }

    #[test]
    fn open_redirect_and_log_injection_flows() {
        let py = "def go():\n    nxt = request.args.get('next')\n    return redirect(nxt)\n";
        assert!(ids(&detect(py, "v.py", FileKind::Python)).contains(&"gen_open_redirect"));
        let guarded = "def go():\n    nxt = safe_redirect(request.args.get('next'))\n    return redirect(nxt)\n";
        assert!(detect(guarded, "v.py", FileKind::Python).is_empty());
        let js =
            "app.get('/r', (req, res) => {\n  const to = req.query.to;\n  res.redirect(to);\n});\n";
        assert!(ids(&detect(js, "r.js", FileKind::JavaScript)).contains(&"gen_open_redirect"));
        let log = "app.post('/x', (req, res) => {\n  const name = req.body.name;\n  logger.info('user ' + name + ' logged in');\n});\n";
        assert!(ids(&detect(log, "r.js", FileKind::JavaScript)).contains(&"gen_log_injection"));
        // Structured logging passes the value as a separate argument, not
        // into the message string: not injectable.
        let structured = "app.post('/x', (req, res) => {\n  const name = req.body.name;\n  logger.info('login', { name });\n});\n";
        assert!(
            !ids(&detect(structured, "r.js", FileKind::JavaScript)).contains(&"gen_log_injection")
        );
    }

    #[test]
    fn first_arg_respects_nesting_and_strings() {
        assert_eq!(first_arg("a, b)"), "a");
        assert_eq!(first_arg("f(a, b), c)"), "f(a, b)");
        assert_eq!(first_arg("\"x, y\", z)"), "\"x, y\"");
        assert_eq!(first_arg("sql)"), "sql");
    }
}
