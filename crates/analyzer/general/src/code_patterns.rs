//! Dangerous code patterns in Python, JavaScript/TypeScript, Go and shell.
//!
//! Every detector here requires a *dynamic* argument: a literal string, a
//! constant, or a bare call with no attacker-influenced input is never a
//! finding. Dynamic means an f-string / template literal, string formatting or
//! concatenation, or a variable — the shapes through which user input reaches
//! a sink.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use crate::text::{code_lines_hash, code_lines_slash};
use crate::{finding, FileKind};

lazy_static! {
    // ---- shared "is this argument dynamic?" -----------------------------
    /// The first argument to a call is a plain string literal.
    static ref LITERAL_ARG: Regex = Regex::new(r#"^\s*(r|b|u)?["'`][^"'`]*["'`]\s*[,)]"#).unwrap();

    // ---- Python ---------------------------------------------------------
    static ref PY_EVAL: Regex = Regex::new(r"\b(eval|exec)\s*\(").unwrap();
    static ref PY_SUBPROCESS_SHELL: Regex = Regex::new(r"\b(subprocess\.(call|run|Popen|check_output|check_call)|os\.system|os\.popen|commands\.getoutput)\s*\(").unwrap();
    static ref PY_SHELL_TRUE: Regex = Regex::new(r"shell\s*=\s*True").unwrap();
    static ref PY_PICKLE: Regex = Regex::new(r"\b(pickle|cPickle|dill|shelve)\.load(s)?\s*\(|\bmarshal\.loads?\s*\(").unwrap();
    static ref PY_YAML_LOAD: Regex = Regex::new(r"\byaml\.load\s*\(").unwrap();
    static ref PY_YAML_SAFE: Regex = Regex::new(r"Loader\s*=\s*(yaml\.)?(SafeLoader|CSafeLoader|BaseLoader)|yaml\.safe_load").unwrap();
    static ref PY_VERIFY_FALSE: Regex = Regex::new(r"\bverify\s*=\s*False\b").unwrap();
    static ref PY_SQL_EXEC: Regex = Regex::new(r"\.(execute|executemany|raw|extra)\s*\(").unwrap();
    static ref PY_WEAK_HASH: Regex = Regex::new(r"\bhashlib\.(md5|sha1)\s*\(").unwrap();
    static ref PY_RANDOM: Regex = Regex::new(r"\brandom\.(random|randint|choice|randrange|getrandbits)\s*\(").unwrap();

    // ---- JavaScript / TypeScript ----------------------------------------
    static ref JS_EVAL: Regex = Regex::new(r"\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[^,)]*\+|setInterval\s*\(\s*[^,)]*\+").unwrap();
    static ref JS_EXEC: Regex = Regex::new(r"\b(exec|execSync|spawn|spawnSync)\s*\(").unwrap();
    static ref JS_INNER_HTML: Regex = Regex::new(r"\.(innerHTML|outerHTML)\s*=|dangerouslySetInnerHTML\s*=\s*\{|document\.write(ln)?\s*\(").unwrap();
    static ref JS_TLS_OFF: Regex = Regex::new(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\x22]?0").unwrap();
    static ref JS_SQL: Regex = Regex::new(r"\.(query|execute|raw)\s*\(").unwrap();
    static ref JS_RANDOM: Regex = Regex::new(r"\bMath\.random\s*\(").unwrap();

    // ---- Go -------------------------------------------------------------
    static ref GO_EXEC: Regex = Regex::new(r"\bexec\.Command(Context)?\s*\(").unwrap();
    static ref GO_TLS_OFF: Regex = Regex::new(r"InsecureSkipVerify\s*:\s*true").unwrap();
    static ref GO_SQL: Regex = Regex::new(r"\.(Query|QueryRow|Exec|Prepare)(Context)?\s*\(").unwrap();
    static ref GO_MATH_RAND: Regex = Regex::new(r"\brand\.(Int|Intn|Int63|Int31|Float64|Read|Perm)\s*\(").unwrap();
    static ref GO_MATH_RAND_IMPORT: Regex = Regex::new(r#""math/rand""#).unwrap();

    // ---- Shell ----------------------------------------------------------
    static ref SH_EVAL: Regex = Regex::new(r#"\beval\s+["']?\$"#).unwrap();
    static ref SH_PIPE: Regex = Regex::new(r"(?i)\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b").unwrap();

    // ---- dynamic-ness -----------------------------------------------------
    /// Formatting/concatenation or interpolation inside the argument list.
    static ref DYNAMIC: Regex = Regex::new(r#"(\bf["']|\.format\s*\(|%\s*[\(\w]|\+\s*[A-Za-z_(]|`[^`]*\$\{|\$\{|\bSprintf\s*\(|\+\s*\w+\s*\+|\bstr\s*\()"#).unwrap();
    /// A function header or assignment that names the surrounding scope.
    static ref DECL_LINE: Regex = Regex::new(r"^\s*(async\s+)?(function\b|def\b|func\b|(export\s+)?(const|let|var)\s+\w+\s*=|\w+\s*\([^)]*\)\s*(=>|\{)|\w+\s*:\s*(async\s*)?(function|\())").unwrap();

    /// Anything that looks like an authentication material name.
    static ref SECRET_CONTEXT: Regex = Regex::new(r"(?i)token|secret|password|passwd|otp|nonce|session|salt|api[_-]?key|csrf|reset").unwrap();
}

/// Text after the first `(` of the match, up to end of line.
fn args_after<'a>(line: &'a str, m: &regex::Match) -> &'a str {
    let start = line[m.start()..]
        .find('(')
        .map(|p| m.start() + p + 1)
        .unwrap_or(m.end());
    &line[start..]
}

/// A call argument that is dynamic: not a bare literal, and either formatted,
/// concatenated, interpolated, or a variable.
fn is_dynamic(args: &str) -> bool {
    // A template literal with `${…}` is interpolation, however literal its
    // delimiters look.
    if args.contains("${") {
        return true;
    }
    if LITERAL_ARG.is_match(args) {
        return false;
    }
    let first = args.trim_start();
    if first.is_empty() || first.starts_with(')') {
        return false;
    }
    DYNAMIC.is_match(args)
        || first
            .chars()
            .next()
            .map(|c| c.is_alphabetic() || c == '_')
            .unwrap_or(false)
}

pub fn detect(source: &str, file_path: &str, kind: FileKind) -> Vec<Finding> {
    let lines = match kind {
        FileKind::Python | FileKind::Shell => code_lines_hash(source),
        _ => code_lines_slash(source),
    };
    let mut out = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let secret_ctx = in_secret_context(&lines, idx);
        match kind {
            FileKind::Python => python(line, idx, file_path, secret_ctx, &mut out),
            FileKind::JavaScript => javascript(line, idx, file_path, secret_ctx, &mut out),
            FileKind::Go => go(line, idx, file_path, source, secret_ctx, &mut out),
            FileKind::Shell => shell(line, idx, file_path, &mut out),
            _ => {}
        }
    }
    out
}

/// Whether the line, or the function header / assignment target it sits
/// under, names authentication material. `return Math.random()…` inside
/// `function resetToken()` is a token; inside `function jitter()` it is not.
fn in_secret_context(lines: &[String], idx: usize) -> bool {
    if SECRET_CONTEXT.is_match(&lines[idx]) {
        return true;
    }
    lines[..idx]
        .iter()
        .rev()
        .take(6)
        .find(|l| DECL_LINE.is_match(l))
        .map(|l| SECRET_CONTEXT.is_match(l))
        .unwrap_or(false)
}

fn python(line: &str, idx: usize, file: &str, secret_ctx: bool, out: &mut Vec<Finding>) {
    if let Some(m) = PY_EVAL.find(line) {
        if is_dynamic(args_after(line, &m)) {
            out.push(finding("gen_code_injection", Severity::High, file, idx,
                "Dynamic input reaches eval/exec: whoever controls the string controls the interpreter", line));
        }
    }
    if let Some(m) = PY_SUBPROCESS_SHELL.find(line) {
        let args = args_after(line, &m);
        let uses_shell = PY_SHELL_TRUE.is_match(line)
            || m.as_str().starts_with("os.system")
            || m.as_str().starts_with("os.popen")
            || m.as_str().starts_with("commands.");
        if uses_shell && is_dynamic(args) {
            out.push(finding("gen_command_injection", Severity::High, file, idx,
                "Dynamic input is passed to a shell: metacharacters in it become commands; pass an argument list without shell=True", line));
        }
    }
    if let Some(m) = PY_PICKLE.find(line) {
        if is_dynamic(args_after(line, &m)) {
            out.push(finding("gen_unsafe_deserialization", Severity::High, file, idx,
                "Untrusted data is deserialised with pickle/marshal, which executes arbitrary code on load", line));
        }
    }
    if PY_YAML_LOAD.is_match(line) && !PY_YAML_SAFE.is_match(line) {
        out.push(finding("gen_unsafe_deserialization", Severity::High, file, idx,
            "yaml.load without a safe Loader instantiates arbitrary Python objects from the document", line));
    }
    if PY_VERIFY_FALSE.is_match(line) {
        out.push(finding(
            "gen_tls_verification_disabled",
            Severity::High,
            file,
            idx,
            "TLS certificate verification is disabled: the connection is open to interception",
            line,
        ));
    }
    if let Some(m) = PY_SQL_EXEC.find(line) {
        let args = args_after(line, &m);
        if DYNAMIC.is_match(args) && !args.contains(", (") && !args.contains(", [") {
            out.push(finding(
                "gen_sql_injection",
                Severity::High,
                file,
                idx,
                "SQL is built by string formatting rather than parameters",
                line,
            ));
        }
    }
    if PY_WEAK_HASH.is_match(line) && secret_ctx {
        out.push(finding(
            "gen_weak_hash",
            Severity::Medium,
            file,
            idx,
            "MD5/SHA-1 used for a credential: use a password hash (argon2, bcrypt, scrypt)",
            line,
        ));
    }
    if PY_RANDOM.is_match(line) && secret_ctx {
        out.push(finding(
            "gen_insecure_randomness",
            Severity::Medium,
            file,
            idx,
            "random is not cryptographically secure; use secrets for tokens and keys",
            line,
        ));
    }
}

fn javascript(line: &str, idx: usize, file: &str, secret_ctx: bool, out: &mut Vec<Finding>) {
    if let Some(m) = JS_EVAL.find(line) {
        if is_dynamic(args_after(line, &m)) {
            out.push(finding("gen_code_injection", Severity::High, file, idx,
                "Dynamic input reaches eval/Function: whoever controls the string controls the runtime", line));
        }
    }
    if let Some(m) = JS_EXEC.find(line) {
        let args = args_after(line, &m);
        // `spawn(cmd, [args])` without a shell is safe; `exec` always uses one.
        let shelled = m.as_str().starts_with("exec")
            || line.contains("shell: true")
            || line.contains("shell:true");
        if shelled && is_dynamic(args) {
            out.push(finding("gen_command_injection", Severity::High, file, idx,
                "Dynamic input is passed to a shell via child_process; use execFile/spawn with an argument array", line));
        }
    }
    if let Some(m) = JS_INNER_HTML.find(line) {
        let rhs = &line[m.end()..];
        if is_dynamic(rhs) {
            out.push(finding(
                "gen_xss_sink",
                Severity::Medium,
                file,
                idx,
                "Dynamic content is written as HTML: use textContent or an escaping renderer",
                line,
            ));
        }
    }
    if JS_TLS_OFF.is_match(line) {
        out.push(finding(
            "gen_tls_verification_disabled",
            Severity::High,
            file,
            idx,
            "TLS certificate verification is disabled: the connection is open to interception",
            line,
        ));
    }
    if let Some(m) = JS_SQL.find(line) {
        let args = args_after(line, &m);
        if (args.contains("${") || DYNAMIC.is_match(args))
            && !args.contains(", [")
            && !args.contains(",[")
        {
            out.push(finding(
                "gen_sql_injection",
                Severity::High,
                file,
                idx,
                "SQL is built by string interpolation rather than parameters",
                line,
            ));
        }
    }
    if JS_RANDOM.is_match(line) && secret_ctx {
        out.push(finding("gen_insecure_randomness", Severity::Medium, file, idx,
            "Math.random is not cryptographically secure; use crypto.randomBytes/getRandomValues for tokens", line));
    }
}

fn go(line: &str, idx: usize, file: &str, source: &str, secret_ctx: bool, out: &mut Vec<Finding>) {
    if let Some(m) = GO_EXEC.find(line) {
        let args = args_after(line, &m);
        // `exec.Command("sh", "-c", dynamic)` or a formatted program name.
        if args.contains("\"-c\"") && DYNAMIC.is_match(args)
            || args.starts_with("fmt.")
            || args.contains("Sprintf")
        {
            out.push(finding(
                "gen_command_injection",
                Severity::High,
                file,
                idx,
                "Dynamic input reaches a shell via exec.Command",
                line,
            ));
        }
    }
    if GO_TLS_OFF.is_match(line) {
        out.push(finding(
            "gen_tls_verification_disabled",
            Severity::High,
            file,
            idx,
            "InsecureSkipVerify disables certificate verification",
            line,
        ));
    }
    if let Some(m) = GO_SQL.find(line) {
        let args = args_after(line, &m);
        if (args.contains("Sprintf") || args.contains("+ ")) && !LITERAL_ARG.is_match(args) {
            out.push(finding(
                "gen_sql_injection",
                Severity::High,
                file,
                idx,
                "SQL is built with Sprintf/concatenation rather than placeholders",
                line,
            ));
        }
    }
    if GO_MATH_RAND.is_match(line) && GO_MATH_RAND_IMPORT.is_match(source) && secret_ctx {
        out.push(finding(
            "gen_insecure_randomness",
            Severity::Medium,
            file,
            idx,
            "math/rand is not cryptographically secure; use crypto/rand for tokens and keys",
            line,
        ));
    }
}

fn shell(line: &str, idx: usize, file: &str, out: &mut Vec<Finding>) {
    if SH_EVAL.is_match(line) {
        out.push(finding(
            "gen_code_injection",
            Severity::High,
            file,
            idx,
            "eval of a variable executes its contents as shell",
            line,
        ));
    }
    if SH_PIPE.is_match(line) {
        out.push(finding(
            "gen_pipe_to_shell",
            Severity::High,
            file,
            idx,
            "Remote content is piped straight into a shell with no integrity check",
            line,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ids(src: &str, path: &str) -> Vec<String> {
        detect(src, path, crate::classify(path))
            .into_iter()
            .map(|f| f.invariant_id)
            .collect()
    }

    #[test]
    fn python_sinks_need_dynamic_input() {
        assert_eq!(
            ids("eval(request.args['q'])", "a.py"),
            vec!["gen_code_injection"]
        );
        assert!(ids("eval('1+1')", "a.py").is_empty());
        assert_eq!(
            ids("subprocess.run(f'ls {path}', shell=True)", "a.py"),
            vec!["gen_command_injection"]
        );
        assert!(ids("subprocess.run(['ls', path])", "a.py").is_empty());
        assert!(ids("subprocess.run('ls -la', shell=True)", "a.py").is_empty());
        assert_eq!(
            ids("cur.execute(f\"SELECT * FROM t WHERE id={uid}\")", "a.py"),
            vec!["gen_sql_injection"]
        );
        assert!(ids(
            "cur.execute(\"SELECT * FROM t WHERE id=%s\", (uid,))",
            "a.py"
        )
        .is_empty());
        assert_eq!(
            ids("data = yaml.load(f)", "a.py"),
            vec!["gen_unsafe_deserialization"]
        );
        assert!(ids("data = yaml.load(f, Loader=yaml.SafeLoader)", "a.py").is_empty());
        assert!(ids("data = yaml.safe_load(f)", "a.py").is_empty());
        assert_eq!(
            ids("r = requests.get(url, verify=False)", "a.py"),
            vec!["gen_tls_verification_disabled"]
        );
        assert_eq!(
            ids("token = random.randint(0, 1<<32)", "a.py"),
            vec!["gen_insecure_randomness"]
        );
        assert!(ids("delay = random.random()", "a.py").is_empty());
        assert_eq!(
            ids("h = hashlib.md5(password.encode())", "a.py"),
            vec!["gen_weak_hash"]
        );
        assert!(ids("etag = hashlib.md5(body)", "a.py").is_empty());
    }

    #[test]
    fn javascript_sinks_need_dynamic_input() {
        assert_eq!(
            ids("el.innerHTML = userInput;", "a.js"),
            vec!["gen_xss_sink"]
        );
        assert!(ids("el.innerHTML = '<b>hi</b>';", "a.js").is_empty());
        assert_eq!(
            ids("exec(`ls ${dir}`);", "a.ts"),
            vec!["gen_command_injection"]
        );
        assert!(ids("execFile('ls', [dir]);", "a.ts").is_empty());
        assert_eq!(
            ids("db.query(`SELECT * FROM u WHERE id=${id}`);", "a.js"),
            vec!["gen_sql_injection"]
        );
        assert!(ids("db.query('SELECT * FROM u WHERE id=$1', [id]);", "a.js").is_empty());
        assert_eq!(
            ids("const token = Math.random().toString(36);", "a.js"),
            vec!["gen_insecure_randomness"]
        );
        assert!(ids("const jitter = Math.random() * 100;", "a.js").is_empty());
        assert_eq!(
            ids("https.request({ rejectUnauthorized: false })", "a.js"),
            vec!["gen_tls_verification_disabled"]
        );
    }

    #[test]
    fn go_sinks_need_dynamic_input() {
        assert_eq!(
            ids(
                "cmd := exec.Command(\"sh\", \"-c\", fmt.Sprintf(\"ls %s\", dir))",
                "a.go"
            ),
            vec!["gen_command_injection"]
        );
        assert!(ids("cmd := exec.Command(\"ls\", dir)", "a.go").is_empty());
        assert_eq!(
            ids("tls.Config{InsecureSkipVerify: true}", "a.go"),
            vec!["gen_tls_verification_disabled"]
        );
        assert_eq!(
            ids(
                "db.Query(fmt.Sprintf(\"SELECT * FROM t WHERE id=%d\", id))",
                "a.go"
            ),
            vec!["gen_sql_injection"]
        );
        assert!(ids("db.Query(\"SELECT * FROM t WHERE id=$1\", id)", "a.go").is_empty());
    }

    #[test]
    fn shell_pipe_and_eval() {
        assert_eq!(
            ids("curl -fsSL https://x | sudo bash", "install.sh"),
            vec!["gen_pipe_to_shell"]
        );
        assert_eq!(ids("eval \"$CMD\"", "run.sh"), vec!["gen_code_injection"]);
        assert!(ids(
            "curl -fsSL https://x -o /tmp/x.sh && sha256sum -c x.sha",
            "install.sh"
        )
        .is_empty());
    }
}
