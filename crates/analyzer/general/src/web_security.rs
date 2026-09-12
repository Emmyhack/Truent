//! Application-layer weaknesses beyond injection: mass assignment, unvalidated
//! uploads, error detail disclosure, sensitive data in logs, TOCTOU on files,
//! insecure temp files and permissions, ReDoS, XXE, unrestricted GraphQL,
//! WebSocket origin, non-atomic multi-writes, object-level authorization,
//! unbounded pagination.
//!
//! Each detector reads the *enclosing function* (see [`function_body`]) so a
//! guard elsewhere in the same handler is seen, and each requires the shape
//! that makes the weakness real — a record loaded by a request-supplied id
//! is only a finding when the function never references the caller's
//! identity; two writes are only non-atomic when the function moves value
//! and opens no transaction.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use crate::text::{code_lines_hash, code_lines_slash};
use crate::{finding, FileKind};

lazy_static! {
    /// A function/handler declaration, any of the three languages.
    static ref DECL: Regex = Regex::new(
        r"^\s*(async\s+)?(def\s+\w+|func\s+(\(\w+\s+\*?\w+\)\s*)?\w+|function\b|(export\s+)?(async\s+)?(const|let|var)\s+\w+\s*=\s*(async\s*)?(function|\()|\w+\s*\([^)]*\)\s*(=>|\{)|(app|router|r)\.(get|post|put|patch|delete|use)\s*\()"
    ).unwrap();

    // 1. mass assignment
    static ref JS_MASS: Regex = Regex::new(
        r"\.(create|insertMany|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate|update|upsert)\s*\(\s*(\{[^}]*\}\s*,\s*)?(\{\s*\.\.\.)?req\.body\b|Object\.assign\s*\([^,]+,\s*req\.body\b|\.set\s*\(\s*req\.body\s*\)"
    ).unwrap();
    static ref PY_MASS: Regex = Regex::new(
        r"\*\*request\.(json|form|data|POST|get_json\(\))|\.objects\.(create|update|filter\([^)]*\)\.update)\s*\(\s*\*\*request\.|\.update\s*\(\s*request\.(json|form|data|POST)\s*\)"
    ).unwrap();

    // 2. uploads
    static ref JS_MULTER: Regex = Regex::new(r"\bmulter\s*\(").unwrap();
    static ref JS_UPLOAD_GUARD: Regex = Regex::new(r"fileFilter|limits\s*:").unwrap();
    static ref PY_FILES: Regex = Regex::new(r"request\.files\b|UploadFile\b").unwrap();
    static ref PY_SAVE: Regex = Regex::new(r"\.save\s*\(|shutil\.copyfileobj|\.write\s*\(").unwrap();
    static ref PY_UPLOAD_GUARD: Regex = Regex::new(
        r"secure_filename|allowed_file|ALLOWED_EXTENSIONS|MAX_CONTENT_LENGTH|\.mimetype|content_type|magic\.|\.filename\.rsplit|imghdr|filetype\.|max_length|size\b"
    ).unwrap();
    static ref GO_FORMFILE: Regex = Regex::new(r"\.FormFile\s*\(").unwrap();
    static ref GO_UPLOAD_GUARD: Regex = Regex::new(
        r"MaxBytesReader|ParseMultipartForm|DetectContentType|filepath\.Ext|Content-Type|\.Size\s*>"
    ).unwrap();

    // 3. error detail disclosure
    static ref JS_ERR_OUT: Regex = Regex::new(
        r"res\.(send|json|end|write)\s*\(\s*(err|error|e|ex)\s*\)|res\.(status\([^)]*\)\.)?(send|json)\s*\([^)]*\b(err|error|e|ex)\.stack\b|\{\s*(error|stack)\s*:\s*(err|error|e|ex)\.stack\b"
    ).unwrap();
    static ref PY_ERR_OUT: Regex = Regex::new(
        r"return\s+(jsonify\()?[^\n]*\b(traceback\.format_exc\(\)|repr\(e\)|str\(e\)|str\(exc\)|str\(err\)|str\(ex\))|return\s+(str\(e\)|str\(ex\)|str\(err\)|repr\(e\)|traceback\.format_exc\(\))\s*,\s*\d{3}"
    ).unwrap();
    static ref GO_ERR_OUT: Regex = Regex::new(r"http\.Error\s*\(\s*w\s*,\s*err\.Error\(\)").unwrap();

    // 4. sensitive data in logs
    static ref LOG_CALL: Regex = Regex::new(
        r"\b(console\.(log|info|debug|warn|error|trace)|logger?\.(info|debug|warning|warn|error|critical|exception|trace|fatal)|logging\.(info|debug|warning|error|critical)|log\.(Printf|Println|Print|Printf|Info|Infof|Debug|Debugf|Error|Errorf|Warn|Warnf)|print|winston\.\w+|pino\.\w+)\s*\("
    ).unwrap();
    static ref SENSITIVE_IDENT: Regex = Regex::new(
        r"(?i)\b(password|passwd|pwd|secret|secret_key|secretKey|api_key|apiKey|access_token|accessToken|refresh_token|refreshToken|private_key|privateKey|authorization|auth_header|credit_card|creditCard|card_number|cardNumber|cvv|ssn|social_security)\b"
    ).unwrap();
    static ref LOG_MASKED: Regex = Regex::new(r"(?i)mask|redact|\*\*\*|\[filtered\]|hash\(|\.length\b|len\(").unwrap();

    // 5. TOCTOU
    static ref FS_CHECK: Regex = Regex::new(
        r"\b(os\.path\.(exists|isfile|isdir)|os\.access|fs\.existsSync|fs\.exists|fs\.accessSync|os\.Stat|os\.Lstat)\s*\(\s*([A-Za-z_][\w.]*)"
    ).unwrap();
    static ref FS_USE: Regex = Regex::new(
        r"\b(open|fs\.(writeFile|writeFileSync|readFile|readFileSync|unlink|unlinkSync|rename|renameSync|mkdir|mkdirSync|createWriteStream)|os\.(Remove|Create|Open|OpenFile|Rename|Mkdir)|shutil\.\w+|os\.(remove|rename|unlink|makedirs|mkdir))\s*\("
    ).unwrap();

    // 6. temp files
    static ref TMP_INSECURE: Regex = Regex::new(
        r#"\btempfile\.mktemp\s*\(|\bmktemp\s*\(|["'`]/tmp/[A-Za-z0-9_.-]+["'`]|os\.TempDir\(\)\s*\+\s*["']"#
    ).unwrap();

    // 7. permissions
    static ref PERM_INSECURE: Regex = Regex::new(
        r#"\bchmod\s+(-R\s+)?(777|666|a\+w|o\+w)\b|os\.chmod\s*\([^,]+,\s*0o?(777|666)\s*\)|fs\.chmod(Sync)?\s*\([^,]+,\s*(0o?777|0o?666|['"](777|666)['"])\s*\)|os\.Chmod\s*\([^,]+,\s*0o?(777|666)\s*\)|umask\s*\(\s*0o?0?\s*\)"#
    ).unwrap();

    // 8. ReDoS: a quantified group containing a quantifier — (a+)+, (\d*)*, (.*a)+
    static ref REGEX_LITERAL: Regex = Regex::new(
        r#"(/(?:\\.|[^/\n])+/[gimsuy]*|new\s+RegExp\s*\(\s*["'`][^"'`]+["'`]|re\.(compile|match|search|fullmatch|findall|sub)\s*\(\s*r?["'][^"']+["']|regexp\.(MustCompile|Compile)\s*\(\s*`[^`]+`)"#
    ).unwrap();
    // The group must *begin* with a quantified atom — `(a+)+`, `(\d*)*`,
    // `(\w+\s?)*`, `(.*a)+`. A group led by a literal, `(-[a-z0-9]+)*`, is
    // the common safe way to write a separated list: the literal prevents
    // the inner and outer repetitions from overlapping.
    static ref NESTED_QUANTIFIER: Regex = Regex::new(r"\((?:\?:)?(?:\\.|\[[^\]]*\]|\.|[A-Za-z0-9_])[+*](?:[^()\\]|\\.)*\)\s*[+*{]").unwrap();

    // 9. XXE
    static ref PY_LXML_IMPORT: Regex = Regex::new(r"from\s+lxml\s+import\s+etree|import\s+lxml\.etree").unwrap();
    static ref PY_LXML_PARSE: Regex = Regex::new(r"\betree\.(parse|fromstring|XML|iterparse)\s*\(").unwrap();
    static ref PY_XXE_SAFE: Regex = Regex::new(r"resolve_entities\s*=\s*False|defusedxml|no_network\s*=\s*True").unwrap();
    static ref PY_XXE_EXPLICIT: Regex = Regex::new(r"resolve_entities\s*=\s*True|load_dtd\s*=\s*True").unwrap();
    static ref JS_XXE: Regex = Regex::new(r"noent\s*:\s*true|dtdload\s*:\s*true|\bxmlParseWithEntities|expandEntities\s*:\s*true").unwrap();

    // 10. GraphQL
    static ref GQL_SERVER: Regex = Regex::new(r"new\s+ApolloServer\s*\(|graphqlHTTP\s*\(|GraphQLView\.as_view\(|createYoga\s*\(|graphql_flask|\bGraphQL\s*\(").unwrap();
    static ref GQL_INTROSPECTION: Regex = Regex::new(r"introspection\s*[:=]\s*[Tt]rue").unwrap();
    static ref GQL_LIMITS: Regex = Regex::new(r"depthLimit|validationRules|queryComplexity|costAnalysis|max_depth|maxDepth|createComplexityLimitRule|armor|persistedQueries|MaxAliasesRule").unwrap();

    // 11. WebSocket origin
    static ref WS_SERVER_JS: Regex = Regex::new(r"new\s+(WebSocket\.Server|WebSocketServer|ws\.Server)\s*\(|new\s+Server\s*\(\s*\{[^}]*\bcors\s*:\s*\{\s*origin\s*:\s*['\x22]\*").unwrap();
    static ref WS_GUARD_JS: Regex = Regex::new(r"verifyClient|origin\b|handleProtocols|\.on\s*\(\s*['\x22]headers").unwrap();
    static ref WS_GO_ORIGIN_TRUE: Regex = Regex::new(r"CheckOrigin\s*:\s*func\s*\([^)]*\)\s*bool\s*\{\s*return\s+true").unwrap();
    static ref WS_PY: Regex = Regex::new(r"websockets\.serve\s*\(").unwrap();
    static ref WS_PY_GUARD: Regex = Regex::new(r"origins\s*=|process_request|check_origin").unwrap();

    // 12. non-atomic multi-write
    static ref WRITE_OP: Regex = Regex::new(
        // A write is a *persistence* call: SQL, an awaited model/repository
        // method, a Django-style `obj.save()`, or a call on an ORM/driver
        // receiver. `createHash().update()` is not one.
        r"\bawait\s+[\w.\[\]]+\.(save|update|create|insert|insertOne|insertMany|updateOne|updateMany|delete|deleteOne|destroy|remove|increment|decrement|upsert)\s*\(|\b(prisma|db|knex|models?|repo\w*|\w+Repository|session|cursor|collection|conn|client|tx|trx|[A-Z]\w+\.objects|[A-Z]\w+)\.(save|update|create|insert|insertOne|insertMany|updateOne|updateMany|delete|deleteOne|destroy|remove|bulk_create|bulk_update|increment|decrement|upsert|Save|Create|Updates?|Delete|Exec)\s*\(|\b\w+\.save\s*\(\s*\)|\bINSERT\s+INTO\b|\bUPDATE\s+\w+\s+SET\b|\bDELETE\s+FROM\b"
    ).unwrap();
    static ref TX_GUARD: Regex = Regex::new(
        r"(?i)transaction|atomic|\bBEGIN\b|\.commit\(|startTransaction|withTransaction|\btx\b|\.Begin\(|\$transaction|session\.with_transaction|savepoint|\bunit_of_work|two_phase|\block\b"
    ).unwrap();
    static ref VALUE_CONTEXT: Regex = Regex::new(
        r"(?i)balance|amount|transfer|withdraw|deposit|payment|payout|refund|order|stock|inventory|credit|debit|wallet|ledger|invoice|quantity|price"
    ).unwrap();

    // 13. object-level authorization
    static ref JS_LOAD_BY_REQ_ID: Regex = Regex::new(
        r"\.(findById|findByPk|findOne|findUnique|findFirst|findOneAndUpdate|findByIdAndUpdate|findByIdAndDelete|findOneAndDelete)\s*\(\s*(\{\s*(where\s*:\s*\{\s*)?(id|_id|pk)\s*:\s*)?(req\.(params|query|body)\.\w+|\w*[iI]d)\b"
    ).unwrap();
    static ref PY_LOAD_BY_REQ_ID: Regex = Regex::new(
        r"(get_object_or_404\s*\(\s*\w+\s*,\s*(pk|id)\s*=\s*(pk|id|\w+_id|request\.\w+(\.get\([^)]*\)|\[[^\]]*\]))\s*\)|\.objects\.get\s*\(\s*(pk|id)\s*=\s*(pk|id|\w+_id|request\.\w+(\.get\([^)]*\)|\[[^\]]*\]))\s*\)|\.query\.get(_or_404)?\s*\(\s*(id|pk|\w+_id|request\.\w+(\.get\([^)]*\)|\[[^\]]*\]))\s*\))"
    ).unwrap();
    static ref GO_LOAD_BY_REQ_ID: Regex = Regex::new(
        r"\.(First|Find|Take)\s*\(\s*&\w+\s*,\s*(c\.Param|mux\.Vars\(r\)\[|r\.URL\.Query\(\)\.Get|chi\.URLParam|id\b)"
    ).unwrap();
    static ref OWNERSHIP_REF: Regex = Regex::new(
        r"(?i)req\.user|request\.user|current_user|g\.user|session\[|\bowner|user_id|userId|tenant|account_id|accountId|permission|authorize|\bcan\(|policy|abilit|isAdmin|is_admin|role|has_perm|@login_required|@permission|\bauth\b|jwt|claims|principal|ctx\.Value\(|c\.Get\(\s*[\x22']user"
    ).unwrap();

    // 14. unbounded pagination
    static ref LIMIT_FROM_REQ: Regex = Regex::new(
        r"(?i)\b(limit|per_page|perPage|page_size|pageSize|take|count|size)\s*(:?=|:)\s*(parseInt\(|Number\(|int\(|strconv\.Atoi\()?\s*(req\.(query|body|params)|request\.(args|GET|POST|json|form|query_params)|c\.Query|r\.URL\.Query\(\)\.Get|c\.DefaultQuery)"
    ).unwrap();
    static ref LIMIT_USED: Regex = Regex::new(r"(?i)\.(limit|take|first|slice)\s*\(|\bLIMIT\b|\[\s*:\s*\w*(limit|per_page|page_size|pageSize|perPage)").unwrap();
    static ref LIMIT_CLAMP: Regex = Regex::new(r"(?i)Math\.min|\bmin\(|clamp|MAX_(PAGE|LIMIT|PER)|max_(page|limit|per)|maxLimit|<=?\s*\d{2,}|>\s*\d{2,}|\bcap\b|paginate_by|PAGE_SIZE").unwrap();
}

/// Index range `[start, end)` of the function enclosing line `idx`: from the
/// nearest preceding declaration to the next declaration (or 80 lines).
fn function_body(lines: &[String], idx: usize) -> (usize, usize) {
    let start = (0..=idx)
        .rev()
        .find(|&i| DECL.is_match(&lines[i]))
        .unwrap_or(0);
    let end = ((idx + 1)..lines.len())
        .find(|&i| DECL.is_match(&lines[i]))
        .unwrap_or(lines.len())
        .min(start + 80)
        .max(idx + 1);
    (start, end)
}

fn body_text(lines: &[String], idx: usize) -> String {
    let (s, e) = function_body(lines, idx);
    lines[s..e].join("\n")
}

pub fn detect(source: &str, file_path: &str, kind: FileKind) -> Vec<Finding> {
    let lines = match kind {
        FileKind::Python | FileKind::Shell => code_lines_hash(source),
        FileKind::JavaScript | FileKind::Go => code_lines_slash(source),
        _ => return Vec::new(),
    };
    let joined = lines.join("\n");
    let mut out = Vec::new();

    // A shell script is not an application: only the permission and
    // temp-file checks read it. Everything else here needs a Python/JS/Go
    // handler — a Python heredoc *inside* a shell script is data, not code.
    let app_code = matches!(kind, FileKind::Python | FileKind::JavaScript | FileKind::Go);

    for (idx, line) in lines.iter().enumerate() {
        if !app_code {
            if TMP_INSECURE.is_match(line) {
                out.push(finding("gen_insecure_temp_file", Severity::Low, file_path, idx,
                    "Predictable temporary file name: another local user can pre-create or symlink it and read or redirect what is written. Use mktemp(1) / mkstemp", line));
            }
            if PERM_INSECURE.is_match(line) {
                out.push(finding("gen_insecure_file_permissions", Severity::Medium, file_path, idx,
                    "World-writable permission: any local process can replace the file's content, which for scripts, configs and keys is code execution or credential theft", line));
            }
            continue;
        }
        // ---- 1. mass assignment -------------------------------------------
        let mass = match kind {
            FileKind::JavaScript => JS_MASS.is_match(line),
            FileKind::Python => PY_MASS.is_match(line),
            _ => false,
        };
        if mass {
            out.push(finding("gen_mass_assignment", Severity::Medium, file_path, idx,
                "The whole request body is bound to a model write: any field the model has — role, is_admin, balance, owner — can be set by the client. Bind an explicit allowlist of fields", line));
        }

        // ---- 2. uploads -----------------------------------------------------
        match kind {
            FileKind::JavaScript
                if JS_MULTER.is_match(line) && !JS_UPLOAD_GUARD.is_match(&joined) =>
            {
                out.push(finding("gen_upload_unvalidated", Severity::Medium, file_path, idx,
                    "File upload accepts any type and size: no fileFilter and no limits. An attacker uploads executables, HTML for stored XSS, or fills the disk", line));
            }
            FileKind::Python if PY_FILES.is_match(line) => {
                let body = body_text(&lines, idx);
                if PY_SAVE.is_match(&body) && !PY_UPLOAD_GUARD.is_match(&body) {
                    out.push(finding("gen_upload_unvalidated", Severity::Medium, file_path, idx,
                        "Uploaded file is saved without validating its name, type or size: path traversal via the filename, stored XSS via HTML, or disk exhaustion", line));
                }
            }
            FileKind::Go if GO_FORMFILE.is_match(line) => {
                let body = body_text(&lines, idx);
                if !GO_UPLOAD_GUARD.is_match(&body) {
                    out.push(finding("gen_upload_unvalidated", Severity::Medium, file_path, idx,
                        "Multipart upload read without a size cap (MaxBytesReader) or content-type/extension check", line));
                }
            }
            _ => {}
        }

        // ---- 3. error detail disclosure ------------------------------------
        let err_out = match kind {
            FileKind::JavaScript => JS_ERR_OUT.is_match(line),
            FileKind::Python => PY_ERR_OUT.is_match(line),
            FileKind::Go => GO_ERR_OUT.is_match(line),
            _ => false,
        };
        if err_out {
            out.push(finding("gen_error_detail_exposed", Severity::Low, file_path, idx,
                "Internal error text or stack trace is returned to the client: it reveals file paths, queries, library versions and logic that guide the next attack. Log it server-side; return a generic message and a correlation id", line));
        }

        // ---- 4. sensitive data in logs -------------------------------------
        if let Some(m) = LOG_CALL.find(line) {
            let args = &line[m.end()..];
            if SENSITIVE_IDENT.is_match(args) && !LOG_MASKED.is_match(args) {
                out.push(finding("gen_log_sensitive_data", Severity::Medium, file_path, idx,
                    "A credential, token or personal identifier is written to the log: logs are copied, shipped and retained far more widely than the store the value came from", line));
            }
        }

        // ---- 5. TOCTOU on the filesystem -----------------------------------
        if let Some(c) = FS_CHECK.captures(line) {
            let var = c.get(3).map(|m| m.as_str()).unwrap_or("");
            if !var.is_empty() {
                let window_end = lines.len().min(idx + 9);
                let hit = lines[idx + 1..window_end]
                    .iter()
                    .any(|l| FS_USE.is_match(l) && l.contains(var));
                if hit {
                    out.push(finding("gen_toctou_file", Severity::Low, file_path, idx,
                        "A check on a path is followed by a use of the same path: between the two, the file can be swapped for a symlink or replaced. Open first and handle the error, or open with O_EXCL/O_NOFOLLOW", line));
                }
            }
        }

        // ---- 6. insecure temp files ----------------------------------------
        if TMP_INSECURE.is_match(line) {
            out.push(finding("gen_insecure_temp_file", Severity::Low, file_path, idx,
                "Predictable temporary file name: another local user can pre-create or symlink it and read or redirect what is written. Use mkstemp / os.CreateTemp / fs.mkdtemp", line));
        }

        // ---- 7. permissions ------------------------------------------------
        if PERM_INSECURE.is_match(line) {
            out.push(finding("gen_insecure_file_permissions", Severity::Medium, file_path, idx,
                "World-writable permission: any local process can replace the file's content, which for scripts, configs and keys is code execution or credential theft", line));
        }

        // ---- 8. ReDoS ------------------------------------------------------
        for m in REGEX_LITERAL.find_iter(line) {
            if NESTED_QUANTIFIER.is_match(m.as_str()) {
                out.push(finding("gen_regex_dos", Severity::Medium, file_path, idx,
                    "Regular expression with a quantifier applied to a group that itself contains a quantifier: catastrophic backtracking on crafted input pins a CPU for seconds to hours. Rewrite without nested repetition or use a linear-time engine (RE2)", line));
                break;
            }
        }

        // ---- 9. XXE --------------------------------------------------------
        match kind {
            FileKind::Python => {
                if PY_XXE_EXPLICIT.is_match(line)
                    || (PY_LXML_PARSE.is_match(line)
                        && PY_LXML_IMPORT.is_match(&joined)
                        && !PY_XXE_SAFE.is_match(&joined))
                {
                    out.push(finding("gen_xxe", Severity::High, file_path, idx,
                        "XML is parsed with external entities enabled (lxml resolves entities by default): a crafted document reads local files or reaches internal services. Use defusedxml or XMLParser(resolve_entities=False)", line));
                }
            }
            FileKind::JavaScript if JS_XXE.is_match(line) => {
                out.push(finding("gen_xxe", Severity::High, file_path, idx,
                    "XML parser configured to expand external entities: a crafted document reads local files or reaches internal services", line));
            }
            _ => {}
        }

        // ---- 10. GraphQL ---------------------------------------------------
        if GQL_SERVER.is_match(line) || GQL_INTROSPECTION.is_match(line) {
            let has_limits = GQL_LIMITS.is_match(&joined);
            let intro = GQL_INTROSPECTION.is_match(line);
            if !has_limits || intro {
                out.push(finding("gen_graphql_unrestricted", Severity::Medium, file_path, idx,
                    if intro {
                        "GraphQL introspection is explicitly enabled: the whole schema, including internal fields, is enumerable by anyone"
                    } else {
                        "GraphQL endpoint without a depth or complexity limit: deeply nested or aliased queries exhaust the server"
                    }, line));
            }
        }

        // ---- 11. WebSocket origin ------------------------------------------
        match kind {
            FileKind::JavaScript
                if WS_SERVER_JS.is_match(line) && !WS_GUARD_JS.is_match(&joined) =>
            {
                out.push(finding("gen_websocket_no_origin_check", Severity::Medium, file_path, idx,
                    "WebSocket server accepts connections from any origin: a page on another site can open a socket with the victim's cookies (cross-site WebSocket hijacking). Verify Origin in verifyClient", line));
            }
            FileKind::Go if WS_GO_ORIGIN_TRUE.is_match(line) => {
                out.push(finding("gen_websocket_no_origin_check", Severity::Medium, file_path, idx,
                    "CheckOrigin returns true unconditionally: cross-site WebSocket hijacking. Compare the Origin header against an allowlist", line));
            }
            FileKind::Python if WS_PY.is_match(line) && !WS_PY_GUARD.is_match(&joined) => {
                out.push(finding("gen_websocket_no_origin_check", Severity::Medium, file_path, idx,
                    "WebSocket server without an origins= allowlist: cross-site WebSocket hijacking", line));
            }
            _ => {}
        }

        // ---- 12. non-atomic multi-write ------------------------------------
        if DECL.is_match(line) {
            let body = body_text(&lines, idx);
            let writes = WRITE_OP.find_iter(&body).count();
            if writes >= 2 && VALUE_CONTEXT.is_match(&body) && !TX_GUARD.is_match(&body) {
                out.push(finding("gen_non_atomic_multi_write", Severity::Medium, file_path, idx,
                    "Two or more writes that move value are not wrapped in a transaction: a failure or a concurrent request between them leaves balances inconsistent (double credit, lost debit). Wrap them atomically", line));
            }
        }

        // ---- 13. object-level authorization --------------------------------
        let loads = match kind {
            FileKind::JavaScript => JS_LOAD_BY_REQ_ID.is_match(line),
            FileKind::Python => PY_LOAD_BY_REQ_ID.is_match(line),
            FileKind::Go => GO_LOAD_BY_REQ_ID.is_match(line),
            _ => false,
        };
        if loads && !OWNERSHIP_REF.is_match(line) {
            let body = body_text(&lines, idx);
            if !OWNERSHIP_REF.is_match(&body) {
                out.push(finding("gen_object_level_auth_missing", Severity::High, file_path, idx,
                    "A record is loaded by a client-supplied id with no reference to the caller's identity anywhere in the handler: any authenticated user can read or modify any other user's object by changing the id (IDOR / BOLA). Scope the query by owner or check ownership before use", line));
            }
        }

        // ---- 14. unbounded pagination --------------------------------------
        if LIMIT_FROM_REQ.is_match(line) {
            let body = body_text(&lines, idx);
            if LIMIT_USED.is_match(&body) && !LIMIT_CLAMP.is_match(&body) {
                out.push(finding("gen_unbounded_query_limit", Severity::Low, file_path, idx,
                    "Page size comes from the request and is used unclamped: `?limit=10000000` returns the whole table and exhausts memory and the database. Cap it (Math.min(limit, MAX))", line));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(src: &str, kind: FileKind) -> Vec<String> {
        detect(src, "f", kind)
            .into_iter()
            .map(|f| f.invariant_id)
            .collect()
    }

    #[test]
    fn mass_assignment() {
        assert!(ids("await User.create(req.body);", FileKind::JavaScript)
            .contains(&"gen_mass_assignment".into()));
        assert!(ids("u = User(**request.json)", FileKind::Python)
            .contains(&"gen_mass_assignment".into()));
        assert!(!ids(
            "await User.create({ name: req.body.name });",
            FileKind::JavaScript
        )
        .contains(&"gen_mass_assignment".into()));
    }

    #[test]
    fn uploads_need_a_guard() {
        assert!(ids(
            "const upload = multer({ dest: 'uploads/' });",
            FileKind::JavaScript
        )
        .contains(&"gen_upload_unvalidated".into()));
        assert!(!ids(
            "const upload = multer({ dest: 'uploads/', limits: { fileSize: 1e6 }, fileFilter });",
            FileKind::JavaScript
        )
        .contains(&"gen_upload_unvalidated".into()));
        let py = "def up():\n    f = request.files['f']\n    f.save(f.filename)\n";
        assert!(ids(py, FileKind::Python).contains(&"gen_upload_unvalidated".into()));
        let ok = "def up():\n    f = request.files['f']\n    f.save(secure_filename(f.filename))\n";
        assert!(!ids(ok, FileKind::Python).contains(&"gen_upload_unvalidated".into()));
    }

    #[test]
    fn error_details_and_logs() {
        assert!(
            ids("res.status(500).send(err.stack);", FileKind::JavaScript)
                .contains(&"gen_error_detail_exposed".into())
        );
        assert!(
            ids("    return jsonify(error=str(e)), 500", FileKind::Python)
                .contains(&"gen_error_detail_exposed".into())
        );
        assert!(ids("console.log('login', password);", FileKind::JavaScript)
            .contains(&"gen_log_sensitive_data".into()));
        assert!(!ids(
            "console.log('login', mask(password));",
            FileKind::JavaScript
        )
        .contains(&"gen_log_sensitive_data".into()));
        assert!(!ids(
            "logger.info('tokens used: %d', tokens.length)",
            FileKind::JavaScript
        )
        .contains(&"gen_log_sensitive_data".into()));
    }

    #[test]
    fn toctou_temp_and_permissions() {
        let py = "def f(p):\n    if os.path.exists(p):\n        with open(p) as fh:\n            return fh.read()\n";
        assert!(ids(py, FileKind::Python).contains(&"gen_toctou_file".into()));
        assert!(ids("name = tempfile.mktemp()", FileKind::Python)
            .contains(&"gen_insecure_temp_file".into()));
        assert!(!ids("fd, name = tempfile.mkstemp()", FileKind::Python)
            .contains(&"gen_insecure_temp_file".into()));
        assert!(ids("os.chmod(path, 0o777)", FileKind::Python)
            .contains(&"gen_insecure_file_permissions".into()));
        assert!(ids("chmod -R 777 /var/www", FileKind::Shell)
            .contains(&"gen_insecure_file_permissions".into()));
        assert!(!ids("os.chmod(path, 0o600)", FileKind::Python)
            .contains(&"gen_insecure_file_permissions".into()));
    }

    #[test]
    fn redos_only_on_nested_quantifiers() {
        assert!(
            ids("const re = /^(a+)+$/;", FileKind::JavaScript).contains(&"gen_regex_dos".into())
        );
        assert!(ids("pat = re.compile(r'(\\d*)*x')", FileKind::Python)
            .contains(&"gen_regex_dos".into()));
        assert!(!ids(
            "const re = /^[a-z]+@[a-z]+\\.[a-z]{2,}$/;",
            FileKind::JavaScript
        )
        .contains(&"gen_regex_dos".into()));
        assert!(
            !ids("const re = /(a|b)+/;", FileKind::JavaScript).contains(&"gen_regex_dos".into())
        );
        // A separator-led group is the safe way to write a list.
        assert!(!ids(
            "NAME_RE = re.compile(r'^[a-z0-9]+(-[a-z0-9]+)*$')",
            FileKind::Python
        )
        .contains(&"gen_regex_dos".into()));
        assert!(ids("const re = /^(\\w+\\s?)*$/;", FileKind::JavaScript)
            .contains(&"gen_regex_dos".into()));
    }

    #[test]
    fn xxe_graphql_websocket() {
        let py = "from lxml import etree\ndoc = etree.parse(request.data)\n";
        assert!(ids(py, FileKind::Python).contains(&"gen_xxe".into()));
        let safe = "from lxml import etree\np = etree.XMLParser(resolve_entities=False)\ndoc = etree.parse(request.data, p)\n";
        assert!(!ids(safe, FileKind::Python).contains(&"gen_xxe".into()));
        assert!(ids(
            "const server = new ApolloServer({ typeDefs, resolvers });",
            FileKind::JavaScript
        )
        .contains(&"gen_graphql_unrestricted".into()));
        assert!(!ids(
            "const server = new ApolloServer({ typeDefs, validationRules: [depthLimit(5)] });",
            FileKind::JavaScript
        )
        .contains(&"gen_graphql_unrestricted".into()));
        assert!(ids(
            "const wss = new WebSocket.Server({ port: 8080 });",
            FileKind::JavaScript
        )
        .contains(&"gen_websocket_no_origin_check".into()));
        assert!(ids(
            "var up = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}",
            FileKind::Go
        )
        .contains(&"gen_websocket_no_origin_check".into()));
    }

    #[test]
    fn non_atomic_only_when_value_moves_without_a_transaction() {
        let bad = "async function transfer(from, to, amount) {\n  from.balance -= amount; await from.save();\n  to.balance += amount; await to.save();\n}\n";
        assert!(ids(bad, FileKind::JavaScript).contains(&"gen_non_atomic_multi_write".into()));
        let ok = "async function transfer(from, to, amount) {\n  await sequelize.transaction(async (t) => {\n  from.balance -= amount; await from.save({ transaction: t });\n  to.balance += amount; await to.save({ transaction: t });\n  });\n}\n";
        assert!(!ids(ok, FileKind::JavaScript).contains(&"gen_non_atomic_multi_write".into()));
        let unrelated = "async function rename(a, b) {\n  a.name = 'x'; await a.save();\n  b.name = 'y'; await b.save();\n}\n";
        assert!(
            !ids(unrelated, FileKind::JavaScript).contains(&"gen_non_atomic_multi_write".into())
        );
        // A hash `.update()` and one awaited delete are not two writes.
        let hash = "async function verifyWalletSignature(msg) {\n  const h = createHash('sha256').update(msg).digest('hex');\n  await prisma.authNonce.delete({ where: { h } });\n  return true;\n}\n";
        assert!(!ids(hash, FileKind::JavaScript).contains(&"gen_non_atomic_multi_write".into()));
    }

    #[test]
    fn idor_needs_absence_of_any_ownership_reference() {
        let bad = "app.get('/orders/:id', async (req, res) => {\n  const order = await Order.findById(req.params.id);\n  res.json(order);\n});\n";
        assert!(ids(bad, FileKind::JavaScript).contains(&"gen_object_level_auth_missing".into()));
        let ok = "app.get('/orders/:id', async (req, res) => {\n  const order = await Order.findOne({ _id: req.params.id, owner: req.user.id });\n  res.json(order);\n});\n";
        assert!(!ids(ok, FileKind::JavaScript).contains(&"gen_object_level_auth_missing".into()));
        let py_bad = "def order(request, pk):\n    o = get_object_or_404(Order, pk=pk)\n    return render(request, 'o.html', {'o': o})\n";
        assert!(ids(py_bad, FileKind::Python).contains(&"gen_object_level_auth_missing".into()));
        let py_ok = "@login_required\ndef order(request, pk):\n    o = get_object_or_404(Order, pk=pk, user=request.user)\n    return render(request, 'o.html', {'o': o})\n";
        assert!(!ids(py_ok, FileKind::Python).contains(&"gen_object_level_auth_missing".into()));
    }

    #[test]
    fn shell_scripts_only_get_shell_checks() {
        // A Python heredoc inside a shell script is data the script writes,
        // not a handler the script runs.
        let sh = "python3 - <<'PY'\nlimit = int(request.args.get(\"limit\"))\nreturn rows[:limit]\nPY\nchmod 777 /tmp/x\n";
        let got = ids(sh, FileKind::Shell);
        assert!(!got.contains(&"gen_unbounded_query_limit".into()));
        assert!(got.contains(&"gen_insecure_file_permissions".into()));
    }

    #[test]
    fn pagination_clamp() {
        let bad = "app.get('/items', async (req, res) => {\n  const limit = parseInt(req.query.limit);\n  res.json(await Item.find().limit(limit));\n});\n";
        assert!(ids(bad, FileKind::JavaScript).contains(&"gen_unbounded_query_limit".into()));
        let ok = "app.get('/items', async (req, res) => {\n  const limit = Math.min(parseInt(req.query.limit) || 20, 100);\n  res.json(await Item.find().limit(limit));\n});\n";
        assert!(!ids(ok, FileKind::JavaScript).contains(&"gen_unbounded_query_limit".into()));
    }
}
