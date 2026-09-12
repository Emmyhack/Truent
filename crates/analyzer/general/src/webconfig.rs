//! Web and API security configuration.
//!
//! The framework-level settings that turn a correct application into an
//! exploitable one: CORS that reflects any origin *with* credentials, cookies
//! without `Secure`/`HttpOnly`, debug mode in a server, JWT verification
//! switched off, CSRF protection removed, and request-controlled URLs or
//! paths reaching an HTTP client or the filesystem (SSRF / path traversal).

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use crate::text::{code_lines_hash, code_lines_slash};
use crate::{finding, FileKind};

lazy_static! {
    static ref CORS_WILDCARD: Regex = Regex::new(r#"(?i)(origin\s*[:=]\s*(["']\*["']|true\b)|Access-Control-Allow-Origin["']?\s*[,:=]\s*["']\*["']|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|origins\s*=\s*["']\*["'])"#).unwrap();
    static ref CORS_CREDENTIALS: Regex = Regex::new(r#"(?i)(credentials\s*[:=]\s*true|Access-Control-Allow-Credentials["']?\s*[,:=]\s*["']?true|CORS_ALLOW_CREDENTIALS\s*=\s*True|supports_credentials\s*=\s*True)"#).unwrap();

    static ref COOKIE_INSECURE: Regex = Regex::new(r#"(?i)(\b(secure|httpOnly|http_only)\s*[:=]\s*[Ff]alse\b|SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False|CSRF_COOKIE_HTTPONLY\s*=\s*False)"#).unwrap();
    /// `sameSite: "none"` is only safe together with `secure: true`; the
    /// regex crate has no look-around, so the pair is checked in code.
    static ref SAMESITE_NONE: Regex = Regex::new(r#"(?i)sameSite\s*[:=]\s*["']none["']"#).unwrap();
    static ref SECURE_TRUE: Regex = Regex::new(r#"(?i)\bsecure\s*[:=]\s*[Tt]rue\b"#).unwrap();

    /// Application debug mode. Case-sensitive on purpose: Cargo's
    /// `debug = true` profile key (debug *info*) and countless `debug: true`
    /// logger options are not an application running in debug mode.
    static ref DEBUG_PY: Regex = Regex::new(r#"(^\s*DEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True)"#).unwrap();
    static ref DEBUG_ENV: Regex = Regex::new(r#"(?m)^\s*(FLASK_DEBUG\s*=\s*1|DJANGO_DEBUG\s*=\s*(True|1|true))\s*$"#).unwrap();

    static ref JWT_UNVERIFIED: Regex = Regex::new(r#"(?i)(verify_signature["']?\s*[:=]\s*False|algorithms\s*[:=]\s*\[?\s*["']none["']|ignoreExpiration\s*:\s*true|verify\s*=\s*False\b.*jwt|jwt\.decode\([^)]*verify\s*=\s*False)"#).unwrap();

    static ref CSRF_OFF: Regex = Regex::new(r#"(?i)(@csrf_exempt\b|WTF_CSRF_ENABLED\s*=\s*False|WTF_CSRF_CHECK_DEFAULT\s*=\s*False|skip_before_action\s+:verify_authenticity_token|protect_from_forgery\s+except|csrf\s*:\s*false)"#).unwrap();

    /// An HTTP client whose target comes from the request.
    static ref SSRF: Regex = Regex::new(r#"(?i)\b(requests\.(get|post|put|delete|head|request)|urllib\.request\.urlopen|urlopen|httpx\.(get|post)|fetch|axios(\.(get|post))?|got|http\.Get|http\.Post|http\.NewRequest)\s*\(\s*[^)]*\b(request\.(args|form|json|values|data|GET|POST|query_params|params)|req\.(query|params|body)|r\.(URL\.Query|FormValue|PostFormValue)|c\.(Query|Param|PostForm))\b"#).unwrap();
    static ref SSRF_GUARD: Regex = Regex::new(r#"(?i)(allowlist|allow_list|whitelist|is_safe_url|validate_url|urlparse\([^)]*\)\.hostname\s*(in|==)|new URL\([^)]*\)\.hostname\s*(===|==|in))"#).unwrap();

    /// A filesystem operation whose path comes from the request.
    static ref TRAVERSAL: Regex = Regex::new(r#"(?i)\b(open|send_file|send_from_directory|os\.path\.join|readFile(Sync)?|createReadStream|sendFile|path\.join|os\.Open|os\.ReadFile|ioutil\.ReadFile|http\.ServeFile)\s*\(\s*[^)]*\b(request\.(args|form|values|GET|POST|query_params|params)|req\.(query|params|body)|r\.(URL\.Query|FormValue)|c\.(Query|Param))\b"#).unwrap();
    static ref TRAVERSAL_GUARD: Regex = Regex::new(r#"(?i)(secure_filename|path\.basename|basename\(|filepath\.Base|\.\.\s*in|contains\(\s*["']\.\.["']|realpath|path\.resolve[^;]*startsWith|filepath\.Clean|safe_join)"#).unwrap();
}

pub fn detect(source: &str, file_path: &str, kind: FileKind) -> Vec<Finding> {
    let lines = match kind {
        FileKind::Python | FileKind::Shell | FileKind::Config | FileKind::ContainerManifest => {
            code_lines_hash(source)
        }
        _ => code_lines_slash(source),
    };
    let mut out = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let lo = idx.saturating_sub(4);
        let hi = (idx + 4).min(lines.len() - 1);
        let near = lines[lo..=hi].join("\n");

        if CORS_WILDCARD.is_match(line) {
            let with_creds = CORS_CREDENTIALS.is_match(&near);
            out.push(finding("gen_web_cors_wildcard",
                if with_creds { Severity::High } else { Severity::Low },
                file_path, idx,
                if with_creds {
                    "CORS allows any origin *with credentials*: any site can make authenticated requests as the user"
                } else {
                    "CORS allows any origin; fine for a public read-only API, wrong for anything that uses cookies or tokens"
                }, line));
        }
        if COOKIE_INSECURE.is_match(line)
            || (SAMESITE_NONE.is_match(line) && !SECURE_TRUE.is_match(line))
        {
            out.push(finding("gen_web_insecure_cookie", Severity::Medium, file_path, idx,
                "Session or CSRF cookie is missing Secure/HttpOnly (or is SameSite=None without Secure): it can be read by script or sent over plaintext", line));
        }
        let debug_on = match kind {
            FileKind::Python => DEBUG_PY.is_match(line),
            FileKind::Config => DEBUG_ENV.is_match(line),
            _ => false,
        };
        if debug_on {
            out.push(finding("gen_web_debug_enabled", Severity::Medium, file_path, idx,
                "Debug mode is enabled in application configuration: stack traces, settings and often an interactive debugger are exposed", line));
        }
        if JWT_UNVERIFIED.is_match(line) {
            out.push(finding(
                "gen_web_jwt_unverified",
                Severity::High,
                file_path,
                idx,
                "JWT signature or expiry verification is disabled: any forged token is accepted",
                line,
            ));
        }
        if CSRF_OFF.is_match(line) {
            out.push(finding(
                "gen_web_csrf_disabled",
                Severity::Medium,
                file_path,
                idx,
                "CSRF protection is disabled for a state-changing endpoint",
                line,
            ));
        }
        if SSRF.is_match(line) && !SSRF_GUARD.is_match(&near) {
            out.push(finding("gen_web_ssrf", Severity::High, file_path, idx,
                "A request-controlled URL is fetched server-side: the server can be pointed at internal services and cloud metadata", line));
        }
        if TRAVERSAL.is_match(line) && !TRAVERSAL_GUARD.is_match(&near) {
            out.push(finding("gen_web_path_traversal", Severity::High, file_path, idx,
                "A request-controlled path reaches the filesystem without normalisation: `../` escapes the intended directory", line));
        }
    }
    out
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
    fn cors_wildcard_with_credentials_is_high_without_is_low() {
        let f = detect(
            "app.use(cors({ origin: '*', credentials: true }));",
            "a.js",
            FileKind::JavaScript,
        );
        assert_eq!(f[0].severity, Severity::High);
        let f = detect(
            "app.use(cors({ origin: '*' }));",
            "a.js",
            FileKind::JavaScript,
        );
        assert_eq!(f[0].severity, Severity::Low);
        assert!(ids(
            "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));",
            "a.js"
        )
        .is_empty());
    }

    #[test]
    fn django_settings() {
        assert_eq!(
            ids("DEBUG = True", "settings.py"),
            vec!["gen_web_debug_enabled"]
        );
        assert!(ids("DEBUG = os.environ.get('DEBUG') == '1'", "settings.py").is_empty());
        assert_eq!(
            ids("SESSION_COOKIE_SECURE = False", "settings.py"),
            vec!["gen_web_insecure_cookie"]
        );
        assert!(ids("SESSION_COOKIE_SECURE = True", "settings.py").is_empty());
        assert_eq!(
            ids("@csrf_exempt\ndef pay(request):", "views.py"),
            vec!["gen_web_csrf_disabled"]
        );
    }

    #[test]
    fn jwt_verification_off() {
        assert_eq!(
            ids(
                "claims = jwt.decode(token, options={\"verify_signature\": False})",
                "a.py"
            ),
            vec!["gen_web_jwt_unverified"]
        );
        assert_eq!(
            ids("jwt.verify(token, key, { algorithms: ['none'] })", "a.js"),
            vec!["gen_web_jwt_unverified"]
        );
        assert!(ids(
            "claims = jwt.decode(token, key, algorithms=['HS256'])",
            "a.py"
        )
        .is_empty());
    }

    #[test]
    fn ssrf_and_traversal_need_request_input_and_no_guard() {
        assert_eq!(
            ids("r = requests.get(request.args['url'])", "a.py"),
            vec!["gen_web_ssrf"]
        );
        assert!(ids("r = requests.get(UPSTREAM_URL)", "a.py").is_empty());
        let guarded = "if urlparse(request.args['url']).hostname in ALLOWED:\n    r = requests.get(request.args['url'])";
        assert!(ids(guarded, "a.py").is_empty());
        assert_eq!(
            ids("fs.readFile(path.join(base, req.query.name), cb)", "a.js"),
            vec!["gen_web_path_traversal"]
        );
        assert!(ids(
            "fs.readFile(path.join(base, path.basename(req.query.name)), cb)",
            "a.js"
        )
        .is_empty());
        assert_eq!(
            ids(
                "return send_file(os.path.join(UPLOADS, request.args['f']))",
                "a.py"
            ),
            vec!["gen_web_path_traversal"]
        );
    }
}
