//! STRIDE threat model generated from discovered structure.
//!
//! Everything here is **REASONED**: it is derived from what the source
//! declares — routes, data stores, outbound calls, secrets, auth and
//! rate-limit markers — and is a starting point for the review, not its
//! conclusion. Each row says what evidence it rests on.

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref ROUTE: Regex = Regex::new(r#"(?x)
        (?:app|router|server|api|r|e|g|mux)\.(get|post|put|patch|delete|route|handle|use|all)\s*\(\s*["'`]([^"'`]+)["'`]   # express/gin/echo/chi
      | @(?:app|router|bp|api)\.(route|get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']                                     # flask/fastapi
      | \bpath\s*\(\s*["']([^"']+)["']                                                                                       # django
      | HandleFunc\s*\(\s*["']([^"']+)["']                                                                                   # net/http
      | function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)                                                                  # solidity
    "#).unwrap();
    static ref DATA_STORE: Regex = Regex::new(r"(?i)\b(sqlite3\.connect|psycopg2|pymongo|mongoose|createConnection|createPool|sql\.Open|prisma|sequelize|knex|redis\.|Redis\(|boto3\.client\(\s*['\x22]s3|gorm\.Open|MongoClient|typeorm|drizzle)").unwrap();
    static ref OUTBOUND: Regex = Regex::new(r"(?i)\b(requests\.(get|post)|httpx\.|urlopen|fetch\(|axios|http\.Get|http\.Post|http\.NewRequest|\.call\{|\.delegatecall\()").unwrap();
    static ref SECRET_SOURCE: Regex = Regex::new(r"(?i)\b(process\.env\.|os\.environ|os\.getenv|Getenv\(|vault|secretsmanager|SecretClient)").unwrap();
    static ref AUTH: Regex = Regex::new(r"(?i)\b(jwt|passport|session|oauth|openid|authenticate|login_required|Depends\(get_current_user|@login_required|require_auth|onlyOwner|onlyRole|Signer<)").unwrap();
    static ref AUTHZ: Regex = Regex::new(r"(?i)\b(role|permission|is_admin|isAdmin|has_perm|can\(|authorize|onlyOwner|onlyRole|has_one|require\(msg\.sender)").unwrap();
    static ref RATE_LIMIT: Regex = Regex::new(r"(?i)\b(rateLimit|rate_limit|limiter|throttle|Throttled|slowapi|express-rate-limit)").unwrap();
    static ref LOGGING: Regex = Regex::new(r"(?i)\b(audit|logger\.|logging\.|log\.Printf|winston|pino|emit\s+\w+)").unwrap();
    static ref VALIDATION: Regex = Regex::new(r"(?i)\b(pydantic|zod|joi|yup|validator|validate|schema|marshmallow|serializer|require\()").unwrap();
}

/// An entry point the model reasons about.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EntryPoint {
    pub file: String,
    pub line: usize,
    pub route: String,
}

/// One STRIDE row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Threat {
    pub category: &'static str,
    pub subject: String,
    pub concern: String,
    pub evidence: String,
}

/// The generated model.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ThreatModel {
    pub entry_points: Vec<EntryPoint>,
    pub data_stores: Vec<String>,
    pub outbound_calls: Vec<String>,
    pub secret_sources: Vec<String>,
    pub has_auth: bool,
    pub has_authz: bool,
    pub has_rate_limit: bool,
    pub has_logging: bool,
    pub has_validation: bool,
    pub threats: Vec<Threat>,
}

/// Build a model from `(path, source)` pairs.
pub fn threat_model(files: &[(String, String)]) -> ThreatModel {
    let mut m = ThreatModel::default();
    let mut seen_store = std::collections::BTreeSet::new();
    let mut seen_out = std::collections::BTreeSet::new();
    let mut seen_secret = std::collections::BTreeSet::new();

    for (path, src) in files {
        for (i, line) in src.lines().enumerate() {
            if let Some(c) = ROUTE.captures(line) {
                let route = (2..=6)
                    .filter_map(|g| c.get(g))
                    .map(|g| g.as_str().to_string())
                    .next()
                    .unwrap_or_default();
                if !route.is_empty() {
                    m.entry_points.push(EntryPoint {
                        file: path.clone(),
                        line: i + 1,
                        route,
                    });
                }
            }
            if let Some(mm) = DATA_STORE.find(line) {
                if seen_store.insert(mm.as_str().to_lowercase()) {
                    m.data_stores
                        .push(format!("{} ({}:{})", mm.as_str(), path, i + 1));
                }
            }
            if let Some(mm) = OUTBOUND.find(line) {
                if seen_out.insert(mm.as_str().to_lowercase()) {
                    m.outbound_calls
                        .push(format!("{} ({}:{})", mm.as_str(), path, i + 1));
                }
            }
            if let Some(mm) = SECRET_SOURCE.find(line) {
                if seen_secret.insert(mm.as_str().to_lowercase()) {
                    m.secret_sources
                        .push(format!("{} ({}:{})", mm.as_str(), path, i + 1));
                }
            }
            if AUTH.is_match(line) {
                m.has_auth = true;
            }
            if AUTHZ.is_match(line) {
                m.has_authz = true;
            }
            if RATE_LIMIT.is_match(line) {
                m.has_rate_limit = true;
            }
            if LOGGING.is_match(line) {
                m.has_logging = true;
            }
            if VALIDATION.is_match(line) {
                m.has_validation = true;
            }
        }
    }

    let n = m.entry_points.len();
    let ep = |_m: &ThreatModel| {
        if n == 0 {
            "the service".to_string()
        } else {
            format!("{} entry point(s)", n)
        }
    };
    if n > 0 || !m.data_stores.is_empty() {
        m.threats.push(Threat {
            category: "Spoofing",
            subject: ep(&m),
            concern: if m.has_auth {
                "Authentication markers found; confirm every state-changing route is behind them"
                    .into()
            } else {
                "No authentication marker found anywhere: every route appears anonymous".into()
            },
            evidence: if m.has_auth {
                "jwt/session/oauth/login_required/Signer detected".into()
            } else {
                "no auth idiom matched".into()
            },
        });
        m.threats.push(Threat { category: "Tampering", subject: ep(&m),
            concern: if m.has_validation { "Input validation markers found; confirm they cover every request field that reaches a store or a shell".into() } else { "No input-validation library or schema found: requests reach handlers unvalidated".into() },
            evidence: if m.has_validation { "validator/schema idiom detected".into() } else { "none matched".into() } });
        m.threats.push(Threat { category: "Repudiation", subject: ep(&m),
            concern: if m.has_logging { "Logging present; confirm security-relevant actions (auth, privilege change, payment) are logged with actor and outcome".into() } else { "No logging found: actions cannot be attributed after the fact".into() },
            evidence: if m.has_logging { "logger/audit idiom detected".into() } else { "none matched".into() } });
        m.threats.push(Threat { category: "Information disclosure", subject: format!("{} secret source(s), {} data store(s)", m.secret_sources.len(), m.data_stores.len()),
            concern: "Secrets read from the environment or a vault must never reach logs or responses; data stores hold the crown jewels".into(),
            evidence: m.secret_sources.iter().chain(m.data_stores.iter()).cloned().collect::<Vec<_>>().join("; ") });
        m.threats.push(Threat {
            category: "Denial of service",
            subject: ep(&m),
            concern: if m.has_rate_limit {
                "Rate limiting present; confirm it is per-principal and covers expensive routes"
                    .into()
            } else {
                "No rate limiting found: every route can be called without bound".into()
            },
            evidence: if m.has_rate_limit {
                "rate-limit idiom detected".into()
            } else {
                "none matched".into()
            },
        });
        m.threats.push(Threat { category: "Elevation of privilege", subject: ep(&m),
            concern: if m.has_authz { "Authorization markers found; confirm object-level checks (this user may act on this resource), not only role checks".into() } else { "No authorization marker found: authenticated users may reach every function".into() },
            evidence: if m.has_authz { "role/permission/onlyOwner idiom detected".into() } else { "none matched".into() } });
    }
    if !m.outbound_calls.is_empty() {
        m.threats.push(Threat { category: "Trust boundary", subject: format!("{} outbound call site(s)", m.outbound_calls.len()),
            concern: "Every outbound call crosses a trust boundary: verify TLS, pin the destination, and never let a request choose the URL".into(),
            evidence: m.outbound_calls.join("; ") });
    }
    m
}

impl ThreatModel {
    /// Markdown rendering.
    pub fn to_markdown(&self, target: &str) -> String {
        let mut s = format!("# Threat model — {target}\n\n> **REASONED.** Generated from declared structure; a starting point for review, not a conclusion.\n\n");
        s.push_str(&format!(
            "## Entry points ({})\n\n",
            self.entry_points.len()
        ));
        for e in &self.entry_points {
            s.push_str(&format!("- `{}` — {}:{}\n", e.route, e.file, e.line));
        }
        s.push_str(&format!(
            "\n## Data stores ({})\n\n",
            self.data_stores.len()
        ));
        for d in &self.data_stores {
            s.push_str(&format!("- {d}\n"));
        }
        s.push_str(&format!(
            "\n## Outbound calls ({})\n\n",
            self.outbound_calls.len()
        ));
        for d in &self.outbound_calls {
            s.push_str(&format!("- {d}\n"));
        }
        s.push_str(&format!(
            "\n## Secret sources ({})\n\n",
            self.secret_sources.len()
        ));
        for d in &self.secret_sources {
            s.push_str(&format!("- {d}\n"));
        }
        s.push_str(
            "\n## STRIDE\n\n| Category | Subject | Concern | Evidence |\n|---|---|---|---|\n",
        );
        for t in &self.threats {
            s.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                t.category, t.subject, t.concern, t.evidence
            ));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_routes_stores_and_missing_controls() {
        let files = vec![
            ("app.py".to_string(), "@app.route('/pay', methods=['POST'])\ndef pay():\n    conn = sqlite3.connect('db')\n    r = requests.get(URL)\n    key = os.environ['K']\n".to_string()),
            ("api.js".to_string(), "app.post('/users', (req, res) => {})\n".to_string()),
        ];
        let m = threat_model(&files);
        assert_eq!(m.entry_points.len(), 2);
        assert_eq!(m.data_stores.len(), 1);
        assert_eq!(m.outbound_calls.len(), 1);
        assert!(!m.has_auth && !m.has_rate_limit);
        assert!(m
            .threats
            .iter()
            .any(|t| t.category == "Spoofing" && t.concern.contains("anonymous")));
        assert!(m.to_markdown("x").contains("REASONED"));
    }
}
