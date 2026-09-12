//! Comment handling for languages the core normaliser does not cover.
//!
//! `truent_core::text` strips `//` and `/* */` comments and string contents.
//! Most of this crate's detectors need the *strings kept* — a SQL query built
//! with an f-string is the finding — and several languages comment with `#`.

/// Remove a `#` comment from one line, respecting quotes.
pub fn strip_hash_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in line.chars() {
        match quote {
            Some(q) => {
                out.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                    out.push(c);
                } else if c == '#' {
                    break;
                } else {
                    out.push(c);
                }
            }
        }
    }
    out
}

/// Remove a `//` comment from one line, respecting quotes and template
/// literals. `/* */` blocks on a single line are removed too.
pub fn strip_slash_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut in_block = false;
    while let Some(c) = chars.next() {
        if in_block {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
            }
            continue;
        }
        match quote {
            Some(q) => {
                out.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' | '`' => {
                    quote = Some(c);
                    out.push(c);
                }
                '/' if chars.peek() == Some(&'/') => break,
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    in_block = true;
                }
                _ => out.push(c),
            },
        }
    }
    out
}

/// Lines with comments removed, strings intact, count preserved.
pub fn code_lines_hash(source: &str) -> Vec<String> {
    source.lines().map(strip_hash_comment).collect()
}

/// Lines with comments removed, strings intact, count preserved.
pub fn code_lines_slash(source: &str) -> Vec<String> {
    source.lines().map(strip_slash_comment).collect()
}

/// Whether a string literal's content is a placeholder rather than a value.
pub fn is_placeholder(value: &str) -> bool {
    let v = value
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_lowercase();
    v.is_empty()
        || v.len() < 8
        || v.contains("example")
        || v.contains("changeme")
        || v.contains("local-only")
        || v.contains("localonly")
        || v.contains("dev-only")
        || v.contains("devonly")
        || v.contains("not-a-secret")
        || v.contains("notasecret")
        || v.contains("insecure")
        || v.contains("change_me")
        || v.contains("placeholder")
        || v.contains("your_")
        || v.contains("your-")
        || v.contains("<your")
        || v.contains("dummy")
        || v.contains("fake")
        || v.contains("xxxx")
        || v.contains("****")
        || v.contains("...")
        || v.starts_with("${")
        || v.starts_with("{{")
        || v.starts_with('$')
        || v.starts_with('<')
        || v.contains("os.environ")
        || v.contains("process.env")
        || v.contains("getenv")
        || v.contains("secrets.")
        || v.contains("vault:")
        || v.chars()
            .all(|c| c == 'x' || c == '0' || c == '*' || c == '-')
}

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total as f64;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_comments_stripped_but_not_inside_strings() {
        assert_eq!(strip_hash_comment("x = 1  # note").trim_end(), "x = 1");
        assert_eq!(strip_hash_comment(r#"s = "a#b""#), r#"s = "a#b""#);
    }

    #[test]
    fn slash_comments_stripped_but_not_urls_or_templates() {
        assert_eq!(strip_slash_comment("x = 1; // note").trim_end(), "x = 1;");
        assert_eq!(
            strip_slash_comment(r#"u = "https://x""#),
            r#"u = "https://x""#
        );
        assert_eq!(strip_slash_comment("a /* b */ c").trim(), "a  c");
    }

    #[test]
    fn placeholders_are_recognised() {
        for p in [
            "changeme",
            "${SECRET}",
            "process.env.KEY",
            "<your-key>",
            "xxxxxxxxxxxx",
            "AKIAIOSFODNN7EXAMPLE",
        ] {
            assert!(is_placeholder(p), "{p}");
        }
        assert!(!is_placeholder("k8Dv2nQp9sLx4Zt7Wm1Ry"));
    }

    #[test]
    fn entropy_separates_words_from_keys() {
        assert!(entropy("password") < 3.0);
        assert!(entropy("k8Dv2nQp9sLx4Zt7Wm1RyBc") > 4.0);
    }
}
