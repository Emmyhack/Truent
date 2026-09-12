//! Source-text normalisation shared by every chain analyzer.
//!
//! The detectors are pattern matchers over source text. Matching *raw* text
//! means matching comments and string literals too, which was the single
//! largest source of false positives across the analyzers: a revert string
//! reading `"ERC20: transfer from the zero address"` registered as an ERC-20
//! transfer, a `msg!("no signer check")` registered as a missing signer check,
//! and a commented-out function was reported as live code.
//!
//! Each analyzer normalises once at its entry point with one of these and
//! hands detectors code only. Line count and order are preserved throughout,
//! so `index + 1` still refers to the right line of the original file, and
//! [`restore_snippets`] puts the user's original text back on each finding.

use crate::Finding;

/// Which comments to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentPolicy {
    /// Remove every comment.
    StripAll,
    /// Remove `//` and `/* */` comments but keep `///` and `//!` doc comments.
    KeepDocComments,
    /// Remove every comment except lines beginning `/// CHECK:`.
    ///
    /// Anchor makes that one annotation semantic — it is the developer's
    /// attestation that an unchecked `AccountInfo` is intentional — so the
    /// Solana analyzer must still see it. Every other doc comment is prose,
    /// and prose must never raise a finding.
    KeepCheckAnnotations,
}

/// Strip string-literal contents and comments from one line.
///
/// Literals are replaced by empty quotes rather than deleted, so
/// `require(x, "")` still reads as a require and column positions stay
/// roughly stable. Escapes are honoured so `"say \"hi\""` ends where it
/// should. A `/` inside a literal is not a comment.
pub fn code_only(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                    out.push(q);
                }
            }
            None => match c {
                '"' | '\'' => {
                    quote = Some(c);
                    out.push(c);
                }
                '/' if chars.peek() == Some(&'/') => break,
                '/' if chars.peek() == Some(&'*') => break,
                _ => out.push(c),
            },
        }
    }
    out
}

/// Remove `/* ... */` block comments, keeping newlines so numbering holds.
pub fn strip_block_comments(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    let mut in_block = false;
    let mut quote: Option<char> = None;

    while i < chars.len() {
        let c = chars[i];
        if in_block {
            if c == '*' && chars.get(i + 1) == Some(&'/') {
                in_block = false;
                i += 2;
                continue;
            }
            if c == '\n' {
                out.push('\n');
            }
            i += 1;
            continue;
        }
        // Track string literals so `"/* not a comment */"` survives intact.
        match quote {
            Some(q) => {
                if c == '\\' {
                    out.push(c);
                    if let Some(&n) = chars.get(i + 1) {
                        out.push(n);
                    }
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                } else if c == '/' && chars.get(i + 1) == Some(&'*') {
                    in_block = true;
                    i += 2;
                    continue;
                } else if c == '/' && chars.get(i + 1) == Some(&'/') {
                    // Line comment: the `/*` inside it is not a block opener.
                    while i < chars.len() && chars[i] != '\n' {
                        out.push(chars[i]);
                        i += 1;
                    }
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Normalise a whole source file for detection.
///
/// Returns one string with the same number of lines as the input.
/// Blank the contents of Rust raw string literals (`r"…"`, `r#"…"#`, any
/// number of `#`) that span lines, keeping every newline so line numbers
/// survive. A per-line lexer cannot see that a line is *inside* such a
/// literal; without this pass a test fixture held in a raw string — an
/// entire vulnerable Anchor program, say — is analysed as if it were code.
pub fn strip_raw_strings(source: &str) -> String {
    let b = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < b.len() {
        // Start of a raw string: `r` followed by `#*"`, not part of an identifier.
        if b[i] == b'r' && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) {
            let mut j = i + 1;
            while j < b.len() && b[j] == b'#' {
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                let hashes = j - (i + 1);
                let close = format!("\"{}", "#".repeat(hashes));
                out.push_str(&source[i..=j]);
                let body_start = j + 1;
                match source[body_start..].find(&close) {
                    Some(len) => {
                        for c in source[body_start..body_start + len].chars() {
                            if c == '\n' {
                                out.push('\n');
                            }
                        }
                        out.push_str(&close);
                        i = body_start + len + close.len();
                        continue;
                    }
                    None => {
                        out.push_str(&source[body_start..]);
                        break;
                    }
                }
            }
        }
        let ch = source[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

pub fn normalize(source: &str, policy: CommentPolicy) -> String {
    let without_blocks = strip_block_comments(source);
    let mut out = String::with_capacity(source.len());
    for (i, line) in without_blocks.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let trimmed = line.trim_start();
        let is_doc = trimmed.starts_with("///") || trimmed.starts_with("//!");
        let is_check = trimmed.starts_with("/// CHECK:");
        let keep = match policy {
            CommentPolicy::StripAll => false,
            CommentPolicy::KeepDocComments => is_doc,
            CommentPolicy::KeepCheckAnnotations => is_check,
        };
        if keep {
            out.push_str(line);
        } else {
            out.push_str(&code_only(line));
        }
    }
    // `str::lines` drops a trailing newline; keep the count identical.
    if source.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Put each finding's original source line back as its snippet.
///
/// Detectors saw stripped text, so the snippet they recorded has its strings
/// emptied. The report should show what the user actually wrote.
pub fn restore_snippets(original: &str, findings: &mut [Finding]) {
    let lines: Vec<&str> = original.lines().collect();
    for f in findings.iter_mut() {
        if f.line >= 1 && f.line <= lines.len() {
            f.snippet = lines[f.line - 1].trim().to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_strings_are_blanked_but_lines_survive() {
        let src = "let a = 1;\nconst F: &str = r#\"\npub fn withdraw() {}\n\"#;\nlet b = r\"x\";\nlet c = r##\"multi\nline\"##;";
        let out = strip_raw_strings(src);
        assert_eq!(out.lines().count(), src.lines().count());
        assert!(!out.contains("withdraw"));
        assert!(!out.contains("multi"));
        assert!(out.contains("let a = 1;") && out.contains("let b = r\"\";"));
        assert_eq!(strip_raw_strings("let cursor = 1;"), "let cursor = 1;");
    }
    use crate::Severity;

    #[test]
    fn revert_strings_are_emptied() {
        let l = r#"require(from != address(0), "ERC20: transfer from the zero address");"#;
        let c = code_only(l);
        assert!(!c.to_lowercase().contains("transfer"));
        assert!(c.contains(r#"require(from != address(0), "")"#));
    }

    #[test]
    fn escapes_and_slashes_inside_strings_are_respected() {
        assert!(!code_only(r#"a("say \"hi\" now"); b"#).contains("hi"));
        let c = code_only(r#"string u = "https://x"; uint y = 1;"#);
        assert!(c.contains("uint y = 1;") && !c.contains("https"));
    }

    #[test]
    fn block_comments_keep_line_numbers_and_ignore_strings() {
        let src = "a\n/* b\n c */\nd";
        let n = normalize(src, CommentPolicy::StripAll);
        assert_eq!(n.lines().count(), 4);
        assert!(!n.contains('b') && n.contains('d'));

        // A block-comment opener inside a string literal is not a comment.
        let s = r#"x = "/* keep */"; y = 1;"#;
        assert!(strip_block_comments(s).contains("y = 1"));
        // ...and inside a line comment it does not open a block either.
        let s2 = "a // /* not open\nb";
        assert!(strip_block_comments(s2).contains('b'));
    }

    #[test]
    fn doc_comments_survive_only_under_keep_doc_policy() {
        let src = "/// CHECK: intentional\nlet x = 1; // plain\n";
        let keep = normalize(src, CommentPolicy::KeepDocComments);
        assert!(keep.contains("/// CHECK: intentional"));
        assert!(!keep.contains("plain"));
        let strip = normalize(src, CommentPolicy::StripAll);
        assert!(!strip.contains("CHECK"));
    }

    #[test]
    fn check_annotation_policy_keeps_only_the_attestation() {
        let src = "/// the vault authority\n/// CHECK: intentional\nlet x = 1; // c\n";
        let n = normalize(src, CommentPolicy::KeepCheckAnnotations);
        assert!(n.contains("/// CHECK: intentional"));
        assert!(
            !n.contains("vault authority"),
            "ordinary doc prose must be stripped"
        );
        assert!(!n.contains("// c"));
    }

    #[test]
    fn normalize_preserves_line_count_with_and_without_trailing_newline() {
        for src in ["a\nb\nc", "a\nb\nc\n"] {
            let n = normalize(src, CommentPolicy::StripAll);
            assert_eq!(n.lines().count(), src.lines().count(), "{src:?}");
        }
    }

    #[test]
    fn restore_snippets_uses_the_original_line() {
        let src = "a\nrequire(x, \"ERC20: nope\");\nc";
        let mut f = vec![Finding::new(
            "t".into(),
            Severity::Low,
            "f".into(),
            2,
            0,
            "m".into(),
            "stripped".into(),
        )];
        restore_snippets(src, &mut f);
        assert_eq!(f[0].snippet, "require(x, \"ERC20: nope\");");
    }
}
