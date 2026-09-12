//! Text preparation shared by the pattern detectors.
//!
//! Truent's EVM detectors match against source text. Matching *raw* text means
//! matching the contents of comments and string literals too, which is the
//! single largest source of false positives in the detector set: every
//! OpenZeppelin token contains
//!
//! ```solidity
//! require(from != address(0), "ERC20: transfer from the zero address");
//! ```
//!
//! and a detector looking for `erc20` near `transfer` fires on the *error
//! message*, not on any transfer. Stripping literals before matching removes
//! that whole class at once.

/// Strip comments and string-literal contents from a line of Solidity.
///
/// String literals are replaced by empty quotes rather than deleted, so
/// `require(x, "")` still reads as a require. Comments are truncated from the
/// delimiter to end of line.
///
/// This is a lexical pass, not a parser: block comments spanning lines are
/// handled by [`strip_block_comments`], and escape handling covers `\` only.
pub use truent_core::text::{code_only, strip_block_comments};

/// Prepare a source file for line-based detection: block comments removed,
/// each line reduced to code only.
///
/// Line count and ordering are preserved, so `index + 1` still refers to the
/// right line of the original file.
pub fn code_lines(source: &str) -> Vec<String> {
    truent_core::text::normalize(source, truent_core::text::CommentPolicy::StripAll)
        .lines()
        .map(str::to_string)
        .collect()
}

/// The body of the function declared at `decl_line`, delimited by brace depth.
///
/// Returns the declaration plus everything up to its closing brace, so a
/// detector can never attribute one function's code to another. Several
/// detectors used to read a fixed 30–50 line window from the declaration,
/// which bled into whatever followed.
pub fn enclosing_function_body(source: &str, decl_line: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut depth: i32 = 0;
    let mut opened = false;
    let mut out: Vec<&str> = Vec::new();

    for line in lines.iter().skip(decl_line) {
        out.push(line);
        depth += line.matches('{').count() as i32;
        if depth > 0 {
            opened = true;
        }
        depth -= line.matches('}').count() as i32;
        if opened && depth <= 0 {
            break;
        }
    }
    out.join("\n")
}

/// Normalise a source file for detection and remember the original lines so
/// findings can be re-anchored to real text afterwards.
pub struct Normalized<'a> {
    /// Comment- and string-stripped source, same line count as the original.
    pub code: String,
    /// The original lines, for restoring snippets.
    pub original: Vec<&'a str>,
}

impl<'a> Normalized<'a> {
    /// Strip comments and string literals once, up front.
    pub fn new(source: &'a str) -> Self {
        Self {
            code: code_lines(source).join("\n"),
            original: source.lines().collect(),
        }
    }

    /// Replace each finding's snippet with the original text of its line.
    ///
    /// Detectors see stripped text, so the snippet they record has its
    /// strings emptied; the report should show what the user wrote.
    pub fn restore_snippets(&self, findings: &mut [truent_core::Finding]) {
        truent_core::text::restore_snippets(&self.original.join("\n"), findings);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_line_comments() {
        assert_eq!(
            code_only("uint x = 1; // balanceOf price").trim(),
            "uint x = 1;"
        );
        assert_eq!(code_only("// entirely a comment").trim(), "");
    }

    #[test]
    fn strips_string_contents_but_keeps_the_quotes() {
        // The exact false positive this exists for: an OpenZeppelin revert
        // string mentioning ERC20 and transfer.
        let line = r#"require(from != address(0), "ERC20: transfer from the zero address");"#;
        let stripped = code_only(line);
        assert!(!stripped.to_lowercase().contains("erc20"));
        assert!(!stripped.to_lowercase().contains("transfer"));
        assert!(stripped.contains(r#"require(from != address(0), "")"#));
    }

    #[test]
    fn handles_single_quotes_and_escapes() {
        assert!(!code_only(r#"revert('ERC20: nope');"#)
            .to_lowercase()
            .contains("erc20"));
        let escaped = code_only(r#"require(a, "say \"hi\" now") ;"#);
        assert!(
            !escaped.contains("hi"),
            "escaped quotes must not end the literal early: {escaped}"
        );
    }

    #[test]
    fn a_slash_inside_a_string_is_not_a_comment() {
        let line = r#"string memory u = "https://example.com"; uint x = 1;"#;
        let stripped = code_only(line);
        assert!(stripped.contains("uint x = 1;"), "got: {stripped}");
        assert!(!stripped.contains("example.com"));
    }

    #[test]
    fn strips_block_comments_but_preserves_line_numbers() {
        let src = "line1\n/* commented\n   balanceOf price\n*/\nline5";
        let stripped = strip_block_comments(src);
        assert_eq!(stripped.lines().count(), 5, "line numbering must survive");
        assert!(!stripped.contains("balanceOf"));
        assert!(stripped.contains("line1") && stripped.contains("line5"));
    }

    #[test]
    fn enclosing_function_body_stops_at_the_closing_brace() {
        let src = "function a() {\n  x = 1;\n}\nfunction getPrice() {\n  return r1 / r0;\n}";
        let body = enclosing_function_body(src, 0);
        assert!(body.contains("x = 1"));
        assert!(
            !body.contains("getPrice"),
            "must not bleed into the next function"
        );
    }

    #[test]
    fn restore_snippets_puts_the_original_text_back() {
        let src = "a\nrequire(x, \"ERC20: nope\");\nc";
        let n = Normalized::new(src);
        assert!(!n.code.contains("ERC20"));
        let mut f = vec![truent_core::Finding::new(
            "t".into(),
            truent_core::Severity::Low,
            "f".into(),
            2,
            0,
            "m".into(),
            "stripped".into(),
        )];
        n.restore_snippets(&mut f);
        assert_eq!(f[0].snippet, "require(x, \"ERC20: nope\");");
    }

    #[test]
    fn code_lines_is_index_stable() {
        let src = "a\n// b\nc";
        let lines = code_lines(src);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].trim(), "a");
        assert_eq!(lines[1].trim(), "");
        assert_eq!(lines[2].trim(), "c");
    }
}
