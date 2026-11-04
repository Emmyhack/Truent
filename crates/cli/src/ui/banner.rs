//! Banner component for Truent CLI introduction.

use crate::ui::constants::{color_dim, color_header};
use crate::ui::utils::is_tty;

/// Render the Truent banner.
///
/// Displays the ASCII art logo and version information.
/// Only shown on interactive TTY; returns empty string for piped output.
///
/// # Arguments
/// * `version` - The version string to display
///
/// # Returns
/// The formatted banner as a string, or empty string if not a TTY.
pub fn render_banner(version: &str) -> String {
    if !is_tty() {
        return String::new();
    }

    let logo = r#"  ████████╗██████╗ ██╗   ██╗███████╗███╗   ██╗████████╗
  ╚══██╔══╝██╔══██╗██║   ██║██╔════╝████╗  ██║╚══██╔══╝
     ██║   ██████╔╝██║   ██║█████╗  ██╔██╗ ██║   ██║
     ██║   ██╔══██╗██║   ██║██╔══╝  ██║╚██╗██║   ██║
     ██║   ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║
     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝"#;

    let colored_logo = logo
        .lines()
        .map(color_header)
        .collect::<Vec<_>>()
        .join("\n");

    let subtitle = format!(
        "  Truent: Multi-chain Smart Contract Invariant Checker  ·  v{}",
        version
    );
    let colored_subtitle = color_dim(&subtitle);

    format!("{}\n{}\n", colored_logo, colored_subtitle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_banner_contains_expected_strings() {
        let banner = render_banner("0.1.1");
        if !banner.is_empty() {
            // If TTY, check that it contains expected parts
            assert!(banner.contains("Truent") || banner.is_empty());
            assert!(banner.contains("0.1.1") || banner.is_empty());
        }
    }

    #[test]
    fn test_banner_logo_structure() {
        let banner = render_banner("0.1.0");
        // Banner should either be empty (non-TTY) or contain the logo
        if !banner.is_empty() {
            assert!(banner.contains("███"), "Banner should contain ASCII art");
        }
    }
}
