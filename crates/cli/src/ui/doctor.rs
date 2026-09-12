//! Doctor health check component.

use crate::ui::constants::{color_failure, color_label, color_success, ICON_CRITICAL, ICON_PASS};
use crate::ui::utils::{divider, term_width};
use serde::Serialize;

/// Represents a component health check result.
#[derive(Debug, Clone, Serialize)]
pub struct HealthCheck {
    /// Name of the component
    pub component: String,
    /// Whether the check passed
    pub passed: bool,
    /// Status message
    pub message: String,
}

/// Render the doctor health check results.
///
/// Displays a list of health checks with pass/fail status.
///
/// # Arguments
/// * `checks` - List of health checks to display
///
/// # Returns
/// The formatted doctor output
pub fn render_doctor_results(checks: &[HealthCheck]) -> String {
    let width = term_width();
    let mut output = String::new();

    // Top divider
    output.push_str(&format!("{}\n", divider(width)));
    output.push_str(&format!(
        "{}  {}  Component Health Check\n",
        color_label("Truent Doctor"),
        "·"
    ));
    output.push_str(&format!("{}\n", divider(width)));
    output.push('\n');

    // Health checks.
    //
    // The component column is padded to the widest name rather than by a fixed
    // run of spaces: the literal-padding version left the message column
    // ragged, since component names differ in length.
    let name_width = checks
        .iter()
        .map(|c| c.component.chars().count())
        .max()
        .unwrap_or(0);

    let mut all_passed = true;
    for check in checks {
        if check.passed {
            output.push_str(&format!(
                "{}  {:<name_width$}  {}\n",
                color_success(ICON_PASS),
                check.component,
                check.message
            ));
        } else {
            output.push_str(&format!(
                "{}  {:<name_width$}  {}\n",
                color_failure(ICON_CRITICAL),
                check.component,
                check.message
            ));
            all_passed = false;
        }
    }

    output.push('\n');
    output.push_str(&format!("{}\n", divider(width)));

    // Summary line
    if all_passed {
        output.push_str(&format!(
            "{} All {} components healthy. Truent is ready.\n",
            color_success(ICON_PASS),
            checks.len()
        ));
    } else {
        let failed_count = checks.iter().filter(|c| !c.passed).count();
        output.push_str(&format!(
            "{} {} components have issues.\n",
            color_failure(ICON_CRITICAL),
            failed_count
        ));
    }

    output.push_str(&format!("{}\n", divider(width)));

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doctor_all_passed() {
        let checks = vec![
            HealthCheck {
                component: "truent-core".to_string(),
                passed: true,
                message: "Initialized successfully".to_string(),
            },
            HealthCheck {
                component: "EVM analyzer".to_string(),
                passed: true,
                message: "Initialized successfully".to_string(),
            },
        ];

        let output = render_doctor_results(&checks);
        assert!(output.contains("Truent Doctor"));
        assert!(output.contains("truent-core"));
        assert!(output.contains("EVM analyzer"));
        assert!(output.contains("All 2 components healthy"));
    }

    #[test]
    fn test_doctor_with_failures() {
        let checks = vec![
            HealthCheck {
                component: "truent-core".to_string(),
                passed: true,
                message: "OK".to_string(),
            },
            HealthCheck {
                component: "DSL parser".to_string(),
                passed: false,
                message: "Failed to initialize".to_string(),
            },
        ];

        let output = render_doctor_results(&checks);
        assert!(output.contains("1 components have issues"));
    }
}
