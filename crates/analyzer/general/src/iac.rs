//! Infrastructure-as-Code misconfiguration: Terraform (HCL) and CloudFormation.
//!
//! Each check names a configuration that is dangerous *as written* —
//! a security group open to the world on an administrative port, a bucket
//! with a public ACL, a database reachable from the internet, an IAM policy
//! granting every action on every resource, storage with encryption switched
//! off. Port 443 open to `0.0.0.0/0` is a web server and is not reported.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use crate::finding;
use crate::text::strip_hash_comment;

lazy_static! {
    static ref TF_CIDR_ANY: Regex = Regex::new(r#"(?i)(cidr_blocks|ipv6_cidr_blocks|source_ranges|cidr)\s*=\s*\[?\s*"(0\.0\.0\.0/0|::/0)""#).unwrap();
    static ref TF_FROM_PORT: Regex = Regex::new(r"(?i)\bfrom_port\s*=\s*(\d+)").unwrap();
    static ref TF_TO_PORT: Regex = Regex::new(r"(?i)\bto_port\s*=\s*(\d+)").unwrap();
    static ref TF_PUBLIC_ACL: Regex = Regex::new(r#"(?i)\bacl\s*=\s*"public-read(-write)?""#).unwrap();
    static ref TF_PUBLIC_BLOCK_OFF: Regex = Regex::new(r"(?i)\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false").unwrap();
    static ref TF_ALL_USERS: Regex = Regex::new(r#"(?i)"(allUsers|allAuthenticatedUsers)""#).unwrap();
    static ref TF_UNENCRYPTED: Regex = Regex::new(r"(?i)\b(encrypted|storage_encrypted|kms_key_id\s*=\s*null|encryption_enabled)\s*=\s*false").unwrap();
    static ref TF_PUBLIC_DB: Regex = Regex::new(r"(?i)\bpublicly_accessible\s*=\s*true").unwrap();
    static ref TF_PUBLIC_IP: Regex = Regex::new(r"(?i)\bassociate_public_ip_address\s*=\s*true").unwrap();

    static ref CFN_CIDR_ANY: Regex = Regex::new(r#"(?i)(CidrIp|CidrIpv6)\s*[:=]\s*["']?(0\.0\.0\.0/0|::/0)"#).unwrap();
    static ref CFN_FROM_PORT: Regex = Regex::new(r#"(?i)\bFromPort\s*[:=]\s*["']?(-?\d+)"#).unwrap();
    static ref CFN_TO_PORT: Regex = Regex::new(r#"(?i)\bToPort\s*[:=]\s*["']?(-?\d+)"#).unwrap();
    static ref CFN_PUBLIC_ACL: Regex = Regex::new(r#"(?i)\bAccessControl\s*[:=]\s*["']?Public(Read|ReadWrite)"#).unwrap();
    static ref CFN_PUBLIC_BLOCK_OFF: Regex = Regex::new(r#"(?i)\b(BlockPublicAcls|BlockPublicPolicy|IgnorePublicAcls|RestrictPublicBuckets)\s*[:=]\s*["']?false"#).unwrap();
    static ref CFN_UNENCRYPTED: Regex = Regex::new(r#"(?i)\b(Encrypted|StorageEncrypted)\s*[:=]\s*["']?false"#).unwrap();
    static ref CFN_PUBLIC_DB: Regex = Regex::new(r#"(?i)\bPubliclyAccessible\s*[:=]\s*["']?true"#).unwrap();
    static ref CFN_MARKER: Regex = Regex::new(r#"AWSTemplateFormatVersion|Type\s*[:=]\s*["']?AWS::"#).unwrap();

    /// IAM `Action: *` together with `Resource: *` — a wildcard policy.
    static ref IAM_ACTION_ALL: Regex = Regex::new(r#"(?i)["']?Action["']?\s*[:=]\s*\[?\s*["']\*["']"#).unwrap();
    static ref IAM_RESOURCE_ALL: Regex = Regex::new(r#"(?i)["']?Resource["']?\s*[:=]\s*\[?\s*["']\*["']"#).unwrap();
    static ref IAM_EFFECT_DENY: Regex = Regex::new(r#"(?i)["']?Effect["']?\s*[:=]\s*["']?Deny"#).unwrap();
}

/// Administrative and data-plane ports that must never face the internet.
const SENSITIVE_PORTS: &[u32] = &[
    22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5984, 6379, 7001, 8020, 9200, 9300,
    11211, 27017, 27018, 28017, 50070,
];

fn port_is_sensitive(from: Option<u32>, to: Option<u32>) -> bool {
    match (from, to) {
        (Some(f), Some(t)) => {
            (f == 0 && t == 0)
                || (f == 0 && t >= 65535)
                || (f == u32::MAX)
                || SENSITIVE_PORTS.iter().any(|p| *p >= f && *p <= t)
        }
        (Some(f), None) => f == 0 || SENSITIVE_PORTS.contains(&f),
        _ => true, // no port stated: the rule allows everything
    }
}

/// Find `from_port`/`to_port` in the lines just above `idx` (same block).
fn nearby_ports(
    lines: &[String],
    idx: usize,
    from_re: &Regex,
    to_re: &Regex,
) -> (Option<u32>, Option<u32>) {
    let lo = idx.saturating_sub(8);
    let mut from = None;
    let mut to = None;
    for l in lines[lo..=idx].iter().rev() {
        if from.is_none() {
            if let Some(c) = from_re.captures(l) {
                from = c[1]
                    .parse::<i64>()
                    .ok()
                    .map(|n| if n < 0 { u32::MAX } else { n as u32 });
            }
        }
        if to.is_none() {
            if let Some(c) = to_re.captures(l) {
                to = c[1]
                    .parse::<i64>()
                    .ok()
                    .map(|n| if n < 0 { 65535 } else { n as u32 });
            }
        }
        // Leaving the block.
        if l.trim().starts_with("resource ") || l.trim().starts_with("Type:") {
            break;
        }
    }
    (from, to)
}

fn iam_wildcard(lines: &[String], idx: usize) -> bool {
    // Action "*" here; Resource "*" within the same statement (±6 lines), not Deny.
    let lo = idx.saturating_sub(6);
    let hi = (idx + 6).min(lines.len() - 1);
    let window = &lines[lo..=hi];
    window.iter().any(|l| IAM_RESOURCE_ALL.is_match(l))
        && !window.iter().any(|l| IAM_EFFECT_DENY.is_match(l))
}

pub fn detect_terraform(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lines: Vec<String> = source.lines().map(strip_hash_comment).collect();
    for (idx, line) in lines.iter().enumerate() {
        if TF_CIDR_ANY.is_match(line) {
            let (from, to) = nearby_ports(&lines, idx, &TF_FROM_PORT, &TF_TO_PORT);
            if port_is_sensitive(from, to) {
                out.push(finding(
                    "gen_iac_open_ingress",
                    Severity::High,
                    file_path,
                    idx,
                    "Security rule admits the whole internet on an administrative or data port",
                    line,
                ));
            }
        }
        if TF_PUBLIC_ACL.is_match(line)
            || TF_PUBLIC_BLOCK_OFF.is_match(line)
            || TF_ALL_USERS.is_match(line)
        {
            out.push(finding(
                "gen_iac_public_storage",
                Severity::High,
                file_path,
                idx,
                "Storage is readable (or writable) by anyone on the internet",
                line,
            ));
        }
        if TF_UNENCRYPTED.is_match(line) {
            out.push(finding(
                "gen_iac_unencrypted_storage",
                Severity::Medium,
                file_path,
                idx,
                "Encryption at rest is explicitly disabled",
                line,
            ));
        }
        if TF_PUBLIC_DB.is_match(line) {
            out.push(finding(
                "gen_iac_public_database",
                Severity::High,
                file_path,
                idx,
                "Database instance is reachable from the public internet",
                line,
            ));
        }
        if IAM_ACTION_ALL.is_match(line) && iam_wildcard(&lines, idx) {
            out.push(finding(
                "gen_iac_wildcard_iam",
                Severity::High,
                file_path,
                idx,
                "IAM policy allows every action on every resource",
                line,
            ));
        }
    }
    out
}

pub fn detect_cloudformation(source: &str, file_path: &str) -> Vec<Finding> {
    if !CFN_MARKER.is_match(source) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let lines: Vec<String> = source.lines().map(strip_hash_comment).collect();
    for (idx, line) in lines.iter().enumerate() {
        if CFN_CIDR_ANY.is_match(line) {
            let (from, to) = nearby_ports(&lines, idx, &CFN_FROM_PORT, &CFN_TO_PORT);
            if port_is_sensitive(from, to) {
                out.push(finding(
                    "gen_iac_open_ingress",
                    Severity::High,
                    file_path,
                    idx,
                    "Security rule admits the whole internet on an administrative or data port",
                    line,
                ));
            }
        }
        if CFN_PUBLIC_ACL.is_match(line) || CFN_PUBLIC_BLOCK_OFF.is_match(line) {
            out.push(finding(
                "gen_iac_public_storage",
                Severity::High,
                file_path,
                idx,
                "Storage is readable (or writable) by anyone on the internet",
                line,
            ));
        }
        if CFN_UNENCRYPTED.is_match(line) {
            out.push(finding(
                "gen_iac_unencrypted_storage",
                Severity::Medium,
                file_path,
                idx,
                "Encryption at rest is explicitly disabled",
                line,
            ));
        }
        if CFN_PUBLIC_DB.is_match(line) {
            out.push(finding(
                "gen_iac_public_database",
                Severity::High,
                file_path,
                idx,
                "Database instance is reachable from the public internet",
                line,
            ));
        }
        if IAM_ACTION_ALL.is_match(line) && iam_wildcard(&lines, idx) {
            out.push(finding(
                "gen_iac_wildcard_iam",
                Severity::High,
                file_path,
                idx,
                "IAM policy allows every action on every resource",
                line,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ids(f: Vec<Finding>) -> Vec<String> {
        f.into_iter().map(|x| x.invariant_id).collect()
    }

    #[test]
    fn ssh_to_the_world_is_flagged_but_https_is_not() {
        let bad = "resource \"aws_security_group_rule\" \"ssh\" {\n  type = \"ingress\"\n  from_port = 22\n  to_port = 22\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n";
        assert_eq!(
            ids(detect_terraform(bad, "sg.tf")),
            vec!["gen_iac_open_ingress"]
        );
        let ok = "resource \"aws_security_group_rule\" \"https\" {\n  type = \"ingress\"\n  from_port = 443\n  to_port = 443\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n";
        assert!(detect_terraform(ok, "sg.tf").is_empty());
        let internal = "resource \"aws_security_group_rule\" \"ssh\" {\n  from_port = 22\n  to_port = 22\n  cidr_blocks = [\"10.0.0.0/8\"]\n}\n";
        assert!(detect_terraform(internal, "sg.tf").is_empty());
    }

    #[test]
    fn public_bucket_unencrypted_db_and_wildcard_iam() {
        let tf = "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\nresource \"aws_db_instance\" \"d\" {\n  storage_encrypted = false\n  publicly_accessible = true\n}\nresource \"aws_iam_policy\" \"p\" {\n  policy = jsonencode({ Statement = [{ Effect = \"Allow\", Action = \"*\", Resource = \"*\" }] })\n}\n";
        let got = ids(detect_terraform(tf, "main.tf"));
        for e in [
            "gen_iac_public_storage",
            "gen_iac_unencrypted_storage",
            "gen_iac_public_database",
            "gen_iac_wildcard_iam",
        ] {
            assert!(got.contains(&e.to_string()), "{e} missing from {got:?}");
        }
    }

    #[test]
    fn scoped_iam_and_deny_wildcards_are_fine() {
        let tf = "policy = jsonencode({ Statement = [{ Effect = \"Allow\", Action = [\"s3:GetObject\"], Resource = \"arn:aws:s3:::b/*\" }] })\n";
        assert!(detect_terraform(tf, "p.tf").is_empty());
        let deny = "Statement = [{ Effect = \"Deny\", Action = \"*\", Resource = \"*\" }]\n";
        assert!(detect_terraform(deny, "p.tf").is_empty());
    }

    #[test]
    fn cloudformation_needs_its_marker() {
        let cfn = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  DB:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      PubliclyAccessible: true\n      StorageEncrypted: false\n";
        assert_eq!(detect_cloudformation(cfn, "t.yaml").len(), 2);
        assert!(detect_cloudformation("PubliclyAccessible: true\n", "notes.yaml").is_empty());
    }
}
