#!/usr/bin/env python3
"""Convert `truent scan --output json` into SARIF 2.1.0.

SARIF lets Truent findings appear inline on the PR diff and in GitHub's
Security tab — deterministic results a developer sees without running
anything. Reads scan JSON on stdin (or argv[1]), writes SARIF to stdout
(or argv[2]).

Pure standard library. Never raises on a malformed/empty report — emits a
valid empty SARIF run so the CI step stays green rather than erroring on the
conversion itself.
"""
import json
import sys

SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def load(src):
    try:
        raw = open(src).read() if src not in (None, "-") else sys.stdin.read()
        return json.loads(raw)
    except Exception:
        return {}


def split_location(loc):
    """`path/to/File.sol:12` -> ('path/to/File.sol', 12). Robust to missing line."""
    if not isinstance(loc, str) or not loc:
        return ("unknown", 1)
    # rsplit once so Windows drive letters / colons in paths don't break it.
    if ":" in loc:
        path, _, line = loc.rpartition(":")
        if path and line.isdigit():
            return (path, max(1, int(line)))
    return (loc, 1)


def to_sarif(report):
    violations = report.get("violations", []) if isinstance(report, dict) else []

    rules = {}
    results = []
    for v in violations:
        rule_id = str(v.get("invariant_id") or v.get("title") or "truent-finding")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": str(v.get("title") or rule_id),
                "shortDescription": {"text": str(v.get("title") or rule_id)},
                "helpUri": str(v.get("reference") or "https://github.com/Emmyhack/Truent"),
                "properties": {"cwe": str(v.get("cwe") or "")},
            }
        path, line = split_location(str(v.get("location") or ""))
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF.get(str(v.get("severity", "")).lower(), "warning"),
            "message": {"text": str(v.get("message") or v.get("title") or rule_id)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line},
                }
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Truent",
                    "informationUri": "https://github.com/Emmyhack/Truent",
                    "version": str(report.get("version") or "0.0.0") if isinstance(report, dict) else "0.0.0",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "-"
    dst = sys.argv[2] if len(sys.argv) > 2 else "-"
    sarif = to_sarif(load(src))
    out = json.dumps(sarif, indent=2)
    if dst in (None, "-"):
        print(out)
    else:
        open(dst, "w").write(out)


if __name__ == "__main__":
    main()
