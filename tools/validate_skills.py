#!/usr/bin/env python3
"""Validate Truent's agent skills and keep skills/index.json in sync.

Truent ships six skills, not eight hundred, so this is deliberately one small
file rather than a suite of linters. What it does enforce is the set of things
that actually break a skill silently:

  * frontmatter that is not valid YAML, or that a regex "parser" would
    mis-read (multi-line descriptions are the classic case — a regex that
    stops at the first newline truncates them, and nothing errors);
  * `name` not matching the directory, which makes a skill uninstallable on
    agentskills.io-compatible platforms;
  * a description that does not say *when* to use the skill, so the agent
    never selects it;
  * frontmatter `metadata.version` drifting from the sidecar VERSION file;
  * a stale index.json.

Usage:
    python3 tools/validate_skills.py              # validate
    python3 tools/validate_skills.py --write      # validate + regenerate index
    python3 tools/validate_skills.py --check      # validate + fail if index stale
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
INDEX_PATH = SKILLS_DIR / "index.json"

# agentskills.io: 1-64 chars, lowercase alphanumeric, single hyphens.
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MAX_DESCRIPTION = 1024
MIN_DESCRIPTION = 50

# A description must say what the skill does AND when to reach for it.
# Without the second half an agent has no basis to select it over a sibling.
TRIGGER_HINTS = ("use when", "triggers on", "use this when", "reach for")


def load_frontmatter(path: Path) -> dict:
    """Parse SKILL.md frontmatter with a real YAML parser.

    Never regex this. A regex that grabs `^description:\\s*(.+)$` silently
    truncates every folded or multi-line description to its first line, and
    the failure is invisible until an agent stops selecting the skill.
    """
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not match:
        raise ValueError("missing or malformed YAML frontmatter")
    data = yaml.safe_load(match.group(1))
    if not isinstance(data, dict):
        raise ValueError("frontmatter is not a YAML mapping")
    return data


def validate(skill_dir: Path) -> list[str]:
    """Return a list of problems with one skill. Empty means valid."""
    errors: list[str] = []
    skill_md = skill_dir / "SKILL.md"

    if not skill_md.is_file():
        return [f"{skill_dir.name}: no SKILL.md"]

    try:
        fm = load_frontmatter(skill_md)
    except (ValueError, yaml.YAMLError) as exc:
        return [f"{skill_dir.name}: {exc}"]

    def err(msg: str) -> None:
        errors.append(f"{skill_dir.name}: {msg}")

    # --- name -------------------------------------------------------------
    name = fm.get("name")
    if not name:
        err("frontmatter has no `name`")
    else:
        if not NAME_RE.match(name):
            err(f"name {name!r} is not kebab-case alphanumeric")
        if len(name) > 64:
            err(f"name is {len(name)} chars (max 64)")
        if name != skill_dir.name:
            # Platforms resolve a skill by directory; a mismatch means the
            # skill loads under a name nothing references.
            err(f"name {name!r} does not match directory {skill_dir.name!r}")

    # --- description ------------------------------------------------------
    desc = fm.get("description")
    if not desc:
        err("frontmatter has no `description`")
    elif not isinstance(desc, str):
        err("description must be a string")
    else:
        if len(desc) < MIN_DESCRIPTION:
            err(f"description is {len(desc)} chars (min {MIN_DESCRIPTION})")
        if len(desc) > MAX_DESCRIPTION:
            err(f"description is {len(desc)} chars (max {MAX_DESCRIPTION})")
        if "<" in desc or ">" in desc:
            err("description contains angle brackets (prompt-injection surface)")
        if not any(hint in desc.lower() for hint in TRIGGER_HINTS):
            err(
                "description never says when to use the skill — add "
                "'Triggers on ...' or 'Use when ...'"
            )

    # --- license ----------------------------------------------------------
    if fm.get("license") != "MIT":
        err(f"license is {fm.get('license')!r}, expected 'MIT' to match the repo")

    # --- metadata ---------------------------------------------------------
    meta = fm.get("metadata")
    if not isinstance(meta, dict):
        err("frontmatter has no `metadata` mapping")
        return errors

    for field in ("version", "author", "domain", "subdomain", "tags"):
        if field not in meta:
            err(f"metadata is missing `{field}`")

    tags = meta.get("tags")
    if not isinstance(tags, list) or len(tags) < 2:
        err("metadata.tags must be a list of at least 2 tags")

    # --- version agreement with the sidecar file --------------------------
    version_file = skill_dir / "VERSION"
    if version_file.is_file():
        sidecar = version_file.read_text(encoding="utf-8").strip()
        declared = str(meta.get("version", "")).strip()
        if sidecar != declared:
            err(f"VERSION file says {sidecar!r}, frontmatter says {declared!r}")

    # --- referenced files exist -------------------------------------------
    body = skill_md.read_text(encoding="utf-8")
    for ref in re.findall(r"\$SKILL_DIR/([A-Za-z0-9_./-]+)", body):
        if not (skill_dir / ref).exists():
            err(f"references $SKILL_DIR/{ref}, which does not exist")

    return errors


def build_index(skill_dirs: list[Path]) -> dict:
    """Machine-readable catalogue of the skills, for discovery tooling."""
    entries = []
    for d in skill_dirs:
        fm = load_frontmatter(d / "SKILL.md")
        meta = fm.get("metadata", {})
        entries.append(
            {
                "name": fm["name"],
                "description": fm["description"],
                "version": str(meta.get("version", "")),
                "domain": meta.get("domain"),
                "subdomain": meta.get("subdomain"),
                "chains": meta.get("chains", []),
                "tags": meta.get("tags", []),
                "path": f"skills/{d.name}",
            }
        )
    return {
        "version": "1.0.0",
        "repository": "https://github.com/geekstrancend/Truent",
        "domain": "smart-contract-security",
        "total_skills": len(entries),
        "skills": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true", help="regenerate skills/index.json")
    group.add_argument("--check", action="store_true", help="fail if index.json is stale")
    args = parser.parse_args()

    skill_dirs = sorted(d for d in SKILLS_DIR.iterdir() if (d / "SKILL.md").is_file())
    if not skill_dirs:
        print("error: no skills found under skills/", file=sys.stderr)
        return 1

    errors: list[str] = []
    for d in skill_dirs:
        errors.extend(validate(d))

    if errors:
        print(f"✗ {len(errors)} problem(s) in {len(skill_dirs)} skill(s):\n", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    print(f"✓ {len(skill_dirs)} skill(s) valid: {', '.join(d.name for d in skill_dirs)}")

    index = build_index(skill_dirs)
    rendered = json.dumps(index, indent=2, ensure_ascii=False) + "\n"

    if args.write:
        INDEX_PATH.write_text(rendered, encoding="utf-8")
        print(f"✓ wrote {INDEX_PATH.relative_to(ROOT)} ({index['total_skills']} skills)")
    elif args.check:
        current = INDEX_PATH.read_text(encoding="utf-8") if INDEX_PATH.is_file() else ""
        if current != rendered:
            print(
                "✗ skills/index.json is stale — run: "
                "python3 tools/validate_skills.py --write",
                file=sys.stderr,
            )
            return 1
        print("✓ skills/index.json is current")

    return 0


if __name__ == "__main__":
    sys.exit(main())
