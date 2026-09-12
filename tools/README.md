# Truent tooling

Small scripts CI and contributors run. Each is deliberately one file with no
dependencies beyond the standard library (plus PyYAML for the skill validator).

## `validate_skills.py`

Validates the agent skills under `skills/` and keeps `skills/index.json` in
sync.

```bash
pip install pyyaml
python3 tools/validate_skills.py           # validate
python3 tools/validate_skills.py --write   # regenerate the index
python3 tools/validate_skills.py --check   # fail if the index is stale
```

Enforces the things that break a skill silently: frontmatter that is not valid
YAML, a `name` that does not match its directory (which makes the skill
uninstallable), a description that never says *when* to use the skill (so an
agent never selects it), `metadata.version` drifting from the sidecar `VERSION`
file, and `$SKILL_DIR/...` paths that do not exist.

Frontmatter is parsed with PyYAML, never a regex — a regex that stops at the
first newline silently truncates multi-line descriptions, and nothing errors.

## `audit_advisories.py`

Cross-references `Cargo.lock` against the [RustSec advisory
database](https://github.com/RustSec/advisory-db).

`cargo audit` is the canonical tool and is what CI runs. This is an **offline
fallback** for environments where installing it is impractical — its build
pulls `gix` and a large dependency tree, which fails on slow or restricted
networks.

```bash
git clone --depth 1 https://github.com/RustSec/advisory-db /tmp/advisory-db
python3 tools/audit_advisories.py Cargo.lock /tmp/advisory-db
```

Exits 1 on a vulnerability, 0 otherwise. Advisories marked `informational`
(unmaintained, unsound, notice) are reported as warnings and do not affect the
exit status, matching cargo-audit's default.
