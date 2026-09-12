#!/usr/bin/env python3
"""Cross-reference Cargo.lock against the RustSec advisory database.

`cargo audit` is the canonical tool and is what CI runs. This is an offline
fallback for environments where installing it is impractical — its build pulls
`gix` and a large dependency tree, which fails on slow or restricted networks.

Same inputs, same source, same rule: a locked package is affected by an
advisory when its version satisfies neither a `patched` nor an `unaffected`
range. Advisories carrying `informational` (unmaintained, unsound, notice) are
reported as warnings and do not affect the exit status, matching cargo-audit's
default.

Usage:
    git clone --depth 1 https://github.com/RustSec/advisory-db /tmp/advisory-db
    python3 tools/audit_advisories.py Cargo.lock /tmp/advisory-db

Exit status: 1 if any vulnerability is found, 0 otherwise.
"""
import re, sys, tomllib
from pathlib import Path

lock_path, db = Path(sys.argv[1]), Path(sys.argv[2])

def parse_ver(v):
    # Cargo.lock versions are clean semver; strip build metadata like
    # "0.9.34+deprecated" and any pre-release tag for ordering purposes.
    core = v.split('+')[0]
    pre = None
    if '-' in core:
        core, pre = core.split('-', 1)
    parts = [int(x) for x in core.split('.')]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts), pre

def cmp_ver(a, b):
    (ai, ap), (bi, bp) = parse_ver(a), parse_ver(b)
    if ai != bi:
        return -1 if ai < bi else 1
    # A pre-release sorts before its release.
    if ap == bp:
        return 0
    if ap is None:
        return 1
    if bp is None:
        return -1
    return -1 if ap < bp else 1

def matches(version, req):
    """Does `version` satisfy one comma-separated semver requirement string?"""
    for part in req.split(','):
        part = part.strip()
        m = re.match(r'^(>=|<=|>|<|\^|=)?\s*v?([0-9][0-9A-Za-z.\-+]*)$', part)
        if not m:
            return False
        op, target = m.group(1) or '^', m.group(2)
        c = cmp_ver(version, target)
        if op == '>=' and not c >= 0: return False
        if op == '>'  and not c >  0: return False
        if op == '<=' and not c <= 0: return False
        if op == '<'  and not c <  0: return False
        if op == '='  and c != 0:     return False
        if op == '^':
            lo, _ = parse_ver(target)
            v, _ = parse_ver(version)
            if c < 0: return False
            # caret: same leftmost non-zero component
            if lo[0] != 0:
                if v[0] != lo[0]: return False
            elif lo[1] != 0:
                if v[0] != 0 or v[1] != lo[1]: return False
            else:
                if v[0] != 0 or v[1] != 0 or v[2] != lo[2]: return False
    return True

packages = {}
for block in re.findall(r'\[\[package\]\]\n(.*?)(?=\n\[\[|\n\Z)', lock_path.read_text(), re.S):
    name = re.search(r'^name = "(.+)"$', block, re.M)
    ver  = re.search(r'^version = "(.+)"$', block, re.M)
    if name and ver:
        packages.setdefault(name.group(1), set()).add(ver.group(1))

vulns, warns = [], []
for name, versions in sorted(packages.items()):
    adv_dir = db / 'crates' / name
    if not adv_dir.is_dir():
        continue
    for f in sorted(adv_dir.glob('RUSTSEC-*.md')):
        text = f.read_text()
        m = re.search(r'```toml\n(.*?)```', text, re.S)
        if not m:
            continue
        meta = tomllib.loads(m.group(1))
        adv, vers = meta.get('advisory', {}), meta.get('versions', {})
        patched    = vers.get('patched', [])
        unaffected = vers.get('unaffected', [])
        for v in sorted(versions):
            if any(matches(v, r) for r in patched):      continue
            if any(matches(v, r) for r in unaffected):   continue
            row = (name, v, adv.get('id'), adv.get('informational'), adv.get('title') or text.split('\n# ',1)[-1].split('\n')[0])
            (warns if adv.get('informational') else vulns).append(row)

print(f"Scanned {len(packages)} locked packages against {len(list((db/'crates').iterdir()))} advisory sets\n")
if vulns:
    print(f"VULNERABILITIES ({len(vulns)}):")
    for n, v, i, _, t in vulns:
        print(f"  {i}  {n} {v}\n      {t}")
else:
    print("Vulnerabilities: none")
print()
if warns:
    print(f"WARNINGS ({len(warns)}):")
    for n, v, i, kind, t in warns:
        print(f"  {i}  {n} {v}  [{kind}]\n      {t}")
else:
    print("Warnings (unmaintained/unsound/notice): none")

sys.exit(1 if vulns else 0)
