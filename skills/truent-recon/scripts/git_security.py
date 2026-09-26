#!/usr/bin/env python3
# Adapted from pashov/skills x-ray/scripts/analyze_git_security.py (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent engine integration, multi-chain.
"""git_security.py — mine a repository's git history for security signal.

Merges Truent's original file-level history miner (fix-prone files, churn
hotspots, late changes, vendor drift, tech-debt markers) with pashov's
commit-level analysis (intent + structural diff scoring, dangerous-area
evolution, developer patterns, repo shape). Multi-language: Solidity, Vyper,
Rust (Anchor / native Solana / Soroban), Move (Aptos / Sui), Cairo.

Pure standard library. Shells out to `git`. Degrades gracefully: a non-repo,
a shallow clone or an empty history still yields a valid JSON document with
empty history sections and a `notes` entry explaining why — never an error.

Usage:
    python3 git_security.py --repo . --src-dir auto --json recon/git-security.json
    python3 git_security.py --repo . --src-dir contracts --days 30 --limit 10

OUTPUT JSON KEYS (top level)
    meta                    repo, src_dir, generated_at, git_head, git_branch,
                            is_git_repo, is_shallow, chains_detected,
                            total_commits, total_source_files, analysis_time_ms
    repo_shape              classification (normal_dev | squashed_import | empty),
                            total_commits, source_touching_commits, bulk_import_sha,
                            date_spread_days, first/last_commit_date, contributors,
                            top_author_share, merge_commits, signals[]
    fix_candidates          COMMIT-level: top-N commits scored for security-fix
                            likelihood (intent + structural diff + domain overlap +
                            shape). Each: sha, full_sha, date, author, subject,
                            score, reasons[], source_files_touched[], test_changed,
                            lines_changed. Score >= 5 is worth a look, >= 10 a diff.
    fix_prone_files         FILE-level: files most often touched by fix-scored
                            commits. Each: file, fix_commits, fix_score_sum,
                            total_changes, fix_ratio.
    churn_hotspots          FILE-level: most-modified source files. Each: file,
                            changes, fix_commits, fix_ratio, last_touched.
    dangerous_area_changes  {area: {commit_count, files[], commits[], truncated?}}
                            areas: access_control, fund_flows, oracle_price,
                            liquidation, signatures, state_machines, upgrade_paths
    late_changes            window_days, cutoff_date, latest_commit_date,
                            late_commits[] (sha, date, author, subject, source_files,
                            security_relevant_files, test_changed, lines_changed),
                            source_without_test_count, total_late_source_commits
    forked_deps             detected_libs[] (name, path, known_upstream, is_submodule,
                            is_internalized, source_file_count, pragma_versions,
                            notes[]), removed_submodules[],
                            locally_modified_vendor_files[] (file, dep_dir)
    tech_debt               total_count, items[] (file, line, type, text,
                            blame_author, blame_date), files_with_debt, capped
    dev_patterns            test_co_change_rate, fix_without_test_rate,
                            avg_commit_size, avg_commit_size_note,
                            single_developer_pct, top_contributor,
                            contributor_breakdown[]
    notes[]                 degradation notes (shallow clone, not a repo, ...)
    how_to_use              one paragraph on ranking audit attention
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


# ═══════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════

@dataclass
class FileChange:
    path: str
    added: int
    deleted: int
    is_source: bool = False
    is_test: bool = False


@dataclass
class Commit:
    sha: str
    short_sha: str
    date: str
    author: str
    subject: str
    files: list[FileChange] = field(default_factory=list)
    is_merge: bool = False

    @property
    def source_files(self) -> list[FileChange]:
        return [f for f in self.files if f.is_source]

    @property
    def test_files(self) -> list[FileChange]:
        return [f for f in self.files if f.is_test]

    @property
    def total_churn(self) -> int:
        return sum(f.added + f.deleted for f in self.files)

    @property
    def source_churn(self) -> int:
        return sum(f.added + f.deleted for f in self.files if f.is_source)


# ═══════════════════════════════════════════════════════════════
# LANGUAGE / PATH CLASSIFICATION (multi-chain)
# ═══════════════════════════════════════════════════════════════

SRC_EXT = (".sol", ".vy", ".rs", ".move", ".cairo")
TEST_HINTS = ("test/", "tests/", "spec/", ".t.sol", ".spec.", "__tests__", "fuzz/",
              "_test.move", "_tests.move", "trident-tests/")
EXCLUDE_DIRS = (
    "/lib/", "/node_modules/", "/forge-std/", "/out/", "/broadcast/",
    "/artifacts/", "/cache/", "/target/", "/build/", "/dist/", "/recon/",
)
WALK_PRUNE = {
    "test", "tests", "lib", "node_modules", "forge-std", "out", "broadcast",
    "artifacts", "cache", "script", "target", "build", "dist", ".git", "recon",
    "mocks", "mock",
}


def classify_path(path: str, src_dir: str) -> tuple[bool, bool]:
    """Classify a path as (is_source, is_test)."""
    lowered = path.lower()
    is_test = any(hint in lowered for hint in TEST_HINTS)
    if not path.endswith(SRC_EXT):
        return False, is_test
    if any(exc in f"/{path}" for exc in EXCLUDE_DIRS):
        return False, is_test
    in_src = src_dir in ("", ".", "./") or path.startswith(src_dir)
    return (in_src and not is_test), is_test


def find_source_files(repo: str, src_dir: str) -> list[str]:
    """Walk the filesystem for current source files under src_dir."""
    result: list[str] = []
    base = repo if src_dir in ("", ".", "./") else os.path.join(repo, src_dir)
    if not os.path.isdir(base):
        return result
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in WALK_PRUNE]
        for fname in files:
            if fname.endswith(SRC_EXT):
                rel = os.path.relpath(os.path.join(root, fname), repo)
                if not any(h in rel.lower() for h in TEST_HINTS):
                    result.append(rel)
    return sorted(result)


def detect_chains(repo: str, source_files: list[str]) -> list[str]:
    """Best-effort chain detection from file extensions and content markers."""
    chains: set[str] = set()
    for rel in source_files:
        if rel.endswith((".sol", ".vy")):
            chains.add("evm")
        elif rel.endswith(".move"):
            chains.add("move")
        elif rel.endswith(".cairo"):
            chains.add("starknet")
        elif rel.endswith(".rs"):
            head = _read_file_safe(os.path.join(repo, rel))[:20000]
            if "soroban_sdk" in head:
                chains.add("soroban")
            elif re.search(r"#\[program\]|anchor_lang|solana_program|entrypoint!", head):
                chains.add("solana")
    return sorted(chains)


def detect_src_dir(repo: str) -> str:
    """Auto-detect the source directory (foundry.toml `src`, then conventions)."""
    toml_path = os.path.join(repo, "foundry.toml")
    if os.path.isfile(toml_path):
        try:
            with open(toml_path, "r", errors="replace") as f:
                for line in f:
                    m = re.match(r'\s*src\s*=\s*["\'](.+?)["\']', line)
                    if m:
                        return m.group(1).rstrip("/") + "/"
        except OSError:
            pass
    for candidate in ("contracts/", "src/", "programs/", "sources/"):
        if os.path.isdir(os.path.join(repo, candidate)):
            return candidate
    return "./"


# ═══════════════════════════════════════════════════════════════
# COMMIT CLASSIFICATION — Intent + Structural Impact model
#
#   Phase 1: classify the commit MESSAGE into one intent category
#            (first match wins from priority-ordered rules)
#   Phase 2: analyse the DIFF for directional code changes
#            (net addition of guards, removal of code paths, ...)
#   Final score = intent_base + structural_impact + shape_modifier
#                 + security_domain_overlap
# ═══════════════════════════════════════════════════════════════

_INTENT_RULES: list[tuple[str, list[re.Pattern], int, str]] = [
    ("security_explicit", [
        re.compile(r"\b(security|vulnerab|exploit|attack|CVE-\d|audit)\b", re.I),
        re.compile(r"\b(reentran|overflow|underflow|front.?run|malleab|replay)\w*", re.I),
    ], 8, "explicit security language"),
    ("urgent_fix", [
        re.compile(r"\b(hotfix|emergency|critical|IMPT)\b", re.I),
    ], 6, "urgent/critical fix"),
    ("bug_fix", [
        re.compile(r"\bfix(es|ed)?\b", re.I),
        re.compile(r"\bbug\b", re.I),
        re.compile(r"\bpatch\b", re.I),
        re.compile(r"\bbroken\b", re.I),
    ], 4, "bug fix"),
    ("hardening", [
        re.compile(r"\b(harden|mitigat|protect|restrict|sanitiz|validat)\w*", re.I),
    ], 2, "hardening/validation"),
    ("feature", [
        re.compile(r"^\s*(feat|add|implement|introduce|support)\b", re.I),
    ], -1, "feature addition"),
    ("maintenance", [
        re.compile(r"^\s*(docs?|chore|ci|test|style|build)\s*:", re.I),
        re.compile(r"\b(readme|typo|format|lint|rename|refactor|cleanup|comment)\b", re.I),
        re.compile(r"\bchange\s+\w+\s+to\s+\w+\b", re.I),
    ], -3, "maintenance/cosmetic"),
]

_TOPIC_TAGS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(oracle|price|liquidat|slippage|MEV|pyth|switchboard|chainlink)\w*", re.I),
     "involves oracle/pricing"),
    (re.compile(r"\b(reentran|overflow|underflow|front.?run)\w*", re.I),
     "involves known vulnerability pattern"),
    (re.compile(r"\b(ecrecover|permit|signature|nonce|signer|ed25519|secp256k1)\w*", re.I),
     "involves signatures/auth"),
    (re.compile(r"\b(upgrade|proxy|migrat|authority|admin|owner|cap(ability)?)\w*", re.I),
     "involves admin/upgrade authority"),
    (re.compile(r"\b(rent|lamport|pda|seed|bump|cpi|sysvar)\w*", re.I),
     "involves Solana account model"),
    (re.compile(r"\b(ttl|storage|require_auth|instance|persistent|temporary)\w*", re.I),
     "involves Soroban storage/auth"),
]


def _classify_intent(subject: str) -> tuple[int, list[str]]:
    primary_score = 0
    reasons: list[str] = []
    primary_cat = None
    for cat, patterns, base_score, reason in _INTENT_RULES:
        if any(p.search(subject) for p in patterns):
            primary_score = base_score
            reasons.append(reason)
            primary_cat = cat
            break
    if primary_cat is None:
        reasons.append("unclassified")
    if primary_score >= 0:
        for pattern, tag_reason in _TOPIC_TAGS:
            if pattern.search(subject) and tag_reason not in reasons:
                if primary_cat != "security_explicit" or "vulnerability pattern" not in tag_reason:
                    primary_score += 2
                    reasons.append(tag_reason)
    return primary_score, reasons


# Phase 2: structural diff analysis, multi-language constructs.
_GUARD_ADD = re.compile(
    r"^\+[^+].*\b(require|revert|assert|require!|assert!|ensure!|abort|require_auth|checked_(add|sub|mul|div))\b", re.M)
_GUARD_REM = re.compile(
    r"^-[^-].*\b(require|revert|assert|require!|assert!|ensure!|abort|require_auth|checked_(add|sub|mul|div))\b", re.M)
_MOD_ADD = re.compile(
    r"^\+[^+].*(\b(onlyOwner|onlyRole|onlyAdmin|nonReentrant|whenNotPaused|initializer|modifier\s+only)\b"
    r"|Signer<|has_one\s*=|constraint\s*=|#\[access_control|require_auth\(|&signer\b|[A-Z]\w*Cap\b)", re.M)
_MOD_REM = re.compile(
    r"^-[^-].*(\b(onlyOwner|onlyRole|onlyAdmin|nonReentrant|whenNotPaused|initializer|modifier\s+only)\b"
    r"|Signer<|has_one\s*=|constraint\s*=|#\[access_control|require_auth\(|&signer\b|[A-Z]\w*Cap\b)", re.M)
_XFER_CHANGE = re.compile(
    r"^[+-][^+-].*(\b(safeTransfer\w*|transferFrom)\b|\.transfer\(|\.call\{value|lamports\(\)|token::transfer|"
    r"coin::(withdraw|deposit|take|split|join)|balance::(join|split)|transfer::(public_)?transfer|env\.storage\(\))", re.M)
_SIG_CHANGE = re.compile(
    r"^[+-][^+-].*\b(ecrecover|permit|ECDSA|EIP.?712|nonce|ed25519|secp256k1|durable|require_auth)\b", re.M)
_ACCT_CHANGE = re.compile(
    r"^[+-][^+-].*\b(balance\w*|totalSupply|total_supply|exchangeRate|index\b|reserve\w*|supply\b)", re.M)
_UPGRADE_CHANGE = re.compile(
    r"^[+-][^+-].*\b(_authorizeUpgrade|upgradeTo\w*|upgrade_authority|update_current_contract_wasm|"
    r"deploy_with_address|set_upgrade|UpgradeCap|publish_upgrade|code_object)\b", re.M)


def _analyze_diff_structure(diff_text: str) -> list[tuple[int, str]]:
    results: list[tuple[int, str]] = []

    guards_added = len(_GUARD_ADD.findall(diff_text))
    guards_removed = len(_GUARD_REM.findall(diff_text))
    if guards_added or guards_removed:
        if guards_added > guards_removed:
            results.append((3, f"adds runtime guards (+{guards_added}/-{guards_removed})"))
        elif guards_removed > guards_added:
            results.append((3, f"removes runtime guards (+{guards_added}/-{guards_removed})"))
        else:
            results.append((2, f"rewrites runtime guards (+{guards_added}/-{guards_removed})"))

    mods_added = len(_MOD_ADD.findall(diff_text))
    mods_removed = len(_MOD_REM.findall(diff_text))
    if mods_added or mods_removed:
        if mods_added > mods_removed:
            results.append((3, f"tightens access control (+{mods_added}/-{mods_removed})"))
        elif mods_removed > mods_added:
            results.append((3, f"loosens access control (+{mods_added}/-{mods_removed})"))
        else:
            results.append((2, f"rewrites access control (+{mods_added}/-{mods_removed})"))

    if _XFER_CHANGE.search(diff_text):
        results.append((2, "changes value-transfer logic"))
    if _SIG_CHANGE.search(diff_text):
        results.append((2, "changes signature/auth handling"))
    if _UPGRADE_CHANGE.search(diff_text):
        results.append((2, "changes upgrade path"))
    if _ACCT_CHANGE.search(diff_text):
        results.append((1, "changes accounting/balance logic"))
    return results


# ═══════════════════════════════════════════════════════════════
# SECURITY AREA CLASSIFICATION (multi-chain)
# ═══════════════════════════════════════════════════════════════

SECURITY_AREAS = {
    "access_control": [
        r"onlyOwner", r"onlyRole", r"modifier\s+only", r"OwnableRoles", r"AccessControl",
        r"require\(msg\.sender", r"Ownable2Step", r"_checkOwner", r"hasRole", r"_checkRole",
        r"onlyAdmin",
        r"Signer<", r"has_one\s*=", r"is_signer", r"#\[access_control",           # Anchor / native Solana
        r"signer::address_of", r"&signer\b", r"[A-Z]\w*Cap\b", r"friend\s+",      # Move
        r"require_auth\(",                                                          # Soroban
    ],
    "fund_flows": [
        r"\.deposit\(", r"\.withdraw\(", r"\.transfer\(", r"\.mint\(", r"\.burn\(",
        r"collateral", r"safeTransfer", r"balanceOf", r"allowance", r"approve",
        r"_pay\b", r"_collect\b", r"function\s+deposit", r"function\s+withdraw",
        r"lamports", r"token::transfer", r"token::mint_to", r"token::burn", r"CpiContext",
        r"coin::(withdraw|deposit|take|split|join|mint|burn)", r"balance::(join|split)",
        r"Coin<", r"Balance<", r"transfer::(public_)?transfer",
        r"env\.storage\(\)", r"token::Client", r"StellarAssetClient",
    ],
    "oracle_price": [
        r"oracle", r"[Pp]rice", r"[Ff]eed", r"TWAP", r"markPrice", r"indexPrice",
        r"latestRoundData", r"getPrice", r"EMA", r"[Pp]rice[Hh]istory",
        r"pyth", r"switchboard", r"get_price_unsafe", r"get_price_no_older_than",
    ],
    "liquidation": [
        r"liquidat", r"backstop", r"ADL", r"[Dd]eleverage", r"[Ii]nsurance",
        r"insolvenc", r"bankruptcy", r"badDebt", r"isLiquidatable", r"health_factor",
    ],
    "signatures": [
        r"ecrecover", r"permit", r"[Ss]ignature", r"EIP.?712", r"ECDSA", r"nonce",
        r"digest", r"_hashTypedData", r"v,\s*r,\s*s",
        r"ed25519", r"secp256k1", r"durable", r"Instructions::", r"sysvar::instructions",
    ],
    "state_machines": [
        r"[Ss]tatus\s*=", r"[Ss]tate\s*=", r"Phase\b", r"Stage\b", r"[Ll]ifecycle",
        r"[Tt]ransition", r"[Pp]aused", r"[Ff]rozen", r"isActive", r"onlyActive",
        r"whenNotPaused", r"is_initialized", r"initialized\s*[:=]",
    ],
    "upgrade_paths": [
        r"_authorizeUpgrade", r"upgradeTo", r"UUPSUpgradeable", r"TransparentUpgradeableProxy",
        r"ERC1967", r"delegatecall", r"upgrade_authority", r"bpf_loader_upgradeable",
        r"update_current_contract_wasm", r"deployer\(\)", r"UpgradeCap", r"publish_upgrade",
        r"code_object", r"managed_coin", r"resource_account",
    ],
}

_AREA_COMPILED = {
    area: [re.compile(p) for p in patterns]
    for area, patterns in SECURITY_AREAS.items()
}

SECURITY_HINT_RE = re.compile(
    r"(withdraw|transfer|mint|burn|deposit|borrow|liquidat|swap|price|oracle|"
    r"admin|owner|auth|access|role|upgrade|delegate|call|sign|verify|bridge|"
    r"collateral|reward|fee|vault|stake|lamport|require_auth|signer|capability|Cap\b)",
    re.I,
)

# ═══════════════════════════════════════════════════════════════
# KNOWN LIBRARIES (vendored under lib/ vendor/ deps/)
# ═══════════════════════════════════════════════════════════════

KNOWN_LIBS = {
    "openzeppelin": {"patterns": ["openzeppelin-contracts", "openzeppelin"], "upstream_pragma": ["0.8."], "label": "OpenZeppelin"},
    "solady": {"patterns": ["solady"], "upstream_pragma": ["0.8."], "label": "Solady"},
    "solmate": {"patterns": ["solmate"], "upstream_pragma": [">=0.8.", "0.8."], "label": "Solmate"},
    "uniswap_v2": {"patterns": ["uniswap", "univ2", "gte-univ2", "v2-core", "v2-periphery"], "upstream_pragma": [">=0.5.", "=0.5.", ">=0.6.", "=0.6."], "label": "Uniswap V2"},
    "uniswap_v3": {"patterns": ["v3-core", "v3-periphery", "uniswap-v3"], "upstream_pragma": [">=0.5.", "=0.7.", ">=0.7."], "label": "Uniswap V3"},
    "uniswap_v4": {"patterns": ["v4-core", "v4-periphery"], "upstream_pragma": ["0.8."], "label": "Uniswap V4"},
    "aave": {"patterns": ["aave"], "upstream_pragma": ["0.8."], "label": "Aave"},
    "chainlink": {"patterns": ["chainlink"], "upstream_pragma": ["0.8.", "0.6."], "label": "Chainlink"},
    "permit2": {"patterns": ["permit2"], "upstream_pragma": ["0.8."], "label": "Permit2"},
    "layerzero": {"patterns": ["layerzero", "lz-"], "upstream_pragma": ["0.8."], "label": "LayerZero"},
    # Non-EVM ecosystems (no pragma check; detection only)
    "anchor": {"patterns": ["anchor-lang", "anchor-spl", "anchor"], "upstream_pragma": [], "label": "Anchor (Solana)"},
    "spl": {"patterns": ["spl-token", "solana-program-library", "spl"], "upstream_pragma": [], "label": "SPL (Solana)"},
    "soroban_sdk": {"patterns": ["soroban-sdk", "soroban"], "upstream_pragma": [], "label": "Soroban SDK"},
    "aptos_framework": {"patterns": ["aptos-framework", "aptos-core", "aptos"], "upstream_pragma": [], "label": "Aptos Framework"},
    "sui_framework": {"patterns": ["sui-framework", "sui"], "upstream_pragma": [], "label": "Sui Framework"},
    "pyth": {"patterns": ["pyth"], "upstream_pragma": ["0.8."], "label": "Pyth"},
}

SKIP_LIB_ANALYSIS = {"forge-std", "ds-test", "forge-std-1"}
DEP_DIRS = ("lib", "vendor", "deps", "node_modules")


# ═══════════════════════════════════════════════════════════════
# GIT DATA COLLECTION
# ═══════════════════════════════════════════════════════════════

def run_git(repo: str, *args: str, timeout: int = 120) -> str:
    """Run git; return stdout, or "" on any failure (never raises)."""
    try:
        out = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True, text=True, timeout=timeout, errors="replace",
        )
        return out.stdout if out.returncode == 0 else ""
    except Exception:
        return ""


def parse_git_log(repo: str, src_dir: str) -> list[Commit]:
    """Parse the full history of HEAD (current branch only) in one call."""
    sep = "<<SEP>>"
    fmt = f"COMMIT_START{sep}%H{sep}%h{sep}%aI{sep}%aN{sep}%P{sep}%s"
    raw = run_git(repo, "log", "--numstat", f"--format={fmt}", timeout=300)

    commits: list[Commit] = []
    current: Commit | None = None
    for line in raw.splitlines():
        if line.startswith(f"COMMIT_START{sep}"):
            if current is not None:
                commits.append(current)
            parts = line.split(sep)
            if len(parts) < 7:
                current = None
                continue
            _, sha, short, date, author, parents, subject = parts[:7]
            current = Commit(
                sha=sha, short_sha=short, date=date[:10], author=author,
                subject=subject, is_merge=(" " in parents.strip()),
            )
        elif current is not None and line.strip():
            parts = line.split("\t")
            if len(parts) >= 3:
                try:
                    added = int(parts[0]) if parts[0] != "-" else 0
                    deleted = int(parts[1]) if parts[1] != "-" else 0
                except ValueError:
                    continue
                path = parts[2]
                is_src, is_tst = classify_path(path, src_dir)
                current.files.append(FileChange(path, added, deleted, is_src, is_tst))
    if current is not None:
        commits.append(current)
    return commits


# ═══════════════════════════════════════════════════════════════
# SECTION 1: REPO SHAPE
# ═══════════════════════════════════════════════════════════════

def analyze_repo_shape(commits: list[Commit]) -> dict:
    if not commits:
        return {
            "classification": "empty", "total_commits": 0, "source_touching_commits": 0,
            "bulk_import_sha": None, "date_spread_days": 0, "first_commit_date": None,
            "last_commit_date": None, "contributors": 0, "top_author_share": 0.0,
            "merge_commits": 0, "signals": ["Empty repository"],
        }

    source_commits = [c for c in commits if c.source_files]
    dates = sorted(c.date for c in commits)
    first, last = dates[0], dates[-1]
    try:
        spread = (datetime.strptime(last, "%Y-%m-%d") - datetime.strptime(first, "%Y-%m-%d")).days
    except ValueError:
        spread = 0

    bulk_sha = None
    signals: list[str] = []
    total_source_added = sum(sum(f.added for f in c.source_files) for c in source_commits)
    if source_commits:
        biggest = max(source_commits, key=lambda c: sum(f.added for f in c.source_files))
        biggest_added = sum(f.added for f in biggest.source_files)
        if total_source_added > 0 and biggest_added / total_source_added > 0.85:
            bulk_sha = biggest.short_sha
            signals.append(f"~{biggest_added} source lines arrived in 1 commit ({bulk_sha})")

    classification = "normal_dev"
    if len(source_commits) <= 1:
        classification = "squashed_import"
        signals.append("Only 1 commit touches source files")
    elif len(source_commits) <= 3 and spread < 7:
        classification = "squashed_import"
        signals.append(f"Only {len(source_commits)} source commits in {spread} days")
    if bulk_sha and classification == "normal_dev":
        signals.append("Bulk import detected with subsequent development")

    authors = Counter(c.author for c in commits)
    top_share = round(authors.most_common(1)[0][1] / len(commits), 3) if commits else 0.0
    merges = sum(1 for c in commits if c.is_merge)

    signals.append(f"Date spread: {spread} days")
    signals.append(f"{len(source_commits)} commits touch source files out of {len(commits)} total")

    return {
        "classification": classification,
        "total_commits": len(commits),
        "source_touching_commits": len(source_commits),
        "bulk_import_sha": bulk_sha,
        "date_spread_days": spread,
        "first_commit_date": first,
        "last_commit_date": last,
        "contributors": len(authors),
        "top_author_share": top_share,
        "merge_commits": merges,
        "signals": signals,
    }


# ═══════════════════════════════════════════════════════════════
# SECTION 2: FIX CANDIDATES (commit-level) + FIX-PRONE FILES (file-level)
# ═══════════════════════════════════════════════════════════════

def score_commit(commit: Commit, diff_text: str, file_areas_cache: dict[str, list[str]]) -> tuple[int, list[str]]:
    reasons: list[str] = []
    intent_score, intent_reasons = _classify_intent(commit.subject)
    reasons.extend(intent_reasons)

    src_files = commit.source_files
    if not src_files:
        return max(intent_score, 0), reasons

    structural_score = 0
    if diff_text:
        for delta, reason in _analyze_diff_structure(diff_text):
            structural_score += delta
            reasons.append(reason)

    domain_score = 0
    touched: set[str] = set()
    for fc in src_files:
        touched.update(file_areas_cache.get(fc.path, []))
    if len(touched) >= 2:
        domain_score = 3
        reasons.append(f"spans {len(touched)} security domains ({', '.join(sorted(touched))})")
    elif len(touched) == 1:
        domain_score = 1
        reasons.append(f"touches {next(iter(touched))} code")

    shape_score = 0
    if 1 <= len(src_files) <= 3:
        shape_score += 2
        reasons.append(f"focused change ({len(src_files)} source files)")
    if sum(f.deleted - f.added for f in src_files) > 0:
        shape_score += 1
        reasons.append("net code removal")
    churn = commit.source_churn
    if churn > 2000:
        shape_score -= 4
        reasons.append("very large change (>2000 source lines)")
    elif churn > 500:
        shape_score -= 2
        reasons.append("large change (>500 source lines)")
    if commit.test_files:
        shape_score += 1
        reasons.append("includes test changes")

    return max(intent_score + structural_score + domain_score + shape_score, 0), _unique(reasons)


FIX_FILE_THRESHOLD = 5  # same bar the report uses for "security-relevant commit"


def find_fix_candidates(commits: list[Commit], repo: str, limit: int,
                        file_areas_cache: dict[str, list[str]],
                        max_diffs: int) -> tuple[list[dict], dict[str, tuple[int, int]]]:
    """Score every non-merge commit. Returns (top-N commits, per-file fix stats).

    Diffs are fetched for source-touching commits only, newest first, capped
    at `max_diffs` so a 10k-commit monorepo does not take minutes; commits past
    the cap are scored on message + shape only (noted in reasons).
    """
    candidates: list[dict] = []
    per_file: dict[str, list[int]] = {}
    diffs_fetched = 0
    for commit in commits:
        if commit.is_merge:
            continue
        diff_text = ""
        capped = False
        if commit.source_files:
            if diffs_fetched < max_diffs:
                diff_text = run_git(repo, "show", "--format=", "--unified=0", "--no-ext-diff", commit.sha)
                diffs_fetched += 1
            else:
                capped = True
        sc, reasons = score_commit(commit, diff_text, file_areas_cache)
        if capped:
            reasons.append("diff not inspected (commit cap reached)")
        if sc >= FIX_FILE_THRESHOLD:
            # file-level fix density counts only commits that look like fixes
            for fc in commit.source_files:
                per_file.setdefault(fc.path, []).append(sc)
        if sc > 0:
            candidates.append({
                "sha": commit.short_sha, "full_sha": commit.sha, "date": commit.date,
                "author": commit.author, "subject": commit.subject, "score": sc,
                "reasons": reasons,
                "source_files_touched": [f.path for f in commit.source_files],
                "test_changed": bool(commit.test_files),
                "lines_changed": commit.source_churn,
            })
    candidates.sort(key=lambda c: (c["score"], c["date"]), reverse=True)
    if limit > 0:
        candidates = candidates[:limit]
    file_stats = {f: (len(v), sum(v)) for f, v in per_file.items()}
    return candidates, file_stats


def rank_files(commits: list[Commit], fix_stats: dict[str, tuple[int, int]],
               source_files: list[str], top: int = 15) -> tuple[list[dict], list[dict]]:
    """File-level views: fix-prone files and churn hotspots (current files only)."""
    live = set(source_files)
    churn: Counter = Counter()
    last_touched: dict[str, str] = {}
    for c in commits:
        if c.is_merge:
            continue
        for fc in c.source_files:
            churn[fc.path] += 1
            last_touched.setdefault(fc.path, c.date)  # log is newest-first

    fix_prone = []
    for f, (n_fix, score_sum) in sorted(fix_stats.items(), key=lambda kv: (kv[1][1], kv[1][0]), reverse=True):
        if f not in live:
            continue
        total = churn.get(f, n_fix) or 1
        fix_prone.append({
            "file": f, "fix_commits": n_fix, "fix_score_sum": score_sum,
            "total_changes": total, "fix_ratio": round(n_fix / total, 2),
        })
        if len(fix_prone) >= top:
            break

    hotspots = []
    for f, n in churn.most_common():
        if f not in live:
            continue
        n_fix = fix_stats.get(f, (0, 0))[0]
        hotspots.append({
            "file": f, "changes": n, "fix_commits": n_fix,
            "fix_ratio": round(n_fix / n, 2) if n else 0.0,
            "last_touched": last_touched.get(f),
        })
        if len(hotspots) >= top:
            break
    return fix_prone, hotspots


# ═══════════════════════════════════════════════════════════════
# SECTION 3: DANGEROUS AREA CHANGES
# ═══════════════════════════════════════════════════════════════

def _read_file_safe(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def classify_file_areas(content: str) -> list[str]:
    areas = []
    for area, patterns in _AREA_COMPILED.items():
        if any(p.search(content) for p in patterns):
            areas.append(area)
    return areas


def _build_file_areas_cache(repo: str, src_dir: str) -> dict[str, list[str]]:
    cache: dict[str, list[str]] = {}
    base = repo if src_dir in ("", ".", "./") else os.path.join(repo, src_dir)
    if os.path.isdir(base):
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in WALK_PRUNE]
            for fname in files:
                if fname.endswith(SRC_EXT):
                    full = os.path.join(root, fname)
                    rel = os.path.relpath(full, repo)
                    cache[rel] = classify_file_areas(_read_file_safe(full))
    lib_path = os.path.join(repo, "lib")
    if os.path.isdir(lib_path):
        for root, dirs, files in os.walk(lib_path):
            dirs[:] = [d for d in dirs if d not in ("test", "tests", "node_modules", "forge-std", ".git")]
            for fname in files:
                if fname.endswith(SRC_EXT):
                    full = os.path.join(root, fname)
                    rel = os.path.relpath(full, repo)
                    if rel not in cache:
                        cache[rel] = classify_file_areas(_read_file_safe(full))
    return cache


def analyze_dangerous_areas(commits: list[Commit], file_areas_cache: dict[str, list[str]]) -> dict:
    result: dict[str, dict] = {a: {"commit_count": 0, "files": set(), "commits": []} for a in SECURITY_AREAS}
    for commit in commits:
        if commit.is_merge:
            continue
        commit_areas: set[str] = set()
        for fc in commit.files:
            for a in file_areas_cache.get(fc.path, []):
                commit_areas.add(a)
                result[a]["files"].add(fc.path)
        for a in commit_areas:
            result[a]["commit_count"] += 1
            result[a]["commits"].append({"sha": commit.short_sha, "date": commit.date, "subject": commit.subject[:80]})
    final = {}
    for area, data in result.items():
        if data["commit_count"] > 0:
            data["files"] = sorted(data["files"])
            if len(data["commits"]) > 15:
                data["commits"] = data["commits"][:15]
                data["truncated"] = True
            final[area] = data
    return final


# ═══════════════════════════════════════════════════════════════
# SECTION 4: LATE CHANGES
# ═══════════════════════════════════════════════════════════════

def analyze_late_changes(commits: list[Commit], repo: str, days: int) -> dict:
    empty = {
        "window_days": days, "cutoff_date": None, "latest_commit_date": None,
        "late_commits": [], "source_without_test_count": 0, "total_late_source_commits": 0,
    }
    if not commits:
        return empty
    dates = []
    for c in commits:
        try:
            dates.append(datetime.strptime(c.date, "%Y-%m-%d"))
        except ValueError:
            pass
    if not dates:
        return empty
    latest = max(dates)
    cutoff = latest - timedelta(days=days)

    late, no_test = [], 0
    for c in commits:
        try:
            cdate = datetime.strptime(c.date, "%Y-%m-%d")
        except ValueError:
            continue
        if cdate < cutoff or not c.source_files:
            continue
        has_test = bool(c.test_files)
        if not has_test:
            no_test += 1
        srcs = [f.path for f in c.source_files][:10]
        late.append({
            "sha": c.short_sha, "date": c.date, "author": c.author, "subject": c.subject[:80],
            "source_files": srcs,
            "security_relevant_files": [p for p in srcs if _looks_security_relevant(os.path.join(repo, p))],
            "test_changed": has_test, "lines_changed": c.source_churn,
        })
    return {
        "window_days": days, "cutoff_date": cutoff.strftime("%Y-%m-%d"),
        "latest_commit_date": latest.strftime("%Y-%m-%d"), "late_commits": late,
        "source_without_test_count": no_test, "total_late_source_commits": len(late),
    }


def _looks_security_relevant(abspath: str) -> bool:
    try:
        with open(abspath, "r", errors="ignore") as fh:
            return bool(SECURITY_HINT_RE.search(fh.read(20000)))
    except OSError:
        return True  # cannot read → do not filter it out


# ═══════════════════════════════════════════════════════════════
# SECTION 5: FORKED / DRIFTED DEPENDENCIES
# ═══════════════════════════════════════════════════════════════

def _detect_lib_identity(dirname: str) -> str | None:
    lower = dirname.lower()
    # longest pattern first so "openzeppelin-contracts" beats "sui"/"spl" substrings
    best: tuple[int, str] | None = None
    for lib_id, info in KNOWN_LIBS.items():
        for pattern in info["patterns"]:
            if pattern.lower() in lower and (best is None or len(pattern) > best[0]):
                best = (len(pattern), lib_id)
    return best[1] if best else None


def _extract_pragmas(sol_dir: str) -> list[str]:
    pragmas = set()
    for root, dirs, files in os.walk(sol_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        for fname in files:
            if not fname.endswith(".sol"):
                continue
            try:
                with open(os.path.join(root, fname), "r", errors="replace") as f:
                    for line in f:
                        m = re.match(r"\s*pragma\s+solidity\s+(.+?)\s*;", line)
                        if m:
                            pragmas.add(m.group(1).strip())
                            break
            except OSError:
                continue
    return sorted(pragmas)


def _count_source_files(dirpath: str) -> int:
    count = 0
    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "target")]
        count += sum(1 for f in files if f.endswith(SRC_EXT))
    return count


def analyze_forked_deps(repo: str, is_git: bool) -> dict:
    detected = []
    active_submodules: set[str] = set()
    gm = os.path.join(repo, ".gitmodules")
    if os.path.isfile(gm):
        for line in _read_file_safe(gm).splitlines():
            m = re.match(r"\s*path\s*=\s*(.+)", line)
            if m:
                active_submodules.add(m.group(1).strip())

    for dep_dir in ("lib", "vendor", "deps"):
        base = os.path.join(repo, dep_dir)
        if not os.path.isdir(base):
            continue
        for entry in sorted(os.listdir(base)):
            entry_path = os.path.join(base, entry)
            if not os.path.isdir(entry_path) or entry in SKIP_LIB_ANALYSIS:
                continue
            n_src = _count_source_files(entry_path)
            if n_src == 0:
                continue
            rel = f"{dep_dir}/{entry}"
            lib_id = _detect_lib_identity(entry)
            gitfile = os.path.join(entry_path, ".git")
            is_submodule = rel in active_submodules or os.path.exists(gitfile)
            is_internalized = not is_submodule
            pragmas = _extract_pragmas(entry_path)
            notes: list[str] = []
            if lib_id:
                label = KNOWN_LIBS[lib_id]["label"]
                expected = KNOWN_LIBS[lib_id]["upstream_pragma"]
                if expected:
                    for p in pragmas:
                        if not any(p.startswith(x) or x in p for x in expected):
                            notes.append(f"Pragma '{p}' differs from expected upstream versions")
                if is_internalized:
                    notes.append(f"Internalized (not a submodule) — may contain modifications from upstream {label}")
            else:
                label = None
                if is_internalized:
                    notes.append("Internalized (not a submodule) — unknown upstream")
            detected.append({
                "name": entry, "path": rel, "known_upstream": label,
                "is_submodule": is_submodule, "is_internalized": is_internalized,
                "source_file_count": n_src, "pragma_versions": pragmas, "notes": notes,
            })

    removed: list[dict] = []
    modified: list[dict] = []
    if is_git:
        log = run_git(repo, "log", "-p", "--", ".gitmodules")
        cur_sha, cur_subject = None, None
        for line in log.splitlines():
            m = re.match(r"^commit\s+([a-f0-9]+)", line)
            if m:
                cur_sha, cur_subject = m.group(1)[:7], None
                continue
            if line.startswith("    ") and cur_subject is None:
                cur_subject = line.strip()[:80]
                continue
            m = re.match(r"^-\s*path\s*=\s*(.+)", line)
            if m and cur_sha:
                removed.append({"path": m.group(1).strip(), "removed_in_sha": cur_sha, "subject": cur_subject or ""})

        # Truent's original signal: vendored source files with LOCAL commits
        # (the repo itself edited them — a fork, whatever .gitmodules says).
        for dep_dir in DEP_DIRS:
            if not os.path.isdir(os.path.join(repo, dep_dir)):
                continue
            touched = run_git(repo, "log", "-n", "500", "--name-only", "--pretty=format:", "--", dep_dir).split()
            for f in sorted(set(x for x in touched if x.endswith(SRC_EXT)))[:15]:
                modified.append({"file": f, "dep_dir": dep_dir})

    return {"detected_libs": detected, "removed_submodules": removed,
            "locally_modified_vendor_files": modified[:30]}


# ═══════════════════════════════════════════════════════════════
# SECTION 6: TECH DEBT
# ═══════════════════════════════════════════════════════════════

_DEBT_RE = re.compile(
    r"(?://|/\*|#|\*)\s*(TODO|FIXME|HACK|XXX|BUG|WORKAROUND|UNSAFE|DO NOT|@audit(?:-\w+)?)\b[:\s]*(.*)",
    re.IGNORECASE,
)
BLAME_CAP = 20


def find_tech_debt(source_files: list[str], repo: str, is_git: bool) -> dict:
    items: list[dict] = []
    files_with_debt: set[str] = set()
    for rel in source_files:
        full = os.path.join(repo, rel)
        try:
            with open(full, "r", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            m = _DEBT_RE.search(line)
            if m:
                files_with_debt.add(rel)
                items.append({
                    "file": rel, "line": i, "type": m.group(1).upper(),
                    "text": (m.group(2) or "").strip()[:120],
                    "blame_author": None, "blame_date": None,
                })

    blame_files = sorted(files_with_debt)[:BLAME_CAP]
    capped = len(files_with_debt) > BLAME_CAP
    if is_git:
        lookup: dict[str, dict[int, tuple[str, str]]] = {}
        for rel in blame_files:
            out = run_git(repo, "blame", "--porcelain", rel)
            if not out:
                continue
            fb: dict[int, tuple[str, str]] = {}
            author, date, ln = "", "", 0
            for b in out.splitlines():
                m = re.match(r"^[a-f0-9]{40}\s+\d+\s+(\d+)", b)
                if m:
                    ln = int(m.group(1))
                    continue
                if b.startswith("author "):
                    author = b[7:].strip()
                elif b.startswith("author-time "):
                    try:
                        date = datetime.fromtimestamp(int(b[12:].strip()), tz=timezone.utc).strftime("%Y-%m-%d")
                    except (ValueError, OSError, OverflowError):
                        date = ""
                elif b.startswith("\t") and ln > 0:
                    fb[ln] = (author, date)
            lookup[rel] = fb
        for item in items:
            info = lookup.get(item["file"], {}).get(item["line"])
            if info:
                item["blame_author"], item["blame_date"] = info

    return {"total_count": len(items), "items": items, "files_with_debt": len(files_with_debt), "capped": capped}


# ═══════════════════════════════════════════════════════════════
# SECTION 7: DEV PATTERNS
# ═══════════════════════════════════════════════════════════════

def analyze_dev_patterns(commits: list[Commit], fix_candidates: list[dict], bulk_import_sha: str | None) -> dict:
    non_merge = [c for c in commits if not c.is_merge]
    source_commits = [c for c in non_merge if c.source_files]
    analysis = [c for c in source_commits if c.short_sha != bulk_import_sha] if bulk_import_sha else source_commits

    test_co_change = (sum(1 for c in source_commits if c.test_files) / len(source_commits)) if source_commits else 0.0
    fix_without_test = None
    if fix_candidates:
        fix_without_test = sum(1 for f in fix_candidates if not f["test_changed"]) / len(fix_candidates)
    avg_size = (sum(c.source_churn for c in analysis) / len(analysis)) if analysis else 0.0
    size_note = "excluding bulk import" if bulk_import_sha and len(analysis) != len(source_commits) else None

    author_lines: dict[str, int] = {}
    for c in source_commits:
        author_lines[c.author] = author_lines.get(c.author, 0) + sum(f.added for f in c.source_files)
    total = sum(author_lines.values())
    breakdown = []
    if total > 0:
        for author, lines in sorted(author_lines.items(), key=lambda x: x[1], reverse=True):
            breakdown.append({"author": author, "lines_added": lines, "pct": round(lines / total, 3)})

    return {
        "test_co_change_rate": round(test_co_change, 3),
        "fix_without_test_rate": round(fix_without_test, 3) if fix_without_test is not None else None,
        "avg_commit_size": round(avg_size, 1),
        "avg_commit_size_note": size_note,
        "single_developer_pct": breakdown[0]["pct"] if breakdown else 0.0,
        "top_contributor": breakdown[0]["author"] if breakdown else "unknown",
        "contributor_breakdown": breakdown[:10],
    }


# ═══════════════════════════════════════════════════════════════
# UTILITY / MAIN
# ═══════════════════════════════════════════════════════════════

def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for i in items:
        if i not in seen:
            out.append(i)
            seen.add(i)
    return out


HOW_TO_USE = (
    "Rank audit attention by: fix_candidates (commits that look like security fixes; "
    "score >= 5 worth reading, >= 10 worth a manual diff) and fix_prone_files (where "
    "those fixes landed) first, then churn_hotspots (high change = high defect density), "
    "then late_changes (recently touched, least reviewed), then dangerous_area_changes "
    "(which security areas churned), forked_deps (drift from upstream) and tech_debt "
    "(self-flagged risk). Feed the resulting file list as the priority set to "
    "`truent scan` / the truent-audit skill. All history is HEAD-only (current branch)."
)


def main() -> int:
    ap = argparse.ArgumentParser(description="Git history security analysis (multi-chain)")
    ap.add_argument("--repo", default=".", help="Path to the repository")
    ap.add_argument("--src-dir", default="auto", help="Source directory (auto-detected)")
    ap.add_argument("--json", default=None, help="Write JSON here (default: stdout)")
    ap.add_argument("--days", type=int, default=30, help="Late-change window in days")
    ap.add_argument("--limit", type=int, default=10, help="Max fix candidates to report")
    ap.add_argument("--max-diffs", type=int, default=1500,
                    help="Max commits whose diff is inspected (newest first)")
    args = ap.parse_args()

    t0 = time.monotonic()
    repo = os.path.abspath(args.repo)
    src_dir = detect_src_dir(repo) if args.src_dir in ("auto", "", None) else args.src_dir
    if src_dir not in (".", "./") and not src_dir.endswith("/"):
        src_dir += "/"
    notes: list[str] = []

    is_git = run_git(repo, "rev-parse", "--is-inside-work-tree").strip() == "true"
    head = run_git(repo, "rev-parse", "--short", "HEAD").strip() or None if is_git else None
    branch = run_git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip() or "unknown" if is_git else None
    is_shallow = run_git(repo, "rev-parse", "--is-shallow-repository").strip() == "true" if is_git else False
    if not is_git:
        notes.append("not a git repository — history sections are empty; filesystem sections (tech_debt, forked_deps.detected_libs) still populated")
    elif is_shallow:
        notes.append("shallow clone — history-based signal is partial; fetch full history for best results")

    source_files = find_source_files(repo, src_dir)
    chains = detect_chains(repo, source_files)
    commits = parse_git_log(repo, src_dir) if is_git else []
    if is_git and not commits:
        notes.append("git log returned no commits (empty history or unreadable)")

    file_areas_cache = _build_file_areas_cache(repo, src_dir)
    repo_shape = analyze_repo_shape(commits)
    fix_cands, fix_stats = find_fix_candidates(commits, repo, args.limit, file_areas_cache, args.max_diffs)
    fix_prone, hotspots = rank_files(commits, fix_stats, source_files)
    dangerous = analyze_dangerous_areas(commits, file_areas_cache)
    late = analyze_late_changes(commits, repo, args.days)
    forked = analyze_forked_deps(repo, is_git)
    debt = find_tech_debt(source_files, repo, is_git)
    patterns = analyze_dev_patterns(commits, fix_cands, repo_shape.get("bulk_import_sha"))

    result = {
        "meta": {
            "repo": repo,
            "src_dir": src_dir.rstrip("/") or ".",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "git_head": head,
            "git_branch": branch,
            "is_git_repo": is_git,
            "is_shallow": is_shallow,
            "chains_detected": chains,
            "total_commits": len(commits),
            "total_source_files": len(source_files),
            "analysis_time_ms": int((time.monotonic() - t0) * 1000),
        },
        "repo_shape": repo_shape,
        "fix_candidates": fix_cands,
        "fix_prone_files": fix_prone,
        "churn_hotspots": hotspots,
        "dangerous_area_changes": dangerous,
        "late_changes": late,
        "forked_deps": forked,
        "tech_debt": debt,
        "dev_patterns": patterns,
        "notes": notes,
        "how_to_use": HOW_TO_USE,
    }
    text = json.dumps(result, indent=2)
    if args.json:
        with open(args.json, "w") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
