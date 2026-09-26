#!/usr/bin/env python3
"""emit_solana_plan.py — build a Truent Solana fuzz plan from an Anchor IDL
and the synthesized property plan.

`truent fuzz <idl.json> --dynamic --chain solana --plan plan.json` is the only
Solana dynamic path. The IDL says which instructions exist; the plan says
which accounts exist, which pools instruction accounts are drawn from, and
what must stay true. This script writes that plan (schema:
crates/dynamic/solana/src/config.rs) so a human only supplies the one thing
neither file can know — concrete pubkeys.

Inputs
  --idl         Anchor IDL (legacy isMut/isSigner or 0.30+ writable/signer)
  --properties  fizz_data/property-plan.json written by the synthesizer
                (array of {id, english, category, sources, dsl, chain, ...})
  --accounts    JSON map of account name -> {pubkey, role?, space?, lamports?,
                data_hex?, owner?}. role is one of mint | token_account |
                signer | state | other. Names that match IDL account names
                are pinned.

Mapping
  conservation properties      -> {"type": "token_conservation"} using the
                                  mint + every token_account in --accounts
  authority/owner-stability    -> {"type": "account_owner"} for each state
  properties                      account (or the account the property names)
  everything else              -> reported as `unmapped`; implement as an
                                  Anchor #[test] / solana-program-test harness
                                  (EXTERNAL) per references/chains/solana.md

The engine rejects a plan with no invariants; so does this script.
Pure standard library; no third-party imports.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SPL_TOKEN_AMOUNT_OFFSET = 64  # u64 `amount` in an SPL token account
SPL_MINT_SUPPLY_OFFSET = 36  # u64 `supply` in an SPL mint

CONSERVATION_RE = re.compile(
    r"conserv|sum of|sum\(|total supply|totalsupply|supply (must )?(equal|match)|"
    r"== ?(mint )?supply|balances? (sum|add up)",
    re.I,
)
OWNER_WORD_RE = re.compile(r"\b(owner|authority|admin|upgrade authority|program owner)\b", re.I)
STABLE_WORD_RE = re.compile(
    r"never (change|be changed|be reassigned|transfer)|unchanged|stable|immutable|"
    r"cannot (be )?(change|reassign|take|rotate)|only .{0,40}(can|may) (change|set|rotate)",
    re.I,
)


def load_json(path: str, what: str):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        sys.exit(f"error: {what} not found: {path}")
    except json.JSONDecodeError as exc:
        sys.exit(f"error: {what} is not valid JSON ({path}): {exc}")


def idl_program_id(idl: dict) -> str | None:
    if isinstance(idl.get("address"), str):
        return idl["address"]
    meta = idl.get("metadata")
    if isinstance(meta, dict) and isinstance(meta.get("address"), str):
        return meta["address"]
    return None


def idl_account_roles(idl: dict) -> dict[str, set[str]]:
    """IDL account name -> {'signer','writable','readonly'} across instructions."""
    roles: dict[str, set[str]] = {}
    for ix in idl.get("instructions", []):
        for acc in ix.get("accounts", []):
            name = acc.get("name")
            if not isinstance(name, str):
                continue
            signer = acc.get("signer", acc.get("isSigner", False))
            writable = acc.get("writable", acc.get("isMut", False))
            bucket = roles.setdefault(name, set())
            if signer:
                bucket.add("signer")
            elif writable:
                bucket.add("writable")
            else:
                bucket.add("readonly")
    return roles


def is_conservation(prop: dict) -> bool:
    sources = " ".join(str(s) for s in prop.get("sources", []))
    text = f"{prop.get('english', '')} {prop.get('name', '')}"
    return bool(
        re.search(r"\bCON-\d+", sources)
        or CONSERVATION_RE.search(text)
    )


def is_owner_stability(prop: dict) -> bool:
    text = f"{prop.get('english', '')} {prop.get('name', '')}"
    return bool(OWNER_WORD_RE.search(text) and STABLE_WORD_RE.search(text))


def label(prop: dict) -> str:
    guarantee = prop.get("guarantee", "EXPLORATORY")
    english = str(prop.get("english", "")).strip().rstrip(".")
    return f"{prop.get('id', '?')} {guarantee} — {english}"[:160]


def build_plan(idl: dict, props: list[dict], accounts: dict, args) -> tuple[dict, list[dict]]:
    roles = idl_account_roles(idl)

    genesis = []
    signers: list[str] = []
    writable: list[str] = []
    readonly: list[str] = []
    pin: dict[str, str] = {}
    mints: list[str] = []
    token_accounts: list[str] = []
    state_accounts: dict[str, str] = {}

    for name, spec in accounts.items():
        if not isinstance(spec, dict) or not isinstance(spec.get("pubkey"), str):
            sys.exit(f"error: --accounts entry {name!r} needs a base58 'pubkey' string")
        pk = spec["pubkey"]
        entry = {"name": name, "pubkey": pk}
        for k in ("lamports", "space", "data_hex", "owner"):
            if k in spec:
                entry[k] = spec[k]
        genesis.append(entry)

        role = str(spec.get("role", "other"))
        if role == "mint":
            mints.append(pk)
        elif role == "token_account":
            token_accounts.append(pk)
        elif role == "state":
            state_accounts[name] = pk

        idl_roles = roles.get(name, set())
        if name in roles:
            pin[name] = pk
        if "signer" in idl_roles or role == "signer":
            signers.append(pk)
        elif "writable" in idl_roles or role in ("mint", "token_account", "state"):
            writable.append(pk)
        else:
            readonly.append(pk)

    invariants: list[dict] = []
    unmapped: list[dict] = []
    conservation_done = False

    for prop in props:
        chain = prop.get("chain")
        if chain not in (None, "solana"):
            continue
        if is_conservation(prop):
            mint = prop.get("mint") or (mints[0] if len(mints) == 1 else None)
            tas = prop.get("token_accounts") or token_accounts
            if mint and tas and not conservation_done:
                invariants.append(
                    {
                        "type": "token_conservation",
                        "name": label(prop),
                        "mint": mint,
                        "token_accounts": list(tas),
                        "amount_offset": int(prop.get("amount_offset", args.amount_offset)),
                        "supply_offset": int(prop.get("supply_offset", args.supply_offset)),
                    }
                )
                conservation_done = True
                continue
            reason = (
                "conservation shape but no single mint / token_account set in --accounts"
                if not conservation_done
                else "conservation already covered by an earlier property"
            )
            unmapped.append({"id": prop.get("id"), "reason": reason})
            continue
        if is_owner_stability(prop):
            target = prop.get("account")
            candidates = (
                {target: accounts[target]["pubkey"]}
                if target in accounts
                else state_accounts
            )
            if candidates:
                for name, pk in candidates.items():
                    invariants.append(
                        {"type": "account_owner", "name": f"{label(prop)} [{name}]", "account": pk}
                    )
                continue
            unmapped.append({"id": prop.get("id"), "reason": "owner-stability shape but no 'state' account in --accounts"})
            continue
        unmapped.append({"id": prop.get("id"), "reason": "not a token_conservation / account_owner shape — write an Anchor #[test] (EXTERNAL)"})

    plan: dict = {}
    program_id = args.program_id or idl_program_id(idl)
    if program_id:
        plan["program_id"] = program_id
    if args.program_so:
        plan["program_so"] = args.program_so
    plan["accounts"] = genesis
    plan["signers"] = signers
    plan["writable"] = writable
    plan["readonly"] = readonly
    plan["pin"] = pin
    plan["invariants"] = invariants
    if args.seed is not None:
        plan["seed"] = args.seed
    if args.runs is not None:
        plan["runs"] = args.runs
    if args.depth is not None:
        plan["depth"] = args.depth
    return plan, unmapped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="emit_solana_plan.py",
        description="Build fizz_data/plan.json for `truent fuzz <idl> --dynamic --chain solana --plan` "
        "from an Anchor IDL, the synthesized property-plan.json and a pubkey map.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "example:\n"
            "  emit_solana_plan.py --idl target/idl/vault.json \\\n"
            "      --properties fizz_data/property-plan.json \\\n"
            "      --accounts fizz_data/solana-accounts.json --out fizz_data/plan.json\n"
            "then:\n"
            "  truent fuzz target/idl/vault.json --dynamic --chain solana --plan fizz_data/plan.json"
        ),
    )
    ap.add_argument("--idl", required=True, help="Anchor IDL JSON")
    ap.add_argument("--properties", required=True, help="property-plan.json from the synthesizer")
    ap.add_argument("--accounts", required=True, help="JSON map: name -> {pubkey, role, space, lamports, data_hex, owner}")
    ap.add_argument("--out", default="fizz_data/plan.json", help="where to write the plan (default: fizz_data/plan.json)")
    ap.add_argument("--program-id", help="override the program id (needed for legacy IDLs without one)")
    ap.add_argument("--program-so", help="path to the compiled program, e.g. target/deploy/x.so")
    ap.add_argument("--amount-offset", type=int, default=SPL_TOKEN_AMOUNT_OFFSET, help="token-account amount byte offset (default 64, SPL Token)")
    ap.add_argument("--supply-offset", type=int, default=SPL_MINT_SUPPLY_OFFSET, help="mint supply byte offset (default 36, SPL Token)")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--runs", type=int)
    ap.add_argument("--depth", type=int)
    args = ap.parse_args(argv)

    idl = load_json(args.idl, "IDL")
    props = load_json(args.properties, "property plan")
    accounts = load_json(args.accounts, "accounts map")
    if not isinstance(idl, dict) or not idl.get("instructions"):
        sys.exit("error: IDL declares no instructions")
    if not isinstance(props, list):
        sys.exit("error: property-plan.json must be a JSON array of property objects")
    if not isinstance(accounts, dict):
        sys.exit("error: --accounts must be a JSON object keyed by account name")

    plan, unmapped = build_plan(idl, props, accounts, args)

    print(f"IDL: {idl.get('name') or (idl.get('metadata') or {}).get('name') or '?'} — {len(idl['instructions'])} instruction(s)")
    print(f"genesis accounts: {len(plan['accounts'])}  signers: {len(plan['signers'])}  writable: {len(plan['writable'])}  readonly: {len(plan['readonly'])}  pinned: {len(plan['pin'])}")
    print(f"invariants mapped: {len(plan['invariants'])}")
    for inv in plan["invariants"]:
        print(f"  [{inv['type']}] {inv['name']}")
    if unmapped:
        print(f"unmapped ({len(unmapped)}) — implement as Anchor #[test] harness (EXTERNAL):")
        for u in unmapped:
            print(f"  {u['id']}: {u['reason']}")

    if not plan["invariants"]:
        print("error: no property mapped to a plan invariant — the engine rejects a plan with nothing to check, so no file was written.", file=sys.stderr)
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    print(f"run:  truent fuzz {args.idl} --dynamic --chain solana --plan {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
