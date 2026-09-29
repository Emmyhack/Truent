#!/usr/bin/env python3
"""Measure Truent's EVM recall against a public audit-findings dataset.

Reads the Zaevlad/audit-findings-dataset parquet (not redistributed with this
repository; download it from Hugging Face), keeps the rows whose proof-of-
concept is Solidity, classifies each row by its title and description, runs
`truent scan --chain evm` over the PoC, and reports, per class, how often a
detector mapped to that class fired and how often any detector fired.

    python3 scripts/audit_dataset_bench.py path/to/findings.parquet [--binary target/release/truent] [--limit N]

Requires pandas and pyarrow. Output is a Markdown table on stdout.
"""
import argparse, json, os, re, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

CLASSES = {  # class -> (title/description pattern, detector ids that answer it)
    'reentrancy': (r'\breentran', ['evm_reentrancy_classic', 'evm_reentrancy_erc20', 'evm_readonly_reentrancy', 'evm_reentrancy_via_whitelisted', 'evm_reentrancy_protection', 'evm_state_mutation_ordering']),
    'access_control': (r'missing (access|auth)|anyone can (call|set|change|update|withdraw|mint|burn|pause|upgrade)|unauthori[sz]ed|no access control|tx\.origin', ['evm_access_control', 'evm_missing_signer_check', 'evm_shallow_auth', 'evm_tx_origin_authentication', 'unauthorized_privileged_mutation', 'evm_unprotected_initializer']),
    'oracle': (r'oracle|twap|spot price|latestrounddata|stale price|latestanswer|chainlink', ['evm_oracle_spot_price', 'evm_stale_oracle_price', 'evm_oracle_answer_unvalidated', 'evm_oracle_self_trade', 'evm_synthetic_collateral_oracle', 'evm_token_balance_manipulation']),
    'slippage_deadline': (r'slippage|deadline|front[- ]?run|sandwich', ['evm_router_slippage_validation', 'evm_swap_missing_deadline', 'evm_frontrunning', 'evm_permit_frontrun_dos']),
    'erc20_handling': (r'safetransfer|safeerc20|usdt|fee[- ]on[- ]transfer|does not return|returns? false|non[- ]standard erc20', ['evm_erc20_without_safe_wrapper', 'evm_unchecked_returns', 'evm_fee_on_transfer_incompatibility']),
    'decimals': (r'\b1e18\b|18 decimals|decimals\(\)|token decimals', ['evm_hardcoded_token_decimals']),
    'approval': (r'safeapprove|approval race|unlimited approval|infinite approval|approve.*front', ['evm_unsafe_token_approval']),
    'nft_transfer': (r'_safemint|onerc721received|transferfrom.*(nft|erc721)', ['evm_erc721_unsafe_transfer']),
    'eth_transfer': (r'\.transfer\(|\.send\(|2300 gas|gas stipend', ['evm_fixed_gas_eth_transfer', 'evm_push_payment_in_loop']),
    'msg_value_loop': (r'msg\.value.*(loop|multicall|batch)|(loop|multicall|batch).*msg\.value', ['evm_msg_value_reused_in_loop', 'evm_arbitrary_call_msg_value']),
    'downcast': (r'downcast|safecast|truncat|uint(8|16|32|64|96|128)\(', ['evm_unsafe_downcast', 'evm_integer_overflow', 'evm_precision_loss']),
    'fee_bounds': (r'(fee|bps|rate).*(no (upper|max)|not (bounded|capped)|exceed|100%|above)', ['evm_fee_parameter_unbounded']),
    'zero_address': (r'zero[- ]address|address\(0\)', ['evm_missing_zero_address_check']),
    'interest_accrual': (r'accru(e|ed|es|al)|updateinterest', ['evm_interest_not_accrued']),
    'reward_checkpoint': (r'updatereward|checkpoint|rewardpertoken', ['evm_reward_checkpoint_missing']),
    'vote_weight': (r'(getvotes|voting power|votes?).*(current|balanceof|flash)|flash.*vot', ['evm_vote_weight_current_balance', 'evm_flash_loan_governance']),
    'signature': (r'ecrecover|malleab|signature (verif|replay)|chain ?id|nonce', ['evm_ecrecover_unvalidated', 'evm_signature_replay_protection', 'evm_cross_chain_replay_missing_chainid']),
    'encodepacked': (r'abi\.encodepacked|hash collision', ['evm_encodepacked_hash_collision']),
    'overflow': (r'overflow|underflow|unchecked \{', ['evm_integer_overflow', 'evm_integer_underflow', 'evm_legacy_unsafe_math', 'evm_unsafe_downcast']),
    'dos_loop': (r'unbounded loop|out[- ]of[- ]gas|block gas limit|denial[- ]of[- ]service', ['evm_unbounded_loop', 'evm_push_payment_in_loop', 'evm_fixed_gas_eth_transfer']),
    'upgradeability': (r'initializ|storage (collision|gap)|delegatecall|proxy', ['evm_unprotected_initializer', 'evm_proxy_storage_collision', 'evm_upgrade_path_verification', 'evm_delegatecall_injection', 'evm_constructor_race_condition']),
    'erc4626': (r'erc[- ]?4626|first depositor|inflation attack|share price', ['evm_erc4626_inflation_protection']),
    'randomness_timestamp': (r'random|blockhash|block\.timestamp|prevrandao', ['evm_timestamp_dependence']),
    'division_zero': (r'division by zero|divide by zero|/ 0\b', ['evm_division_by_zero']),
}
PLACEHOLDER = {'no poc', 'n/a', '', 'none', 'nan', 'null'}
SOLIDITY = re.compile(r'\b(contract|function|pragma solidity|interface)\b')

def extract_code(poc: str) -> str:
    blocks = re.findall(r'```(?:solidity|sol|javascript|js)?\s*\n(.*?)```', poc, flags=re.S)
    text = '\n'.join(blocks) if blocks else poc
    return text if SOLIDITY.search(text) else ''

def scan(binary: str, code: str) -> set:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'poc.sol')
        with open(path, 'w') as f:
            f.write(code)
        try:
            r = subprocess.run([binary, 'scan', 'poc.sol', '--chain', 'evm', '--output', 'json'], cwd=d, capture_output=True, text=True, timeout=60)
            out = json.loads(r.stdout) if r.stdout.strip().startswith('{') else {}
        except Exception:
            return set()
    return {v.get('invariant_id') for v in out.get('violations', [])}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('parquet')
    ap.add_argument('--binary', default='target/release/truent')
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--workers', type=int, default=os.cpu_count() or 4)
    ap.add_argument('--include-tests', action='store_true', help='also scan PoCs that are only test scripts')
    a = ap.parse_args()
    a.binary = os.path.abspath(a.binary)  # scans run from a temp dir
    import pandas as pd
    df = pd.read_parquet(a.parquet)
    df['code'] = df['bug_poc'].astype(str).map(lambda p: '' if p.strip().lower() in PLACEHOLDER else extract_code(p))
    df = df[df['code'].str.len() > 40]
    # A Foundry/Hardhat test only *calls* the vulnerable protocol; the bug it
    # demonstrates lives in code that is not in the file. Only PoCs that carry
    # a contract of their own can be judged by a static scan of the file.
    is_test = df['code'].str.contains(r'forge-std|hardhat|\bfunction\s+test\w*\s*\(|vm\.(prank|deal|warp|startPrank)', regex=True)
    has_contract = df['code'].str.contains(r'^\s*contract\s+\w+', regex=True, flags=re.M)
    total_all = len(df)
    df = df[has_contract & ~is_test] if not a.include_tests else df
    if a.limit:
        df = df.head(a.limit)
    text = (df['bug_title'].astype(str) + '\n' + df['bug_desc'].astype(str)).str.lower()
    labels = {k: text.str.contains('(?:' + r + ')', regex=True) for k, (r, _) in CLASSES.items()}
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        hits = list(ex.map(lambda c: scan(a.binary, c), df['code'].tolist()))
    any_hit = [bool(h) for h in hits]
    print(f'| class | PoC rows | class detector fired | any detector fired |')
    print(f'|---|---:|---:|---:|')
    rows = []
    for k, (_, ids) in CLASSES.items():
        idx = [i for i, m in enumerate(labels[k].tolist()) if m]
        if not idx:
            continue
        cls = sum(1 for i in idx if hits[i] & set(ids))
        anyf = sum(1 for i in idx if any_hit[i])
        rows.append((k, len(idx), cls, anyf))
    rows.sort(key=lambda r: -r[1])
    for k, n, c, af in rows:
        print(f'| {k} | {n} | {c} ({c/n:.0%}) | {af} ({af/n:.0%}) |')
    print(f'\n{len(df)} of {total_all} Solidity PoCs carry their own contract and were scanned; {sum(any_hit)} ({sum(any_hit)/max(len(df),1):.0%}) produced at least one finding.')

if __name__ == '__main__':
    sys.exit(main())
