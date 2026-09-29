//! Protocol-state ordering drawn from lending, staking and governance
//! findings: interest not accrued before a balance-changing action, reward
//! accounting not checkpointed, votes weighed by a balance that a flash loan
//! can inflate, and swaps whose deadline is the current block.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use super::implementations::split_functions;
use super::textutil::code_lines;

lazy_static! {
    static ref FUNCTION_DECL: Regex = Regex::new(r"(?i)\bfunction\s+(\w+)\s*\(").unwrap();
    static ref ACCRUE_DEF: Regex = Regex::new(r"(?i)\bfunction\s+(_?accrue\w*|_?updateInterest\w*|_?accrueInterest\w*)\s*\(").unwrap();
    static ref ACCRUE_CALL: Regex = Regex::new(r"(?i)\b_?accrue\w*\s*\(|\b_?updateInterest\w*\s*\(").unwrap();
    static ref LENDING_VERB: Regex = Regex::new(r"(?i)^(borrow|repay|liquidate|redeem|withdraw|deposit|mint|supply|seize)\w*$").unwrap();
    static ref REWARD_MACHINERY: Regex = Regex::new(r"(?i)\b(updateReward|_updateReward|rewardPerToken|_checkpoint|checkpoint|_updateRewards|updateRewards|_updateAccounting)\b").unwrap();
    static ref REWARD_APPLIED: Regex = Regex::new(r"(?i)\b(updateReward|_updateReward|_checkpoint|checkpoint|_updateRewards|updateRewards|_updateAccounting)\s*\(").unwrap();
    static ref STAKING_VERB: Regex = Regex::new(r"(?i)^(stake|unstake|withdraw|deposit|exit|getReward|claim|_transfer|transfer|transferFrom)\w*$").unwrap();
    static ref BALANCE_MUTATION: Regex = Regex::new(r"(?i)\b(_?balances?|staked|_?stakes?|deposits?|shares|totalSupply|_totalSupply|totalStaked)\b\s*(\[[^\]]*\])?\s*(\+=|-=|=[^=])").unwrap();
    static ref VOTE_FN: Regex = Regex::new(r"(?i)\bfunction\s+(castVote\w*|vote\w*|_castVote\w*|propose\w*)\s*\(").unwrap();
    static ref CURRENT_WEIGHT: Regex = Regex::new(r"(?i)\b(balanceOf|getVotes|votingPower|delegates)\s*\(\s*(msg\.sender|voter|account|_voter|_account|sender)\s*\)").unwrap();
    static ref SNAPSHOT_WEIGHT: Regex = Regex::new(r"(?i)getPastVotes|getPriorVotes|balanceOfAt|totalSupplyAt|snapshot|checkpoint").unwrap();
    static ref ROUTER_CALL: Regex = Regex::new(r"(?i)\.\s*(swapExact\w+|swapTokensForExact\w+|exactInput\w*|exactOutput\w*|addLiquidity\w*|removeLiquidity\w*)\s*\(").unwrap();
    static ref NOW_AS_DEADLINE: Regex = Regex::new(r"(?i)\bblock\.timestamp\b(\s*\+\s*\d+)?\s*[,)]|deadline\s*:\s*block\.timestamp|type\s*\(\s*uint256\s*\)\s*\.max\s*[,)]|deadline\s*:\s*type\s*\(\s*uint256\s*\)\s*\.max").unwrap();
    static ref VIEW_OR_PURE: Regex = Regex::new(r"(?i)\b(view|pure)\b").unwrap();
    /// Accrual only means interest in a contract that carries debt.
    static ref LENDING_CONTEXT: Regex = Regex::new(r"(?i)\b(borrow|debt|interest|collateral|utili[sz]ation)\b").unwrap();
}

fn finding(id: &str, file: &str, idx: usize, line: &str, sev: Severity, msg: &str) -> Finding {
    Finding::new(
        id.to_string(),
        sev,
        file.to_string(),
        idx + 1,
        0,
        msg.to_string(),
        line.trim().to_string(),
    )
    .with_metadata("detector".to_string(), "protocol_state".to_string())
}

fn name_of(decl: &str) -> Option<String> {
    FUNCTION_DECL.captures(decl).map(|c| c[1].to_string())
}

/// The contract has an interest-accrual routine, and a lending action
/// changes balances without calling it first: rates apply to stale debt.
pub fn detect_interest_not_accrued(source: &str, file_path: &str) -> Vec<Finding> {
    if !ACCRUE_DEF.is_match(source) || !LENDING_CONTEXT.is_match(source) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let Some((idx, decl)) = span.lines.first() else {
            continue;
        };
        let Some(name) = name_of(decl) else { continue };
        if !LENDING_VERB.is_match(&name) || VIEW_OR_PURE.is_match(decl) {
            continue;
        }
        let body: Vec<&str> = span.lines.iter().map(|(_, l)| l.as_str()).collect();
        let mutates = body
            .iter()
            .any(|l| BALANCE_MUTATION.is_match(l) || l.contains("+=") || l.contains("-="));
        if mutates
            && !body.iter().any(|l| ACCRUE_CALL.is_match(l))
            && !decl.to_ascii_lowercase().contains("accrue")
        {
            out.push(finding(
                "evm_interest_not_accrued", file_path, *idx, decl, Severity::High,
                "Lending action changes balances without accruing interest first: the rate is applied \
                 to a stale principal, so borrowers who act before accrual pay less and lenders earn less; \
                 call the accrual routine at the top of every state-changing entry point",
            ));
        }
    }
    out
}

/// Staking accounting exists (`updateReward`, `rewardPerToken`, checkpoints)
/// but a balance-changing function neither carries the modifier nor calls it:
/// rewards are computed from the new balance over the old period.
pub fn detect_reward_checkpoint_missing(source: &str, file_path: &str) -> Vec<Finding> {
    if !REWARD_MACHINERY.is_match(source) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let Some((idx, decl)) = span.lines.first() else {
            continue;
        };
        let Some(name) = name_of(decl) else { continue };
        if !STAKING_VERB.is_match(&name) || VIEW_OR_PURE.is_match(decl) {
            continue;
        }
        if REWARD_MACHINERY.is_match(decl) {
            continue;
        } // carries the modifier
        let body: Vec<&str> = span.lines.iter().map(|(_, l)| l.as_str()).collect();
        let mutates = body.iter().any(|l| BALANCE_MUTATION.is_match(l));
        if mutates && !body.iter().any(|l| REWARD_APPLIED.is_match(l)) {
            out.push(finding(
                "evm_reward_checkpoint_missing", file_path, *idx, decl, Severity::High,
                "Balance changes without a reward checkpoint: the reward index is applied to the new \
                 balance for the whole elapsed period, so a late depositor claims rewards accrued \
                 before they arrived; apply `updateReward` (or the checkpoint) before the mutation",
            ));
        }
    }
    out
}

/// A vote weighed by a live balance rather than a snapshot: borrow the
/// tokens, vote, return them in the same transaction.
pub fn detect_vote_weight_current_balance(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lines = code_lines(source);
    for span in split_functions(&lines) {
        let Some((_, decl)) = span.lines.first() else {
            continue;
        };
        if !VOTE_FN.is_match(decl) {
            continue;
        }
        let body: Vec<&str> = span.lines.iter().map(|(_, l)| l.as_str()).collect();
        if body.iter().any(|l| SNAPSHOT_WEIGHT.is_match(l)) {
            continue;
        }
        for (idx, line) in &span.lines {
            if CURRENT_WEIGHT.is_match(line) {
                out.push(finding(
                    "evm_vote_weight_current_balance", file_path, *idx, line, Severity::High,
                    "Vote weight read from the current balance: tokens borrowed in a flash loan count in \
                     full and are returned in the same transaction; weigh votes at a past block \
                     (`getPastVotes`, `balanceOfAt`) fixed when the proposal was created",
                ));
            }
        }
    }
    out
}

/// A router call whose deadline is `block.timestamp` (or unbounded): the
/// deadline can never expire, so a validator can hold the transaction until
/// the price is worst for the sender and include it then.
pub fn detect_swap_missing_deadline(source: &str, file_path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lines = code_lines(source);
    let mut i = 0;
    while i < lines.len() {
        if ROUTER_CALL.is_match(&lines[i]) {
            // The argument list may span several lines; read to the closing paren.
            let mut depth = 0i32;
            let mut window = String::new();
            let mut j = i;
            while j < lines.len() && j < i + 12 {
                window.push_str(&lines[j]);
                window.push('\n');
                depth += lines[j].matches('(').count() as i32;
                depth -= lines[j].matches(')').count() as i32;
                if depth <= 0 && j > i || (depth <= 0 && lines[j].contains(';')) {
                    break;
                }
                j += 1;
            }
            if NOW_AS_DEADLINE.is_match(&window) {
                out.push(finding(
                    "evm_swap_missing_deadline", file_path, i, &lines[i], Severity::Medium,
                    "Swap deadline is the current block (or unbounded): it can never expire, so the \
                     transaction can be held in the mempool and executed later at a worse price; \
                     take a deadline from the caller and pass it through",
                ));
            }
            i = j.max(i) + 1;
        } else {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interest_accrual() {
        let bad = "contract L {\n    function accrueInterest() public {\n        index += 1;\n    }\n    function borrow(uint256 a) external {\n        debt[msg.sender] += a;\n    }\n}";
        assert_eq!(detect_interest_not_accrued(bad, "a.sol").len(), 1);
        let good = "contract L {\n    function accrueInterest() public {\n        index += 1;\n    }\n    function borrow(uint256 a) external {\n        accrueInterest();\n        debt[msg.sender] += a;\n    }\n}";
        assert!(detect_interest_not_accrued(good, "a.sol").is_empty());
    }

    #[test]
    fn reward_checkpoint() {
        let bad = "contract S {\n    modifier updateReward(address a) {\n        _;\n    }\n    function stake(uint256 a) external {\n        _balances[msg.sender] += a;\n    }\n}";
        assert_eq!(detect_reward_checkpoint_missing(bad, "a.sol").len(), 1);
        let good = "contract S {\n    modifier updateReward(address a) {\n        _;\n    }\n    function stake(uint256 a) external updateReward(msg.sender) {\n        _balances[msg.sender] += a;\n    }\n}";
        assert!(detect_reward_checkpoint_missing(good, "a.sol").is_empty());
    }

    #[test]
    fn vote_weight() {
        let bad = "contract G { function castVote(uint256 id, bool s) external { uint256 w = token.balanceOf(msg.sender); votes[id] += w; } }";
        assert_eq!(detect_vote_weight_current_balance(bad, "a.sol").len(), 1);
        let good = "contract G { function castVote(uint256 id, bool s) external { uint256 w = token.getPastVotes(msg.sender, proposals[id].snapshot); votes[id] += w; } }";
        assert!(detect_vote_weight_current_balance(good, "a.sol").is_empty());
    }

    #[test]
    fn swap_deadline() {
        let bad = "router.swapExactTokensForTokens(amountIn, minOut, path, address(this), block.timestamp);";
        assert_eq!(detect_swap_missing_deadline(bad, "a.sol").len(), 1);
        let good =
            "router.swapExactTokensForTokens(amountIn, minOut, path, address(this), deadline);";
        assert!(detect_swap_missing_deadline(good, "a.sol").is_empty());
    }
}
