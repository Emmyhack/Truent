// EXPECT: evm_reward_checkpoint_missing
pragma solidity ^0.8.20;
contract Staking {
    uint256 public rewardPerTokenStored;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;
    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        rewards[account] = earned(account);
        userRewardPerTokenPaid[account] = rewardPerTokenStored;
        _;
    }
    function rewardPerToken() public view returns (uint256) { return rewardPerTokenStored + 1; }
    function earned(address account) public view returns (uint256) { return rewards[account] + _balances[account] * (rewardPerToken() - userRewardPerTokenPaid[account]) / 1e18; }
    function stake(uint256 amount) external {
        _totalSupply += amount;
        _balances[msg.sender] += amount;
    }
    function withdraw(uint256 amount) external updateReward(msg.sender) {
        _totalSupply -= amount;
        _balances[msg.sender] -= amount;
    }
}
