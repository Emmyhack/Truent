// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAggregatorV3 {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
    function decimals() external view returns (uint8);
}

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

/// Staking with a Chainlink-priced reward: staleness and sanity checks on the
/// feed, slippage bound on the caller's side, CEI throughout, guarded.
contract Staking {
    IERC20 public immutable stakeToken;
    IAggregatorV3 public immutable priceFeed;
    mapping(address => uint256) public staked;
    uint256 public totalStaked;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    constructor(IERC20 token, IAggregatorV3 feed) {
        stakeToken = token;
        priceFeed = feed;
    }

    function stake(uint256 amount) external nonReentrant {
        require(amount > 0, "zero");
        staked[msg.sender] += amount;
        totalStaked += amount;
        require(stakeToken.transferFrom(msg.sender, address(this), amount), "transferFrom failed");
    }

    function unstake(uint256 amount, uint256 minValueUsd) external nonReentrant {
        require(staked[msg.sender] >= amount, "insufficient");
        uint256 valueUsd = _valueUsd(amount);
        require(valueUsd >= minValueUsd, "slippage");
        staked[msg.sender] -= amount;
        totalStaked -= amount;
        require(stakeToken.transfer(msg.sender, amount), "transfer failed");
    }

    function _valueUsd(uint256 amount) internal view returns (uint256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = priceFeed.latestRoundData();
        require(answer > 0, "invalid price");
        require(updatedAt != 0 && block.timestamp - updatedAt <= 1 hours, "stale price");
        require(answeredInRound >= roundId, "stale round");
        return (amount * uint256(answer)) / (10 ** priceFeed.decimals());
    }
}
