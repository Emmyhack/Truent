// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// A lending pool that accrues interest before every balance change, checks
/// the position's health after it, bounds its fee, validates addresses,
/// casts through a checked bound, and validates its oracle answer.
interface IAggregator { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }
contract Pool {
    uint256 public constant MAX_FEE_BPS = 1_000;
    address public immutable governance;
    IAggregator public oracle;
    uint256 public feeBps;
    uint256 public borrowIndex = 1e18;
    uint256 public lastAccrual;
    mapping(address => uint256) public debt;
    mapping(address => uint128) public collateral;

    bool public paused;
    modifier onlyGovernance() { require(msg.sender == governance, "governance"); _; }
    modifier whenNotPaused() { require(!paused, "paused"); _; }
    function setPaused(bool _paused) external onlyGovernance { paused = _paused; }

    constructor(IAggregator _oracle, address gov) {
        require(address(_oracle) != address(0) && gov != address(0), "zero address");
        governance = gov;
        oracle = _oracle;
        lastAccrual = block.timestamp;
    }
    function setFeeBps(uint256 _feeBps) external onlyGovernance {
        require(_feeBps <= MAX_FEE_BPS, "fee cap");
        feeBps = _feeBps;
    }
    function setOracle(IAggregator _oracle) external onlyGovernance {
        require(address(_oracle) != address(0), "zero oracle");
        oracle = _oracle;
    }
    function _accrueInterest() internal {
        uint256 elapsed = block.timestamp - lastAccrual;
        borrowIndex += (borrowIndex * elapsed * 5) / (365 days * 100);
        lastAccrual = block.timestamp;
    }
    function deposit(uint256 amount) external whenNotPaused {
        _accrueInterest();
        require(amount <= type(uint128).max, "too large");
        collateral[msg.sender] += uint128(amount);
        require(_isHealthy(msg.sender), "unhealthy");
    }
    function borrow(uint256 amount) external whenNotPaused {
        _accrueInterest();
        debt[msg.sender] += amount;
        require(_isHealthy(msg.sender), "unhealthy");
    }
    function _isHealthy(address account) internal view returns (bool) {
        return uint256(collateral[account]) * price() >= debt[account] * 2e18;
    }
    function price() public view returns (uint256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = oracle.latestRoundData();
        require(answer > 0, "invalid price");
        require(block.timestamp - updatedAt < 1 hours, "stale");
        require(answeredInRound >= roundId, "stale round");
        return uint256(answer);
    }
}
