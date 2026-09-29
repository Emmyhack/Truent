// EXPECT: evm_oracle_answer_unvalidated
pragma solidity ^0.8.20;
interface IAggregator { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }
contract Pricer {
    IAggregator public immutable feed;
    constructor(IAggregator f) { feed = f; }
    function price() external view returns (uint256) {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        require(block.timestamp - updatedAt < 1 hours, "stale");
        return uint256(answer);
    }
}
