// EXPECT: evm_division_by_zero
pragma solidity ^0.8.20;
contract Bad {
    uint256 public totalShares;
    uint256 public totalAssets;
    function pricePerShare() external view returns (uint256) {
        return totalAssets * 1e18 / totalShares;
    }
}
