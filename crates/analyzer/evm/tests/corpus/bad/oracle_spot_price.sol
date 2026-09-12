// EXPECT: evm_oracle_spot_price
pragma solidity ^0.8.20;
contract Bad {
    uint256 public reserve0;
    uint256 public reserve1;
    function getPrice() external view returns (uint256) {
        return (reserve1 * 1e18) / reserve0;
    }
}
