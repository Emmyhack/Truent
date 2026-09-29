// EXPECT: evm_hardcoded_token_decimals
pragma solidity ^0.8.20;
contract Pricer {
    mapping(address => uint256) public priceOf;
    function valueOf(address token, uint256 amount) external view returns (uint256) {
        return (amount * priceOf[token]) / 1e18;
    }
}
