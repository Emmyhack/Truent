// EXPECT: evm_unchecked_returns
pragma solidity ^0.8.20;
contract Bad {
    mapping(address => uint256) public balances;
    function payout(address to, uint256 amount) external {
        balances[to] -= amount;
        to.call{value: amount}("");
    }
}
