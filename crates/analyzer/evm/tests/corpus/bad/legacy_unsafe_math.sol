// EXPECT: evm_legacy_unsafe_math
pragma solidity ^0.7.6;
contract Bad {
    mapping(address => uint256) public balances;
    function add(uint256 amount) external {
        balances[msg.sender] = balances[msg.sender] + amount;
    }
}
