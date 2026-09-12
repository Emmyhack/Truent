// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// Accounting vault with a deliberate bug: `withdraw` never checks the
/// balance, and the arithmetic is unchecked, so `total` underflows.
contract Vault {
    mapping(address => uint256) public balances;
    uint256 public total;
    function deposit(uint256 amount) external { balances[msg.sender] += amount; total += amount; }
    function withdraw(uint256 amount) external {
        unchecked { balances[msg.sender] -= amount; total -= amount; }
    }
}
