// EXPECT: evm_interest_not_accrued
pragma solidity ^0.8.20;
contract Lending {
    uint256 public borrowIndex = 1e18;
    uint256 public lastAccrual;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public collateral;
    function accrueInterest() public {
        uint256 elapsed = block.timestamp - lastAccrual;
        borrowIndex += (borrowIndex * elapsed * 5) / (365 days * 100);
        lastAccrual = block.timestamp;
    }
    function borrow(uint256 amount) external {
        require(collateral[msg.sender] >= amount * 2, "collateral");
        debt[msg.sender] += amount;
    }
    function repay(uint256 amount) external {
        accrueInterest();
        debt[msg.sender] -= amount;
    }
}
