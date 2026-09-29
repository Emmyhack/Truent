// EXPECT: evm_fixed_gas_eth_transfer
pragma solidity ^0.8.20;
contract Refunds {
    mapping(address => uint256) public owed;
    function claim() external {
        uint256 amount = owed[msg.sender];
        owed[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
