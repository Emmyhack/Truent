// EXPECT: evm_tx_origin_authentication
pragma solidity ^0.8.20;
contract Treasury {
    address public owner;
    constructor() { owner = msg.sender; }
    function drain(address payable to) external {
        require(tx.origin == owner, "not owner");
        to.transfer(address(this).balance);
    }
}
