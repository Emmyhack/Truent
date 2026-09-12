// EXPECT: evm_single_eoa_admin
pragma solidity ^0.8.20;
contract Bad {
    address public owner;
    constructor() { owner = msg.sender; }
    function withdrawAll() external {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
}
