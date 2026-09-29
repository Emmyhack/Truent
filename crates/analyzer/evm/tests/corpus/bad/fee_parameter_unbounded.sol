// EXPECT: evm_fee_parameter_unbounded
pragma solidity ^0.8.20;
contract Fees {
    address public owner;
    uint256 public feeBps;
    constructor() { owner = msg.sender; }
    function setFeeBps(uint256 _feeBps) external {
        require(msg.sender == owner, "owner");
        feeBps = _feeBps;
    }
}
