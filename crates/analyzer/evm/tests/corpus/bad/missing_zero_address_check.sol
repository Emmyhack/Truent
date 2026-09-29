// EXPECT: evm_missing_zero_address_check
pragma solidity ^0.8.20;
contract Config {
    address public owner;
    address public oracle;
    constructor() { owner = msg.sender; }
    function setOracle(address _oracle) external {
        require(msg.sender == owner, "owner");
        oracle = _oracle;
    }
}
