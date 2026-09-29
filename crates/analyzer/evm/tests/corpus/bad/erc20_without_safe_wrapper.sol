// EXPECT: evm_erc20_without_safe_wrapper
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
contract Sweeper {
    address public owner;
    constructor() { owner = msg.sender; }
    function sweep(IERC20 token, uint256 amount) external {
        require(msg.sender == owner, "owner");
        require(token.transfer(owner, amount), "transfer failed");
    }
}
