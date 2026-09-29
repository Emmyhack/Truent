// EXPECT: evm_unsafe_token_approval
pragma solidity ^0.8.20;
interface IERC20 { function approve(address, uint256) external returns (bool); }
contract Zapper {
    IERC20 public immutable token;
    constructor(IERC20 t) { token = t; }
    function zap(address spender) external {
        token.approve(spender, type(uint256).max);
    }
}
