// EXPECT: evm_swap_missing_deadline
pragma solidity ^0.8.20;
interface IRouter { function swapExactTokensForTokens(uint256, uint256, address[] calldata, address, uint256) external returns (uint256[] memory); }
contract Rebalancer {
    IRouter public immutable router;
    constructor(IRouter r) { router = r; }
    function rebalance(uint256 amountIn, uint256 minOut, address[] calldata path) external {
        router.swapExactTokensForTokens(amountIn, minOut, path, address(this), block.timestamp);
    }
}
