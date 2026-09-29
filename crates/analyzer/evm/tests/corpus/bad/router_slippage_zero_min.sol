// EXPECT: evm_router_slippage_validation
// EXPECT: evm_swap_missing_deadline
pragma solidity ^0.8.20;
interface IRouter {
    function getAmountsOut(uint256, address[] calldata) external view returns (uint256[] memory);
    function swapExactTokensForTokens(uint256, uint256, address[] calldata, address, uint256) external returns (uint256[] memory);
}
contract Harvester {
    IRouter public immutable router;
    constructor(IRouter r) { router = r; }
    function harvest(uint256 amountIn, address[] calldata path) external {
        uint256[] memory quoted = router.getAmountsOut(amountIn, path);
        uint256 minOut = (quoted[quoted.length - 1] * 99) / 100;
        router.swapExactTokensForTokens(amountIn, minOut, path, address(this), block.timestamp);
    }
}
