// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Correct handling of caller-chosen tokens and NFTs: SafeERC20 wrappers,
/// decimals read from the token, forceApprove, and safeTransferFrom.
/// Administration sits behind a governance contract, not a single key.
interface IERC20 { function transfer(address, uint256) external returns (bool); function decimals() external view returns (uint8); }
interface IERC721 { function safeTransferFrom(address, address, uint256) external; }
library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal { require(token.transfer(to, amount), "transfer"); }
    function forceApprove(IERC20, address, uint256) internal {}
}
contract Handler {
    using SafeERC20 for IERC20;
    IERC721 public immutable nft;
    address public immutable governance;
    modifier onlyGovernance() { require(msg.sender == governance, "governance"); _; }
    constructor(IERC721 n, address gov) {
        require(gov != address(0), "zero governance");
        nft = n;
        governance = gov;
    }
    function sweep(IERC20 token, uint256 amount) external onlyGovernance {
        token.safeTransfer(governance, amount);
    }
    function normalise(IERC20 token, uint256 amount) external view returns (uint256) {
        return amount * 1e18 / (10 ** token.decimals());
    }
    function grant(IERC20 token, address router, uint256 amount) external onlyGovernance {
        token.forceApprove(router, amount);
    }
    function release(address to, uint256 tokenId) external onlyGovernance {
        nft.safeTransferFrom(address(this), to, tokenId);
    }
}
