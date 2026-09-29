// EXPECT: evm_erc721_unsafe_transfer
pragma solidity ^0.8.20;
interface IERC721 { function transferFrom(address, address, uint256) external; }
contract Escrow {
    IERC721 public immutable nft;
    mapping(uint256 => address) public seller;
    constructor(IERC721 n) { nft = n; }
    function release(address to, uint256 tokenId) external {
        require(msg.sender == seller[tokenId], "seller");
        nft.transferFrom(address(this), to, tokenId);
    }
}
