// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Snapshot-weighted voting, a swap with a caller-supplied deadline and an
/// asserted minimum, a permit wrapped in try, ETH sent with call, and a
/// chain-bound, nonce-bound, zero-checked signature.
interface IVotes { function getPastVotes(address, uint256) external view returns (uint256); }
interface IRouter { function swapExactTokensForTokens(uint256, uint256, address[] calldata, address, uint256) external returns (uint256[] memory); }
interface IERC20Permit {
    function permit(address, address, uint256, uint256, uint8, bytes32, bytes32) external;
    function transferFrom(address, address, uint256) external returns (bool);
    function allowance(address, address) external view returns (uint256);
}
contract Protocol {
    IVotes public immutable votes;
    IRouter public immutable router;
    IERC20Permit public immutable token;
    mapping(uint256 => uint256) public snapshotBlock;
    mapping(uint256 => uint256) public forVotes;
    mapping(address => uint256) public owed;
    mapping(address => uint256) public nonces;

    constructor(IVotes v, IRouter r, IERC20Permit t) { votes = v; router = r; token = t; }

    function castVote(uint256 proposalId) external {
        forVotes[proposalId] += votes.getPastVotes(msg.sender, snapshotBlock[proposalId]);
    }
    function swap(uint256 amountIn, uint256 amountOutMin, address[] calldata path, uint256 deadline) external {
        uint256[] memory amounts = router.swapExactTokensForTokens(amountIn, amountOutMin, path, address(this), deadline);
        require(amounts[amounts.length - 1] >= amountOutMin, "slippage");
    }
    function depositWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        if (token.allowance(msg.sender, address(this)) < amount) {
            try token.permit(msg.sender, address(this), amount, deadline, v, r, s) {} catch {}
        }
        require(token.transferFrom(msg.sender, address(this), amount), "transfer");
    }
    function claim() external {
        uint256 amount = owed[msg.sender];
        owed[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
    function verify(address owner, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(block.chainid, address(this), owner, nonces[owner]++));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == owner, "bad signature");
    }
}
