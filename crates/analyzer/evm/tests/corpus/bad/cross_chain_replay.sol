// EXPECT: evm_cross_chain_replay_missing_chainid
pragma solidity ^0.8.20;
contract Bad {
    mapping(bytes32 => bool) public used;
    function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(to, amount));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0));
        require(!used[digest]);
        used[digest] = true;
        payable(to).transfer(amount);
    }
}
