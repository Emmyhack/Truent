// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Merkle airdrop: root is immutable and validated non-zero at construction,
/// claims are marked before the transfer, proof is verified.
contract MerkleAirdrop {
    bytes32 public immutable merkleRoot;
    mapping(address => bool) public claimed;
    mapping(address => uint256) public balanceOf;

    event Claimed(address indexed account, uint256 amount);

    constructor(bytes32 root) {
        require(root != bytes32(0), "zero root");
        merkleRoot = root;
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender], "already claimed");
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(_verify(proof, leaf), "invalid proof");
        claimed[msg.sender] = true;
        balanceOf[msg.sender] += amount;
        emit Claimed(msg.sender, amount);
    }

    function _verify(bytes32[] calldata proof, bytes32 leaf) internal view returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            computed = computed <= p
                ? keccak256(abi.encodePacked(computed, p))
                : keccak256(abi.encodePacked(p, computed));
        }
        return computed == merkleRoot;
    }
}
