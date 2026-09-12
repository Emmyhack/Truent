// EXPECT: evm_merkle_root_zero_default
pragma solidity ^0.8.20;
contract Bad {
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;
    function claim(uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(verify(proof, merkleRoot, leaf), "bad proof");
        claimed[msg.sender] = true;
    }
    function verify(bytes32[] calldata, bytes32, bytes32) internal pure returns (bool) { return true; }
}
