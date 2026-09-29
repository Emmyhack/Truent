// EXPECT: evm_encodepacked_hash_collision
pragma solidity ^0.8.20;
contract Registry {
    mapping(bytes32 => address) public owners;
    function register(string memory namespace, string memory name) external {
        bytes32 key = keccak256(abi.encodePacked(namespace, name));
        require(owners[key] == address(0), "taken");
        owners[key] = msg.sender;
    }
}
