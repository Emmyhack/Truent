// EXPECT: evm_ecrecover_unvalidated
pragma solidity ^0.8.20;
contract Claims {
    mapping(address => bool) public claimed;
    function claim(address owner, bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad signature");
        claimed[owner] = true;
    }
}
