// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// EIP-712 permit with nonce, deadline and chain-id-bound domain separator —
/// every replay dimension covered.
contract Permit {
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("Permit"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "Permit: expired deadline");
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == owner, "Permit: invalid signature");
        allowance[owner][spender] = value;
    }
}
