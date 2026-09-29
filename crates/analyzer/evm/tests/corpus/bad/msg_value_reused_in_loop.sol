// EXPECT: evm_msg_value_reused_in_loop
pragma solidity ^0.8.20;
contract Mint {
    uint256 public constant PRICE = 0.1 ether;
    mapping(uint256 => address) public ownerOf;
    function mintMany(uint256[] calldata ids) external payable {
        for (uint256 i = 0; i < ids.length; i++) {
            require(msg.value >= PRICE, "underpaid");
            ownerOf[ids[i]] = msg.sender;
        }
    }
}
