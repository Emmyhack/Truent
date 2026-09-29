// EXPECT: evm_unsafe_downcast
pragma solidity ^0.8.20;
contract Packed {
    struct Position { uint128 amount; uint128 debt; }
    mapping(address => Position) public positions;
    function record(uint256 amount) external {
        positions[msg.sender].amount = uint128(amount);
    }
}
