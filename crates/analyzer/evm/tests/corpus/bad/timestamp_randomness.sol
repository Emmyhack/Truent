// EXPECT: evm_timestamp_dependence
pragma solidity ^0.8.20;
contract Bad {
    address[] public players;
    function pickWinner() external returns (address) {
        uint256 idx = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % players.length;
        return players[idx];
    }
}
