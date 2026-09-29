// EXPECT: evm_vote_weight_current_balance
pragma solidity ^0.8.20;
interface IVotes { function balanceOf(address) external view returns (uint256); }
contract Governor {
    IVotes public immutable token;
    mapping(uint256 => uint256) public forVotes;
    mapping(uint256 => mapping(address => bool)) public voted;
    constructor(IVotes t) { token = t; }
    function castVote(uint256 proposalId) external {
        require(!voted[proposalId][msg.sender], "voted");
        voted[proposalId][msg.sender] = true;
        forVotes[proposalId] += token.balanceOf(msg.sender);
    }
}
