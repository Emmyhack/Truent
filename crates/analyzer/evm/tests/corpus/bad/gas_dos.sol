// EXPECT: evm_unbounded_loop
// EXPECT: evm_push_payment_in_loop
// EXPECT: evm_missing_pause_mechanism
pragma solidity ^0.8.20;

contract Rewards is Ownable {
    address[] public holders;
    mapping(address => uint256) public balances;

    function join() external {
        holders.push(msg.sender);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function borrow(uint256 amount) external {
        balances[msg.sender] += amount;
    }

    function distribute() external onlyOwner {
        for (uint256 i = 0; i < holders.length; i++) {
            payable(holders[i]).transfer(1 ether);
        }
    }
}
