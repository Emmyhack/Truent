// EXPECT: evm_reentrancy_erc20
pragma solidity ^0.8.20;
interface IERC20 { function transfer(address, uint256) external returns (bool); }
contract Bad {
    mapping(address => uint256) private _balances;
    IERC20 public token;
    function withdraw(uint256 amount) external {
        token.transfer(msg.sender, amount);
        _balances[msg.sender] -= amount;
    }
}
