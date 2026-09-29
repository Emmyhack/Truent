// EXPECT: evm_permit_frontrun_dos
pragma solidity ^0.8.20;
interface IERC20Permit {
    function permit(address, address, uint256, uint256, uint8, bytes32, bytes32) external;
    function transferFrom(address, address, uint256) external returns (bool);
}
contract Vault {
    IERC20Permit public immutable token;
    mapping(address => uint256) public balances;
    constructor(IERC20Permit t) { token = t; }
    function depositWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        token.permit(msg.sender, address(this), amount, deadline, v, r, s);
        require(token.transferFrom(msg.sender, address(this), amount), "transfer");
        balances[msg.sender] += amount;
    }
}
