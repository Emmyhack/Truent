// EXPECT: evm_readonly_reentrancy
pragma solidity ^0.8.20;
contract Bad {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function getVirtualPrice() public view returns (uint256) {
        return address(this).balance * 1e18 / totalSupply;
    }
    function burn(uint256 shares) external {
        (bool ok, ) = msg.sender.call{value: shares}("");
        require(ok);
        totalSupply -= shares;
        balanceOf[msg.sender] -= shares;
    }
}
