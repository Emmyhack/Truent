// EXPECT: evm_unbacked_synthetic_mint
pragma solidity ^0.8.20;
contract Bad {
    uint256 public totalMinted;
    uint256 public totalCollateral;
    function deposit() external payable { totalCollateral += msg.value; }
    function mint(uint256 amount) external {
        totalMinted += amount;
        synth.mint(msg.sender, amount);
    }
}
