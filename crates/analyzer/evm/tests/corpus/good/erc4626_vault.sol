// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// ERC-4626 with OpenZeppelin's virtual-share/asset offset, which is the
/// standard inflation-attack mitigation. Correct CEI on withdraw.
contract Vault4626 {
    IERC20 public immutable asset;
    mapping(address => uint256) private _shares;
    uint256 private _totalShares;
    uint256 private constant VIRTUAL_SHARES = 1e3;
    uint256 private constant VIRTUAL_ASSETS = 1;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);

    constructor(IERC20 asset_) {
        asset = asset_;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function totalSupply() public view returns (uint256) {
        return _totalShares;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        return (assets * (_totalShares + VIRTUAL_SHARES)) / (totalAssets() + VIRTUAL_ASSETS);
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        return (shares * (totalAssets() + VIRTUAL_ASSETS)) / (_totalShares + VIRTUAL_SHARES);
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        require(shares > 0, "ERC4626: zero shares");
        _totalShares += shares;
        _shares[receiver] += shares;
        require(asset.transferFrom(msg.sender, address(this), assets), "ERC4626: transferFrom failed");
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function withdraw(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        require(_shares[msg.sender] >= shares, "ERC4626: insufficient shares");
        _shares[msg.sender] -= shares;
        _totalShares -= shares;
        require(asset.transfer(receiver, assets), "ERC4626: transfer failed");
        emit Withdraw(msg.sender, receiver, assets, shares);
    }
}
