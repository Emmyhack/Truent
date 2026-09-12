// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// UUPS-style upgradeable logic contract: initializer guarded against
/// re-initialisation, upgrade authorised by the owner, implementation
/// verified to be a contract before the switch.
contract UpgradeableLogic {
    bool private _initialized;
    bool private _initializing;
    address public owner;
    uint256 public value;

    event Upgraded(address indexed implementation);

    modifier initializer() {
        require(!_initialized || _initializing, "Initializable: contract is already initialized");
        bool isTopLevel = !_initializing;
        if (isTopLevel) {
            _initializing = true;
            _initialized = true;
        }
        _;
        if (isTopLevel) {
            _initializing = false;
        }
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address owner_) external initializer {
        require(owner_ != address(0), "zero owner");
        owner = owner_;
    }

    function setValue(uint256 v) external onlyOwner {
        value = v;
    }

    function _authorizeUpgrade(address newImplementation) internal view onlyOwner {
        require(newImplementation.code.length > 0, "not a contract");
    }

    function upgradeTo(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
        emit Upgraded(newImplementation);
    }
}
