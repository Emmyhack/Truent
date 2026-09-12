// EXPECT: evm_upgrade_path_verification
pragma solidity ^0.8.20;
contract Bad {
    address public implementation;
    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;
    }
}
