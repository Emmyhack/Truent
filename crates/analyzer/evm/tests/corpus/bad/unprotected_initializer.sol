// EXPECT: evm_unprotected_initializer
pragma solidity ^0.8.20;
contract Bad {
    address public owner;
    function initialize(address owner_) external {
        owner = owner_;
    }
}
