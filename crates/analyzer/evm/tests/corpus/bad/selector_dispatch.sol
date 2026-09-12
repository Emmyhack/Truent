// EXPECT: evm_arbitrary_function_selector_dispatch
pragma solidity ^0.8.20;
contract Bad {
    function execute(address target, bytes calldata data) external {
        target.delegatecall(data);
    }
}
