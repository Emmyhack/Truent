// Adapted from pashov/skills fizz/templates/FuzzTester.sol (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent native path first, multi-chain.
// SPDX-License-Identifier: MIT
pragma solidity >=0.6.2 <0.9.0;

import {Handlers} from "./handlers/Handlers.sol";

/// @notice Entry point for fuzzing tests
contract FuzzTester is Handlers {
    constructor() payable {
        setup();
    }
}
