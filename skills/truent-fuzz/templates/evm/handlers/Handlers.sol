// Adapted from pashov/skills fizz/templates/handlers/Handlers.sol (MIT, Copyright (c) 2024 AI Skills Contributors). Changes: Truent native path first, multi-chain.
// SPDX-License-Identifier: MIT
pragma solidity >=0.6.2 <0.9.0;

import "../Base.sol";

/// @notice Inherits from all the handlers to expose all entry points in a single contract.
///         Manages environment changes (e.g. current actor, current token, mocks setup, etc.).
abstract contract Handlers
{
	function setCurrentActor(uint256 entropy) public {
        actor = actors[entropy % actors.length];
    }
}