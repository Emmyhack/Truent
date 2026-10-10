// SPDX-License-Identifier: MIT
pragma solidity >=0.6.2 <0.9.0;

/// A Foundry invariant harness: compiled only by the test runner, never
/// deployed. Its unguarded setUp, EOA "owner" and raw transfers are the
/// test's business, not findings.
import "forge-std/Test.sol";

contract VaultHarness is Test {
    address owner;
    address[] actors;

    function setUp() public {
        owner = msg.sender;
        actors.push(address(0x1));
    }

    function invariant_actorsNonEmpty() public view {
        assert(actors.length > 0);
    }

    function pickActor(address addy) internal view returns (address) {
        return actors[uint256(uint160(addy)) % actors.length];
    }
}
