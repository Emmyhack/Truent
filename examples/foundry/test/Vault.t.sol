// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Vault} from "../src/Vault.sol";
/// halmos explores every `check_*` function symbolically; a counterexample
/// is a concrete input that violates the assertion.
contract VaultTest {
    Vault v;
    function setUp() public { v = new Vault(); }
    /// With nothing deposited, a withdrawal must leave `total` at zero.
    /// The unchecked subtraction wraps instead: amount = 1 is a witness.
    function check_total_never_wraps(uint256 amount) public {
        v.withdraw(amount);
        assert(v.total() == 0);
    }
    function check_deposit_adds(uint256 a, uint256 b) public {
        v.deposit(a);
        v.deposit(b);
        assert(v.total() == a + b);
    }
}
