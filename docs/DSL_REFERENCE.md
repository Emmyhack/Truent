# Truent Invariant DSL Reference

The Truent Invariant DSL (Domain Specific Language) is a declarative language for defining smart contract invariants—conditions that must always be true for a contract to be considered secure.

## Overview

An invariant is a Boolean expression that defines a critical property your contract must maintain. Truent checks these invariants throughout execution and reports violations.

## File Format

Invariant files use the `.invar` extension:

```
invariants.invar
token_rules.invar
security_checks.invar
```

## Basic Syntax

### Invariant Declaration

```
invariant <name> {
  description: "<human-readable description>"
  severity: <critical|high|medium|low>
  cwe: "<CWE-XXX>"
  target: <evm|solana|move>
  
  condition: <expression>
  
  remediation: "<fix instructions>"
  reference: "<url>"
}
```

### Example: Balance Conservation

```
invariant balance_conservation {
  description: "Total supply remains constant except during mint/burn"
  severity: critical
  cwe: "CWE-682"
  target: evm
  
  condition: (msg.value + balance_increase == total_outflow)
  
  remediation: "Ensure all balance changes are tracked and equivalent"
  reference: "https://docs.truent.dev/invariants/balance-conservation"
}
```

## Data Types

The DSL supports multiple data types for expressing conditions:

| Type | Example | Usage |
|------|---------|-------|
| `uint` | `1000` | Numeric values |
| `address` | `0x1234...` | Account addresses |
| `bool` | `true` | Boolean conditions |
| `bytes` | `0xdead` | Byte sequences |
| `string` | `"owner"` | Text values |

## Operators

### Comparison

```
== Equal
!= Not equal
<  Less than
>  Greater than
<= Less than or equal
>= Greater than or equal
```

### Logical

```
&&  AND (both must be true)
||  OR (at least one must be true)
!   NOT (negate condition)
```

### Arithmetic

```
+   Addition
-   Subtraction
*   Multiplication
/   Division
%   Modulo
```

### State Access

```
storage.<variable>    Access contract storage
msg.sender            Call message sender
msg.value             Call value
balance.<address>     Account balance
```

## Built-in Functions

### Utility Functions

```
len(array)           Array/string length
contains(array, x)   Check element presence
sum(array)           Sum numeric array
max(array)           Maximum value
min(array)           Minimum value
count(array, x)      Count occurrences
```

### Access Control

```
hasRole(address, role)      Check role membership
isOwner(address)            Check owner status
isApproved(addr, spender)   Check approval
```

### Numeric

```
safeMul(a, b)               Multiply without overflow
safeAdd(a, b)               Add without overflow
safeSub(a, b)               Subtract safely
```

### Accumulation

```
forAll(array, condition)    All elements match
exists(array, condition)    Any element matches
```

## Expression Examples

### Simple Conditions

```
invariant non_zero_balance {
  condition: (balance > 0)
}
```

### Logical Combinations

```
invariant owner_controlled {
  condition: (msg.sender == owner) && (hasRole(msg.sender, "ADMIN"))
}
```

### Collection Operations

```
invariant no_duplicate_entries {
  condition: forAll(entries, !contains(errors, @current))
}
```

### State Validation

```
invariant paused_state_valid {
  condition: (isPaused == false) || (totalSupply == 0)
}
```

### Arithmetic Safety

```
invariant safe_transfers {
  condition: safeAdd(balance, amount) <= MAX_UINT256
}
```

## Scopes

Invariants can target specific scopes within contracts:

### Function Scope

Check invariant only during specific function:

```
invariant within_transfer_function {
  scope: function(transfer)
  condition: (msg.sender == caller) && (recipientBalance_after > recipientBalance_before)
}
```

### State Scope

Check only when state changes:

```
invariant on_state_change {
  scope: state
  condition: (timestamp < block.timestamp)
}
```

### Global Scope (default)

Check across entire contract execution:

```
invariant global_constraint {
  scope: global
  condition: (totalSpent <= budget)
}
```

## Metadata

### Severity Levels

```
severity: critical     System may be compromised
severity: high         Significant security risk
severity: medium       Important to address
severity: low          Best practice improvement
```

### CWE References

Include Common Weakness Enumeration codes:

```
cwe: "CWE-841"    Improper Enforcement of Behavioral Workflow
cwe: "CWE-682"    Incorrect Calculation
cwe: "CWE-347"    Improper Verification of Cryptographic Signature
```

### Target Chains

Specify which blockchains the invariant applies to:

```
target: evm       Ethereum, Polygon, Arbitrum, etc.
target: solana    Solana blockchain
target: move      Aptos, Sui, Move-based chains
```

### Remediation

Provide clear fix instructions:

```
remediation: "Add checks to ensure sender is owner before allowing state changes"
```

## Advanced Patterns

### Temporal Invariants

Conditions involving time:

```
invariant time_lock_enforced {
  condition: (currentTime >= lockReleaseTime) || (balance == 0)
}
```

### Quantified Expressions

```
invariant all_transfers_logged {
  condition: forAll(transfers, isLogged(@current))
}

invariant valid_signer_exists {
  condition: exists(signers, (address != 0x0))
}
```

### Transitive Conditions

```
invariant consistent_balances {
  condition: (sum(accountBalances) == totalSupply) && 
             (totalSpent <= totalReceived)
}
```

### Permission Hierarchies

```
invariant admin_override_safe {
  condition: (hasRole(caller, "ADMIN") && isValidOperation()) ||
             (hasRole(caller, "USER") && isAllowedUserOp())
}
```

## Comments

Add comments to clarify your invariants:

```
invariant example {
  // Single-line comment
  
  /* Multi-line comment
     explaining the invariant
     in detail */
  
  description: "..."
  condition: (x > 0)  // Inline comment
}
```

## Composition

Combine multiple invariants into groups:

```
group access_control {
  invariant owner_only { ... }
  invariant role_based { ... }
  invariant multi_sig { ... }
}
```

## Chain-Specific Syntax

### EVM-Specific

```
invariant evm_example {
  target: evm
  
  condition: (msg.sender.code.length == 0)  // EOA only
}
```

With EVM-specific functions:

```
isContract(address)        Check if address is smart contract
isEOA(address)            Check if externally owned account
codeSize(address)         Get contract code size
```

### Solana-Specific

```
invariant solana_example {
  target: solana
  
  condition: (signer.is_signer == true)
}
```

With Solana-specific functions:

```
isSigner(account)         Check if account signed
isWritable(account)       Check if writable
isOwned(account)          Check account ownership
```

### Move-Specific

```
invariant move_example {
  target: move
  
  condition: (resource_exists(@creator))
}
```

With Move-specific functions:

```
exists(resource)          Resource exists
borrowed(reference)       Reference is borrowed
moved(value)             Value was moved
```

## Pre-defined Invariant Library

Truent includes 22 built-in invariants organized by category:

### Balance & Arithmetic (5)
- `balance_conservation` - Total supply constant
- `no_integer_overflow` - No arithmetic overflow
- `no_integer_underflow` - No arithmetic underflow
- `positive_balance` - Balance always non-negative
- `supply_tracking` - Total supply matches sum

### Access Control (4)
- `owner_only_function` - Restricted to owner
- `role_based_access` - Role checks enforced
- `admin_override_safe` - Admin has safe override path
- `permission_consistency` - Roles are consistent

### State Consistency (4)
- `state_immutability` - Immutable state unchanged
- `state_transition_valid` - State transitions are valid
- `no_reentrancy` - Reentrancy guards present
- `paused_state_valid` - Pause mechanism consistent

### Cross-Chain (3)
- `bridge_conservation` - Assets conserved in bridge
- `oracle_freshness` - Price feed recent
- `canonical_state` - Single source of truth

### Transaction Safety (6)
- `signature_validation` - Signatures verified
- `nonce_ordering` - Nonces in order
- `gas_efficiency` - Gas-efficient patterns
- `safe_delegatecall` - Delegatecall safe
- `safe_selfdestruct` - No selfdestruct vulnerabilities
- `no_timestamp_dependence` - No block.timestamp abuse

## Using Built-in Invariants

Reference built-in invariants in your config:

```toml
[invariants]
enabled = ["balance_conservation", "no_reentrancy", "owner_only_function"]
```

## Validation & Testing

### Syntax Validation

```bash
truent doctor          # Validates all invariants
```

### Dry Run

```bash
truent check ./contracts --dry-run
```

### Debug Mode

```bash
truent check ./contracts --verbose --debug
```

Prints detailed analysis of each invariant check.

## Best Practices

1. **Be Specific** - Express exact mathematical relationships, not approximate ones
2. **Use Clear Names** - Name invariants after the property they check
3. **Document Intent** - Explain why the invariant matters in description
4. **Reference Standards** - Include CWE references when applicable
5. **Provide Fixes** - Always include remediation guidance
6. **Test Violations** - Create test cases that violate each invariant
7. **Chain Awareness** - Account for chain-specific behavior
8. **Performance** - Keep conditions simple for faster analysis

## Common Patterns

### Owner Protection

```
invariant owner_protected {
  condition: (msg.sender == owner) || (hasRole(msg.sender, "APPROVED"))
}
```

### Rate Limiting

```
invariant rate_limit {
  condition: (lastCall + cooldown < now) || (operationCounter < maxPerBlock)
}
```

### Circuit Breaker

```
invariant circuit_breaker {
  condition: !emergencyStop || (emergencyStop && balance == 0)
}
```

### Whitelist Enforcement

```
invariant whitelist_enforced {
  condition: contains(whitelist, msg.sender)
}
```

## Debugging Invariants

When an invariant fails, Truent shows:
- **Line number** - Where the invariant is defined
- **Expression** - The condition that failed
- **Context** - Values of relevant variables at failure time
- **Stack trace** - Call hierarchy leading to failure
- **Suggestion** - Recommended fix

Example violation output:

```
✗ Owner Protection Failed
  Condition: (msg.sender == owner) || (hasRole(msg.sender, "APPROVED"))
  
  Context:
    msg.sender     = 0xdeadbeef...
    owner          = 0xcafebabe...
    hasRole result = false
  
  Stack:
    transfer() called from withdraw()
    withdraw() called from main()
```

## Migration Guide

### From OpenZeppelin Guards

```
OLD: require(msg.sender == owner);
NEW: invariant owner_check {
       condition: (msg.sender == owner)
     }
```

### From Custom Checks

```
OLD: if (totalSpent > budget) revert();
NEW: invariant budget_enforcement {
       condition: (totalSpent <= budget)
     }
```

## Performance Considerations

- Simple conditions: < 1ms
- Complex expressions with 10+ checks: 5-10ms
- Large array operations: 10-50ms (depends on size)

Optimize by:
1. Using built-in invariants (pre-optimized)
2. Keeping conditions simple
3. Avoiding nested loops
4. Caching frequently checked values

## Soroban Invariant DSL (.sinv format)

The `.sinv` declarative format allows authors to define chain-specific invariants compiled directly into Truent's binary. Under `invariants/soroban/`, each rule captures a security invariant specific to Stellar's Soroban smart contract environment.

### Format Specification

```toml
# Comments start with #
invariant = "<chain_prefix>_<name>"
severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
chain = "soroban"
description = "<one-line explanation of the security property>"
message = "<failure message reported to the developer>"
references = [
  "<url1>",
  "<url2>"
]
```

### Worked Soroban Examples

#### 1. Admin-Only Upgrade Protection (`invariants/soroban/admin_only_upgrade.sinv`)

Guards Soroban's contract upgradeability pathway (`update_current_contract_wasm`). Ensures an unauthorized caller cannot overwrite contract bytecode without an explicit `admin.require_auth()` check.

```toml
invariant = "sor_admin_only_upgrade"
severity = "CRITICAL"
chain = "soroban"
description = "WASM contract bytecode update executed without admin require_auth check"
message = "Upgrade function at {line} executes update_current_contract_wasm without admin authorization"
references = [
  "https://developers.stellar.org/docs/learn/smart-contract-internals/authorization",
  "https://github.com/stellar/soroban-examples"
]
```

#### 2. Storage TTL Extended on Persistent Writes (`invariants/soroban/ttl_extended_persistent_writes.sinv`)

Addresses Soroban's state archival mechanism. Because persistent storage entries expire unless explicitly renewed, any state write must accompany an `extend_ttl` or `.bump()` call to prevent contract state loss.

```toml
invariant = "sor_ttl_extended_persistent_writes"
severity = "HIGH"
chain = "soroban"
description = "Persistent storage write lacks extend_ttl or bump call risking state archival"
message = "Function at {line} writes persistent storage without extending entry TTL threshold"
references = [
  "https://developers.stellar.org/docs/learn/smart-contract-internals/state-archival"
]
```

#### 3. Balance Conservation Invariant (`invariants/soroban/balance_conservation.sinv`)

Enforces monetary conservation across token and vault state transitions: a balance decrement for sender $A$ must equal balance increment for recipient $B$, preventing unauthorized inflation or token destruction.

```toml
invariant = "sor_balance_conservation"
severity = "HIGH"
chain = "soroban"
description = "Token or vault state mutation does not maintain total balance conservation"
message = "Transfer function at {line} updates account balances with raw unverified delta"
references = [
  "https://developers.stellar.org/docs/tokens/token-interface"
]
```

## Examples

See `examples/` directory for complete examples:
- `examples/evm_token.sol` - ERC-20 token invariants
- `examples/solana_token_transfer.rs` - Solana program invariants
- `examples/account_abstraction.invar` - Abstract account invariants
