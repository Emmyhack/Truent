# Symbolic-execution example

A deliberately buggy `Vault` (unchecked subtraction in `withdraw`) and the
halmos `check_*` tests that expose it.

    truent symbolic examples/foundry          # runs halmos if installed
    truent symbolic examples/foundry --format json --out symbolic.json
    truent release-check . --symbolic-report symbolic.json

`check_total_never_wraps` produces a counterexample (`amount = 2^255`);
`check_deposit_adds` holds. The counterexample is reported as a **proven**
finding: it is a concrete input, not an inference.
