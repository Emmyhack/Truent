# truent-symbolic

Symbolic execution, settled honestly. Truent's engines match patterns and
follow dataflow; they do not solve constraints. This crate drives the tools
that do — **halmos**, **Mythril**, **hevm** — and owns the result under
Truent's honesty contract:

- a **counterexample** (a concrete input the solver produced) is recorded as
  a **proven** finding: `evm_symbolic_counterexample`;
- a timeout, an unknown solver result, or a check whose every path reverted
  is `evm_symbolic_unresolved` — a lead, never a pass.

```
truent symbolic examples/foundry                 # halmos if installed, else hevm, else mythril
truent symbolic path/to/project --tool mythril
truent symbolic path/to/project --format json --out symbolic.json
truent release-check . --symbolic-report symbolic.json
```

Without an executor on `PATH` the run reports an error and install hints —
it never reports "no findings".

The parsers are pure and tested against captured real output
(`tests/fixtures/`); `examples/foundry` in the repository is a deliberately
buggy vault with `check_*` tests that halmos breaks, and CI runs it.
