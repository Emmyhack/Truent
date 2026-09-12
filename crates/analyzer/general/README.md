# truent-analyzer-general

Truent's analyzer for everything that is not a smart contract: any
repository's secrets, CI workflows, container and cluster configuration, and
application code in Python, JavaScript/TypeScript, Go and shell.

It is held to the same bar as the chain analyzers: a detector fires only on a
dynamic, attacker-influenced input — `eval("literal")` is not a finding,
`eval(request.args["q"])` is — a corpus of correct code must produce zero
findings, and every finding carries CWE, MITRE ATT&CK and NIST CSF
identifiers.

```bash
truent scan . --chain general      # this analyzer only
truent scan . --chain auto         # every applicable engine, per file
```
