# truent-skills

Truent's skill runtime: host, index, preflight and run
[agentskills.io](https://agentskills.io) security skill libraries.

Truent's engine is deterministic — it runs a contract and reports what it
observed. Most security work isn't like that. Triaging a cloud breach or
hunting DNS tunnelling means driving `aws`, `kubectl`, `tshark` and a SIEM, and
no compiled analyzer replaces those.

This crate lets Truent **host** that capability rather than pretend to
reimplement it.

```bash
truent skills source add mukul975/Anthropic-Cybersecurity-Skills
truent skills search T1048.003          # by ATT&CK technique
truent skills doctor                    # what's runnable on this machine
truent skills run analyzing-dns-logs-for-exfiltration --yes
```

## Two deliberate properties

**Sources are cloned, never vendored.** A library stays in its own repository
under its own licence and updates with `git pull`. Copying a third-party
catalogue into Truent would fork it on day one and leave Truent shipping a
stale, relicensed snapshot.

**Third-party output is `ADVISORY`, never engine-backed.** Truent's whole claim
is that it never presents as verified anything it did not verify. Running
someone else's script does not make its output reproducible, and the label says
so on every line that mentions it — in listings, in `show`, and after every
run.

## Safety

`skills run` executes third-party code that can touch cloud APIs, scanners and
live network traffic. It prompts before running, and **refuses outright when
stdin is not a terminal** unless `--yes` is passed, so a piped or CI invocation
can never silently execute it. `--dry-run` prints the command instead.

Many of these libraries contain offensive and dual-use techniques. Only run
them against systems you own or are explicitly authorised to test.
