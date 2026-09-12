# truent-pathways

The map from every class of software, web, system-design and cloud security
to what Truent does about it: a **native detector** (engine-verified), a
**hosted skill** subdomain (expert workflow driving the real tool), or an
explicit **assessment checklist** for controls that only a person with access
to the live system can verify.

```bash
truent pathways                    # the whole map, with coverage
truent pathways api-security       # one class
truent assess .                    # run every native engine, route the rest
truent threat-model .              # STRIDE from discovered entry points
```

Tests fail the build if a pathway names a detector the taxonomy does not know
or a skill subdomain that does not exist, so "covered" can never drift.
