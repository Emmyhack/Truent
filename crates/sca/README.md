# truent-sca

Software composition analysis for Truent: parses lockfiles (Cargo, npm, pip,
Poetry, Pipenv, Go, Yarn), matches every pinned dependency against an
advisory database (OSV JSON or RustSec), reports unpinned and unlocked
dependencies, and emits a CycloneDX 1.5 SBOM.

```bash
truent deps .                                  # pinning + lockfile checks, SBOM
truent deps . --advisory-db ./advisory-db      # + vulnerability matching, offline
truent deps . --sbom sbom.cdx.json
```

Advisory matching is only as current as the database you point it at; the
report says which database and how many advisories it held.
