# Incident-response runbook

Owner: repository maintainer (`.github/CODEOWNERS`). Disclosure channel:
`SECURITY.md`. Detection input: `security/alerts/*.sigma.yml` converted for
the SIEM, plus GitHub code-scanning alerts from `truent scan --sarif`.

## Severity

| Level | Definition | Response start | Examples |
|---|---|---|---|
| SEV1 | Active exploitation, credential/key compromise, or a poisoned release | immediately | leaked publish token; malicious version on npm/crates.io; database exfiltration |
| SEV2 | Confirmed vulnerability reachable in production, not yet exploited | < 4 h | a LIKELY finding from `truent exposure` on a deployed path |
| SEV3 | Vulnerability with a precondition, or in a non-production path | < 2 business days | POSSIBLE/UNLIKELY findings; unmaintained dependency with no known exploit |

## Steps

1. **Triage** — confirm with evidence (`truent exposure`, `truent probe`,
   the alert itself); assign a severity; open a private incident issue.
2. **Contain** — revoke the credential / token / key first, ask questions
   second. For a poisoned release: `npm deprecate` + `cargo yank` the version,
   delete the GitHub Release asset, and publish an advisory.
3. **Eradicate** — fix on a branch; `truent release-check --strict` must be
   READY before the fix ships; add the case to the regression corpus
   (`tests/corpus/bad/`) so it cannot return.
4. **Recover** — redeploy from a tagged, attested release; restore data per
   `disaster-recovery.md` if integrity is in doubt; rotate remaining secrets.
5. **Communicate** — users within 72 h for SEV1/SEV2 with what happened,
   what was affected, what they must do (rotate, upgrade).
6. **Learn** — blameless post-mortem within 5 business days; every action
   item gets an owner and a date; the detector gap that let it through
   becomes a Truent detector.

## Evidence handling

Preserve logs and artifacts before changing anything (`gh run download`,
database snapshot, container image digest). Never paste secrets into the
incident issue — reference the secret manager version instead.

## Contacts

- Maintainer: `@geekstrancend`
- npm / crates.io support: for takedown of a malicious version
- GitHub Security: for advisory publication (GHSA)
