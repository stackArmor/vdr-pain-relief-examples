# vdr-pain-relief-examples

**Public illustrative subset of the PAIN Relief taxonomy** — the standard,
auditable row format that maps a *machine-verified security control* to the *CWE
weakness class it provably counters* and the *deterministic scoring reduction* it
earns, for FedRAMP Rev5 VDR/VER PAIN scoring.

This repository exists so the **format is auditable and reusable**. It publishes
a handful of representative rows — an existence proof of the schema, governance,
and reasoning — not the full catalog. The maintained catalog is proprietary; these
show exactly how a row is structured, verified, and justified so that any
provider or assessor can read, reproduce, and challenge a PAIN Relief decision.

See the method paper: *PAIN Relief: A Verified-Control Method for Reducing
FedRAMP Rev5 VDR/VER PAIN and Exploitability*
(https://stackarmor.github.io/rfc-fedramp-vdr/vdr-pain-relief.pdf).

## What a row means

Two levers, kept strictly apart (a control belongs to one, by its causal
mechanism):

- **Impact** — a verified control that *bounds what a successful exploit yields*
  lowers a Modified impact metric High→Low (one rung, never None) and steps the
  PAIN level down.
- **Likelihood** — a verified control that *reduces whether the exploit succeeds*
  lowers a local `adjustedEPSS = EPSS × residualFactor` (multiplicative across
  controls, floored) and can move a finding to NLEV.

The discriminator: *if the exploit fully succeeds despite the control, is the
impact still full?* Yes → likelihood (egress control — an attacker who routes
around it gets full impact). No → impact (a schema-scoped DB credential caps
reach even on full success).

Nothing here edits the published EPSS or the CVSS base vector, softens a CISA
KEV / BOD 26-04 date, or changes the internet-reachability determination.

## The examples

| Row | Control | Counters | Lever |
|---|---|---|---|
| `CC-RUN-DISTROLESS` | no shell in image | CWE-78/77 | impact (MC/MI) |
| `CC-RUN-SELINUX-CONFINE` | SELinux domain confinement (STIG-verifiable) | ACE class | impact (MC/MI) |
| `CC-RATELIMIT-CONSUMPTION` | route rate limiting | CWE-400/1333/… | impact (MA) |
| `CC-NET-EGRESS-DENY` | egress control (firewall tiers) | CWE-917/94/… | likelihood |
| `CC-LIKE-EDR-BLOCK` | blocking-mode EDR/RASP | (under review) | likelihood |

`CC-RUN-SELINUX-CONFINE` illustrates verification from **STIG/SCAP** results
(DISA RHEL 8 STIG `RHEL-08-010450` + a per-process confined-domain check), not
just Kubernetes config.

## Files

- `examples.yaml` — the rows.
- `classes.yaml` — outcome classes the rows reference (ACE).
- `profiles/verification-sources.yaml` — per-platform predicates that prove each
  control is enforced.
- `schema/pain-relief.schema.json` + `validate.py` — the row schema and a
  validator.
- `GOVERNANCE.md` — the rules a row must satisfy.

## Governance in one line

A row earns credit only for an **enforced, machine-verifiable (or attested)**
control — never a *claimed* one (input sanitization and WAF signature coverage
stay in the VEX lane). See `GOVERNANCE.md`.
