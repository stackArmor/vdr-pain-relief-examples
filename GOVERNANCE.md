# Governance

Adding a row grants a scoring discount across the whole estate. Treat every change
like a security setting change — because it is one (the memo's own rule:
mislabeling is a downgrade attack).

## Rules a row must satisfy

1. **A causal story, not a strength adjective.** "Egress deny breaks the staged
   fetch" qualifies. "EDR makes exploitation harder" never does. The rationale must
   name the mechanism by which the control interrupts the weakness class.
2. **Machine-verifiable or attested-artifact, never claimed.** The control must be
   provable from enforced configuration or telemetry a collector reads
   (`verification-sources.yaml`), or — for structure the platform cannot expose,
   like a field-encryption schema map — from a signed, dated, reusable artifact in
   the style of the VEX paper's surface attestations. Per-finding human claims are
   the VEX lane, not this repo.
3. **CWE-keyed, fail-open.** A row applies only to the CWE classes it lists. A
   finding with no CWE, an unmapped CWE, or a generic one (`NVD-CWE-noinfo`,
   bare CWE-20) earns nothing. Coverage gaps are a data-quality metric, not a
   reason to loosen keys.
4. **One rung.** Impact moves are High→Low only. None is reserved for the VEX
   disposition path (zero-impact is an applicability claim with its own
   governance). Likelihood rows feed the LEV inputs; nothing here touches
   reachability or KEV/BOD 26-04 dates.
   **4a. Impact does not stack.** Multiple rows firing on the same Modified
   metric still produce a single High→Low move (None is VEX-reserved, so the rung
   has one step); the evidence lines list every row that fired. Exploitability is
   different: it is continuous (adjustedEPSS), so its residual factors DO stack
   multiplicatively, bounded by STACKING_FLOOR (see "Exploitability moves").
5. **Disqualifiers are explicit.** If a deployment fact defeats the row (a writable
   volume under a read-only rootfs; a replayable broker feeding a crash-recoverable
   consumer), it is listed on the row and checked mechanically where possible.
6. **Back-test before merge.** Run the proposed row against a real scan corpus and
   attach the firing statistics to the PR. A row that moves a large fraction of the
   estate is presumed miscalibrated until argued otherwise.
7. **Refusals are recorded.** A rejected proposal goes into `rejected/REJECTED.md`
   with its reason. The refusal log is audit evidence that the table is curated,
   not accumulated.

## Review

- Row additions/changes: PR with two approvals, one of which is the security owner.
- The consuming plugin pins releases; a new release never auto-deploys into scoring.
- Every release's diff is reviewable as "which findings' scores can this change."

## Interaction with the public papers

The PAIN memo publishes the method, the row anatomy, the governance rules, and a
handful of illustrative rows. It states that the maintained catalog is proprietary
and that every applied credit carries its rationale in the finding evidence. Keep
the snippet honest: never publish a row here that the memo's snippet contradicts.

## Row visibility

Rows default to private. Marking a row `visibility: public` is a governance
decision (same review bar as adding one): public rows ship inside the public
plugin binary and appear in the white-paper snippet. Keep the public set small,
illustrative, and stable -- it is the "example, not a standard" tier. The
export tool (`scripts/export_public_snippet.py`) emits only public rows plus
the classes and verification profiles they reference; adapters and the
rejected log are never exported.

## Exploitability moves (likelihood lane)

FedRAMP exploitability is binary: LEV or NLEV. Controls never edit the published
EPSS number; they lower a LOCAL estimate, exactly as impact credits move Modified
C/I/A without touching the CVSS base vector.

    adjustedEPSS = max( EPSS * PRODUCT(residualFactor of each applicable row),
                        EPSS * STACKING_FLOOR )     # multiplicative stacking, floored
    LEV = KEV OR (adjustedEPSS >= 0.70) OR (floor AND NOT floor-defeated)

- **KEV is frozen by default**, with one governed, OFF-BY-DEFAULT exception.
  Normally a KEV stays LEV regardless of controls. An adopter MAY enable the
  **KEV exploitability downgrade**: a KEV may be classified NLEV iff the effective
  residual (product of applicable factors, floored) is <= 0.7 AND the resulting
  adjustedEPSS < 0.5 -- a deliberately high bar reflecting that KEV is *observed*
  exploitation, not a prediction. Even when it fires, this only relaxes the
  PAIN-matrix column: the **CISA KEV / BOD 26-04 due date always applies as the
  floor** (`VDR-TFR-KEV`: remediate by the CISA date "even if fully mitigated").
  So the finding's deadline = min(PAIN-matrix cell, CISA KEV date); NLEV can relax
  the deadline UP TO the CISA date, never past it. Rationale for off-by-default: a
  3PAO may reasonably challenge NLEV on an actively-exploited CVE, so the adopter
  turns it on knowingly and documents the controls.
- **The floor is binary**, defeated only by edge-auth (`move: floor-defeated`) --
  it is a reachability premise, not a probability, so it never carries a
  residualFactor.
- **EPSS is graduated.** Only `move: epss-residual` rows carry a residualFactor
  in (0,1); the threshold does the calibration work (a strong factor is needed to
  cross a near-certain finding). residualFactor values are governed, back-tested
  constants like the PAIN cut-points.
- **Stacking is multiplicative (defense-in-depth).** Every applicable
  `epss-residual` row's factor multiplies in, so independent controls compound:
  two 0.85 controls give 0.72x, not 0.85x. This rewards layered runtime defense,
  which is the point of the incentive.
- **Bounded by STACKING_FLOOR** (governed constant, illustrative 0.5 pending
  back-test): total reduction from stacking can never take adjustedEPSS below
  `EPSS * STACKING_FLOOR`. Real controls are not perfectly independent, so naive
  compounding would overstate; the floor caps it. Set once, governed, and
  reviewable like the cut-points.
- **Impact does NOT stack (rule 4a stands).** The Modified-impact rung is
  High->Low only -- None is VEX-reserved -- so multiple impact rows on one metric
  still yield one step. Stacking is exclusively an exploitability (continuous
  EPSS) behavior.
- **No taxonomy / no likelihood rows:** adjustedEPSS = EPSS, floor as-is -- stock
  FedRAMP LEV/NLEV, unchanged.

Both EPSS (published) and adjustedEPSS (local, with the row that moved it) appear
in output; the published number is never mutated in the record.
