# Self-Exposure Grade (A+…F) — Mozilla-Observatory-style, over your OWN findings

One plain number a first-time visitor grasps in a second: **"my public footprint
is a D."** The grade is computed ONLY over the run's REAL `module_events` — the
exposures the detectors/enrichers already found about the user's own footprint —
and every point it deducts NAMES the finding that caused it, so the user can see
exactly which exposure to remove to raise their grade. No dial, no gauge, no
spinner — a letter and a transparent ledger.

Files:

| File | Role |
|------|------|
| `integrations/grade/exposure-grade.js` | The pure grader. `computeExposureGrade(events)` and the scope-gated `gradeForScopedRun(input, events)`. |
| `integrations/grade/_selftest.js` | Self-test (auto-discovered by `run-module-selftests.js`). |

## The model (borrowed: Mozilla HTTP Observatory / SecurityHeaders)

The [MDN HTTP Observatory](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring)
grades a site by starting every site at a **baseline of 100** and applying a set
of **weighted, named penalties** (e.g. *no Content-Security-Policy: −25*,
*Subresource Integrity not implemented: −50*), deducting from the baseline in one
pass and mapping the final number onto an **A+…F** band; its own docs call the
modifiers "essentially arbitrary… based on feedback from industry professionals."
SecurityHeaders.com uses the same A–F-by-which-headers-are-present shape.
([scoring.md](https://github.com/mozilla/http-observatory/blob/main/httpobs/docs/scoring.md))

We borrow that exact shape, **reframed from "security headers on a site" to
"privacy exposures of a SELF subject"**:

1. **Baseline 100.** A footprint with nothing found keeps its 100 = A+.
2. **Frozen named-deduction table** keyed on the frozen `EVENT_TYPES` vocab:

   | Exposure category | Base penalty |
   |-------------------|-------------:|
   | `SECRET_LEAK_PUBLIC` (leaked credential) | −45 |
   | `BREACH_RANGE_HIT` (HIBP-style hit) | −40 |
   | `BROKER_LISTING_HIT` (data-broker aggregation) | −30 |
   | `PII_POSTAL_PUBLIC` (self-published address) | −30 |
   | `PII_PHONE_PUBLIC` | −22 |
   | `TRACKER_SESSION_RECORDING` / `TRACKER_KEYLOGGING` | −20 |
   | `TRACKER_FINGERPRINTING` | −18 |
   | `EXPOSURE_SUMMARY` (e.g. re-identification mosaic) | −18 |
   | `PII_EMAIL_PUBLIC` | −15 |
   | `PII_HANDLE_PUBLIC` / `PII_GEO_HINT_PUBLIC` / `LEAK_REFERRER` | −12 |
   | `SELF_USERNAME` / `TRACKER_THIRD_PARTY` | −8 |
   | `SELF_PROFILE_URL` | −6 |
   | `COOKIE_THIRD_PARTY` | −5 |

3. Each instance's penalty is **scaled by the event's own frozen `RISK` and
   `VISIBILITY` rank** — a high-risk *indexed* (search-discoverable) leak bites
   full weight; a private, info-level one barely moves the grade. This reuses the
   existing vocab; it adds no new risk axis.
4. **Repeat-damped + capped:** the worst instance of a category takes full
   weight; each additional instance of the *same* category adds a shrinking
   amount (it is the same class of problem), and a single category can deduct at
   most 55 points — so one noisy category can't alone hide an otherwise-clean
   footprint.
5. The final `score = round(100 − Σ deductions)` maps onto **A+…F** bands
   (A≈90, B≈80, C≈70, D≈50, F<40, with +/− splits), mirroring the Observatory's
   A–F spacing.

The result's `breakdown` is the exact per-category ledger, sorted worst-first —
the same rubric the [portable evidence package](exports.md) publishes, so the
letter is **re-derivable from the bundle** (`score == round(baseline − Σ
deduction)`), the reproducibility Datasette/Frictionless publishing is built
around.

## Red lines (by construction)

- **No data, no grade.** Zero real `module_events` ⇒ `{ graded:false,
  reason:'no_data', grade:null }`. We NEVER fabricate a baseline "A" for an
  unscanned subject — that would be fake data.
- **scope=self only.** `gradeForScopedRun(input, events)` routes the input
  through the REAL `shared/scope.js` gate (read-only require — Codex owns that
  file; we never rewrite it) and grades ONLY an allowed `scope=self` run. A
  rejected input (`scope_rejected`) or any non-self scope (`not_self_scope`)
  returns NO grade. A grade is a self-audit artifact, never produced for another
  subject.
- **No protected attributes.** The deduction table keys only off the frozen
  vocab + frozen RISK/VISIBILITY ranks. There is no event type for
  sex/gender/sexuality/romance/relationship/live-location upstream, so no
  deduction can ever be driven by one.
- **No raw PII/QI read or emitted.** The grader reads only each event's
  `event_type`, `risk`, `visibility`, `confidence` — never the raw values.

## Usage

```bash
# Pure grade over a list of REAL module_events
node -e "const {computeExposureGrade}=require('./integrations/grade/exposure-grade'); \
  console.log(computeExposureGrade([]))"   # => { graded:false, reason:'no_data', grade:null, ... }

# Scope-gated entry (self-only; refuses stalking input via the real gate)
node -e "const {gradeForScopedRun}=require('./integrations/grade/exposure-grade'); \
  console.log(gradeForScopedRun({scope_type:'self',target_urls:['https://example.com/me'],goal:'track a private person'},[]).reason)"  # scope_rejected

# Self-test (also runs under: node integrations/run-module-selftests.js)
node integrations/grade/_selftest.js
```

## How a mature system wires this

- **Mozilla HTTP Observatory / SecurityHeaders** — the baseline-100,
  named-weighted-deduction, single-pass, A+…F-band grading model we mirror.
  <https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring> ·
  <https://github.com/mozilla/http-observatory/blob/main/httpobs/docs/scoring.md>
- **Datasette / Frictionless** — a grade is trustworthy only if it is
  reproducible from the published evidence; the `breakdown` ledger is emitted as
  a Frictionless resource so any consumer re-derives the letter from the rows,
  the way a Datasette site is recomputable from its own data.
  <https://datasette.io/> · <https://specs.frictionlessdata.io/data-package/>
