# PRIVACY-AND-RETENTION.md

> **Disclaimer:** This describes the product's privacy design and how it maps to commonly cited
> obligations under the GDPR and CCPA/CPRA. It is **not legal advice**. Confirm applicability,
> roles (controller/processor), and lawful bases with counsel for your deployment and
> jurisdiction.

---

## 1. Privacy-by-design posture

MirrorTrace is built around **data minimization** and **purpose limitation**: the only data it
collects is what is necessary for a declared, lawful `scope_type` (self / consented /
public_figure / brand / safety_evidence). Anything outside that is rejected at A0 before
collection, so the cleanest privacy control is **not collecting in the first place**.

---

## 2. The core principle: aggregation of public data is itself the harm

A central, non-negotiable position of this product:

> **Aggregating otherwise-public data points into a sustained profile of a *private* person is
> itself a privacy harm — even if every individual data point was publicly visible.**

A single public post is public. A continuously updated, searchable, time-stamped dossier of a
private person — where they were, what they liked, who they interacted with — is surveillance,
and it is the exact harm a non-consensual tracking workflow would inflict. This is why:

- The scope model has **no "private person" scope** (COMPLIANCE.md §1).
- `private_person_tracking` is a `prohibited_analysis` token.
- Even "all from public sources" jobs are rejected when the subject is a non-consenting private
  individual.

This reflects the GDPR principle that processing must have a **lawful basis** and a
**specified, explicit, legitimate purpose**, and that aggregation/profiling can intrude on
rights even over "manifestly public" data. Publicness of a source does not by itself create a
lawful basis to build a profile.

---

## 3. GDPR mapping (where applicable)

| GDPR principle | How the product honors it |
|---|---|
| **Purpose limitation** (Art. 5(1)(b)) | Every job carries a declared `scope_type` = its purpose; data is used only for that purpose. No repurposing a `self` audit into surveillance of others. |
| **Data minimization** (Art. 5(1)(c)) | Collect only what the scope requires; single-URL mode by default; no outward crawling. |
| **Storage limitation** (Art. 5(1)(e)) | Default 30-day retention, 90-day hard max (see §4). |
| **Lawful basis** (Art. 6) | `self` = subject is the user; `consented` = consent (Art. 6(1)(a)) with record + revocation; `public_figure`/`brand` = limited to public-capacity / organizational data; `safety_evidence` = the user's own legitimate interest in evidence about themselves. |
| **Special category data** (Art. 9) | The product refuses inferences about sexuality/health/etc.; `romance_inference` and `gender_from_image` are forbidden precisely because they risk Art. 9 data. |
| **Data subject rights** (Arts. 15–22) | Deletion mechanism (§5), access/export of stored items, and human review for sensitive scopes. |

---

## 4. Retention

- **Default retention: 30 days** from collection for any stored evidence/finding.
- **Maximum retention: 90 days.** No item may be retained beyond 90 days without an explicit,
  logged, human-approved legal-hold (e.g. an active `safety_evidence` matter), and even then
  only the specific items under hold.
- Retention is **per-item** and enforced by a scheduled purge job that runs at least daily.
- Expired items are **hard-deleted** (not soft-deleted/flagged) from primary storage and
  scheduled for deletion from backups on the next backup rotation.
- Aggregated, non-identifying operational metrics (e.g. counts of rejected jobs) may be retained
  longer as they contain no personal data.

---

## 5. Deletion mechanism

1. **On-demand deletion:** the user can delete any item or an entire job from the UI; deletion
   is immediate in primary storage and queued for backups.
2. **Data-subject request (DSR):** a documented path for a subject (including a consented third
   party, or a person who appears in `safety_evidence`) to request access or deletion. Consent
   revocation by a `consented` subject triggers **immediate** stop-collection + deletion of
   their data.
3. **Cascade:** deleting a job deletes its evidence, derived findings, and cached fetches;
   audit-log entries (§6) are retained per §6 but contain no payload.
4. **Verification:** each deletion writes an audit entry (who/what/when) and a tombstone so
   re-collection of the same item is flagged.

---

## 6. Audit log

- **Immutable, append-only** log of: every A0 decision (pass/reject + reason), every collection,
  every access mode used, every deletion, every consent grant/revoke, and every human-review
  sign-off.
- Stores **metadata, not payloads** — enough to prove what happened and why, without itself
  becoming a second copy of personal data.
- Used for: incident response, DSR fulfillment proof, demonstrating purpose limitation, and the
  T10 acceptance evidence.
- Retention of the audit log follows legal/operational need and is separate from the 30/90-day
  content retention; it must not be used to reconstruct deleted content.

---

## 7. CCPA / CPRA considerations (where applicable)

- **No sale/share** of personal information; the product is a single-user audit tool, not a data
  broker, and does not monetize collected data.
- **Right to know / delete:** served by §5's deletion mechanism and stored-item export.
- **Data minimization & purpose:** CPRA's reasonable-necessity and proportionality expectations
  align with the scope model and retention limits above.
- **Sensitive personal information:** the product refuses to infer SPI categories (e.g.
  sex life/orientation), consistent with the `prohibited_analysis` list.

---

## 8. Data-subject considerations for non-users

Even within allowed scopes, third parties can appear:

- **Consented subjects:** consent must be **specific, informed, freely given, and revocable**;
  a record is kept; revocation deletes their data immediately.
- **Public figures:** limited to **public-capacity** activity; private life, home, family, and
  real-time location are out of scope.
- **`safety_evidence`:** material is preserved because it **involves/targets the user**;
  third-party data incidental to that evidence is minimized and access-controlled, and the
  matter is human-reviewed.
- **Incidental individuals** in a brand/public page (e.g. a named employee): the product must
  not re-identify or build a profile of them — doing so is `private_person_tracking`.

---

## 9. Security baseline (summary)

- Encryption in transit and at rest for stored evidence.
- Access controls; sensitive scopes (`safety_evidence`, `consented` onboarding) gated by human
  review.
- Secrets/API keys never logged; audit log stores metadata only.
- Purge and deletion jobs are themselves audited.
