# LexGuard / AICTE FDR Guard

## Complete project guide and 4-5 minute demonstration script

This document is the complete demonstration and explanation guide for the
LexGuard project. It describes what problem the project addresses, what
happens after login, what each role can see and do, the major workflows, the
technical trust and security controls, and a ready-to-read video script.

> **Important prototype notice:** This project is a local prototype. The
> bank responses are simulated, no AICTE or bank system is connected, and the
> sample reminder and release rules are not official policy. Do not present
> synthetic records as real financial or institutional records.

---

## 1. Project identity and problem statement

### Project name

**LexGuard: AICTE FDR Guard and forensic evidence management platform**

### Problem being addressed

Institutions submit security deposits and Fixed Deposit Receipts (FDRs), but a
manual or disconnected process makes it difficult to:

- know which instruments are active, expiring, matured, renewed, released, or
  under review;
- prove whether an FDR value came from an institution claim or an independent
  bank confirmation;
- detect duplicate FDR references and mismatched values;
- keep uploaded receipts private while still making them reviewable;
- preserve document versions, hashes, evidence custody, and audit history;
- coordinate institution users, regional officers, reviewers, and administrators;
- follow a controlled release/refund process instead of treating maturity as
  automatic release; and
- produce useful reports without losing the underlying traceability.

### Proposed solution

LexGuard combines two related workspaces:

1. **AICTE FDR Guard** - a security-deposit/FDR registry and workflow system.
2. **LexGuard forensic workspace** - document integrity, evidence, cases,
   metadata, chain of custody, vault, reports, and audit functions.

The central design principle is separation of trust levels:

- **Institution claimed value**: what the submitting institution entered.
- **OCR candidate value**: what text extraction suggested from an uploaded
  document. OCR is only a candidate and has unavailable confidence in this
  prototype.
- **Bank-confirmed value**: an independently submitted response through a
  short-lived, single-use verification link.

These values are stored and displayed separately so that an unverified claim
cannot silently become an official-looking confirmation.

---

## 2. How to run the website

From the repository folder in PowerShell:

```powershell
py -3.11 -m pip install -r requirements.txt
$env:LEXGUARD_SESSION_SECRET = (py -3.11 -c "import secrets; print(secrets.token_urlsafe(48))")
py -3.11 -m uvicorn app:app --reload --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

The application redirects `/` to the sign-in page. The session secret must be
at least 32 characters and should be stored locally rather than committed.

### Synthetic demonstration accounts

The project README defines these local-only accounts:

| FDR role | Username | Password |
|---|---|---|
| Bureau Admin | `demo-admin` | `DemoAdmin!2026` |
| Institution User | `demo-institution` | `DemoInstitution!2026` |
| Regional Officer | `demo-officer` | `DemoOfficer!2026` |

The intended initializer is:

```powershell
py -3.11 seed_demo.py --allow-demo-seed
```

These accounts and records are fictional. Change or remove them before any
shared or deployed use.

---

## 3. What happens on first login

1. The user opens the website and sees **Sign in to your workspace**.
2. The user enters a username and password.
3. The server validates the credentials against the SQLite user database.
4. The session stores the username and role.
5. The user is redirected to the **AICTE FDR Guard Overview dashboard**.
6. The menu is generated from the role:
   - institution and regional scope limits which FDR records are visible;
   - privileged actions are checked again on the server, not only hidden in
     the menu.
7. The FDR dashboard displays a **DEMO MODE** banner explaining that bank
   responses are simulated.
8. If the user opens a retained LexGuard page, the application may require the
   separate encrypted evidence vault to be configured and unlocked.
9. A first-time user can use **Register** to create a basic account. New
   accounts should then be assigned the appropriate role and FDR institution
   scope by an administrator.

### Session controls

- **Sign out** ends the authenticated session.
- **Lock Vault** keeps the account signed in but requires the vault unlock
  flow before protected forensic pages can be opened again.
- Forms use CSRF tokens.
- The FDR portal checks that the current database role is still valid when a
  request is made.

---

## 4. FDR roles and what each login can do

The FDR portal uses these role names. The older LexGuard workspace uses
`Admin`, `Investigator`, `Analyst`, and `Viewer`; the application maps those
legacy roles to the FDR concepts where necessary.

### 4.1 Institution User

Typical purpose: submit and maintain an institution's own security-deposit
records.

Can:

- open the FDR overview, registry, verification center, maturity radar,
  renewal history, release requests, and reports;
- see only institutions assigned to the account;
- create a new FDR submission;
- upload a PDF, PNG, JPG, or JPEG receipt up to 10 MB;
- review OCR candidate values and manually enter claimed values;
- edit claimed field values;
- attach supporting documents to an FDR;
- start a release/refund eligibility request;
- resubmit a release request after clarification;
- inspect discrepancy history and the action timeline.

Cannot:

- issue bank verification links;
- resolve discrepancies;
- perform officer scrutiny or recommendation;
- approve or release a request;
- administer institutions, users, settings, or the audit chain.

### 4.2 Regional Officer

Typical purpose: independently review assigned institution records and
coordinate verification.

Can:

- view assigned institution scopes;
- inspect registry records, field-by-field verification states, documents,
  discrepancies, renewals, maturity alerts, and reports;
- generate a secure verification link for a selected FDR field;
- scrutinize release requests;
- request clarification;
- re-evaluate an ineligible request;
- recommend an eligible request;
- resolve a discrepancy after the field is bank-confirmed and a resolution
  note is supplied.

Cannot:

- approve the final recommendation;
- confirm the final release;
- administer all institutions or prototype settings unless separately given
  administrator privileges.

### 4.3 Bureau Admin

Typical purpose: system owner and competent-authority workflow participant.

Can do everything an institution user and officer can do, plus:

- view all institutions and all FDR records;
- create institutions and assign users to institution scopes;
- view the FDR audit trail and verify the SHA-256 audit chain;
- change prototype reminder thresholds and virtual demo date offset;
- version release eligibility rules;
- approve or reject recommended release requests;
- confirm the release process;
- manage legacy LexGuard users, roles, and deletions;
- access the forensic vault, reports, and all protected pages.

### 4.4 Viewer / legacy role

`Viewer` is the legacy read-oriented role and maps to the FDR concept of an
institution-scoped user. Its visible menu is restricted compared with the
administrator and officer roles. The legacy workspace uses the explicit
`Viewer` role for user management and access control.

### 4.5 Bank Verifier

The bank verifier does not log in with a normal account. An authorized officer
generates a field-specific link. The verifier opens that link, sees only the
requested field, and submits a simulated response. The link:

- is random and time-limited to 24 hours;
- is stored server-side as a SHA-256 token hash;
- is single-use;
- is revoked when a new link for the same field is issued;
- cannot be reused after consumption or expiry.

---

## 5. FDR Guard navigation and features

### 5.1 Overview dashboard (`/fdr/dashboard`)

The first logged-in screen shows:

- total instruments in the user's authorized scope;
- recorded deposit value;
- active instruments;
- instruments expiring within 30 days;
- instruments with pending bank verification;
- open discrepancies;
- release requests awaiting action;
- overdue instruments;
- matured instruments;
- renewals pending;
- lifecycle distribution chart;
- maturity trend by month;
- prioritized FDRs requiring attention;
- deadline notifications.

The dashboard links each important KPI to the relevant filtered registry or
maturity view. It also runs the prototype maturity scan when opened.

### 5.2 FDR Registry (`/fdr/registry`)

The registry is the searchable working list. Users can:

- search by FDR number, bank, or institution;
- filter by lifecycle status;
- open an instrument detail page;
- see maturity date, institution, bank, amount, pending fields, and open
  discrepancies;
- work only with records inside their authorized scope.

### 5.3 New Submission (`/fdr/new`)

Available to Institution Users and Bureau Admins.

The submission process is:

1. Upload a receipt document.
2. Extract text using the existing OCR module.
3. Display labelled candidate values when detected:
   FDR number, bank, branch, amount, issue date, maturity date, and holder.
4. Review or correct every value manually.
5. Select the institution.
6. Optionally select an original FDR being replaced.
7. Submit the claimed values.

Accepted receipt types are PDF, PNG, JPG, and JPEG. The upload is stored
outside the static web root and receives a SHA-256 digest.

### 5.4 Instrument Detail (`/fdr/{id}`)

The detail page is the main review screen. It contains:

- institution and region;
- FDR number, bank, branch, and amount;
- lifecycle status;
- replacement relationship and renewal history;
- claimed-versus-bank-confirmed comparison for every required field;
- OCR candidate and confidence-unavailable notice;
- field value history;
- secure bank-link generation for officers;
- verification request history;
- private supporting documents and SHA-256 prefix;
- discrepancy history and resolution controls;
- release/refund request form;
- application audit timeline.

Required tracked fields are:

- FDR number;
- issuing bank;
- bank branch;
- deposit amount;
- issue date;
- maturity date;
- holder/beneficiary.

### 5.5 Verification Center (`/fdr/verification`)

This page gathers field-level verification work in one place. It shows the
institution claim, current status, and bank-confirmed value where available.
It helps reviewers focus on pending, mismatched, or confirmed fields.

### 5.6 Secure bank verification

An officer selects one field on an FDR detail page and generates a link. The
bank verifier opens the public link and submits one of the supported responses:

- confirm;
- dispute;
- clarification.

The response is stored with its source and timestamp. A confirmed value can
change the field to **Bank-confirmed**. A differing value creates a
**Mismatch** and an open discrepancy. A discrepancy can only be resolved
after the claim matches an independently bank-confirmed value.

### 5.7 Maturity Radar (`/fdr/maturity`)

The radar identifies:

- upcoming maturity dates;
- urgency windows;
- overdue instruments;
- reminder notifications;
- records that need renewal or another explicit action.

The prototype reminder worker scans hourly while the application process is
running, and the dashboard/radar can also trigger a scan. Maturity alone does
not automatically release an instrument.

### 5.8 Renewal History (`/fdr/renewals`)

A replacement FDR can point to the original instrument. The original remains
in the database and the replacement relationship is visible. This preserves a
traceable chain rather than overwriting history.

### 5.9 Release and Refund Requests (`/fdr/releases`)

The release lifecycle separates duties:

1. Institution submits a reason.
2. The system evaluates eligibility using the active rule-set version.
3. Regional Officer begins scrutiny.
4. Officer requests clarification, re-evaluates, or recommends.
5. Bureau Admin approves or rejects.
6. Bureau Admin confirms the release process.
7. The instrument becomes **Released** only after the final release action.

Each request records its eligibility result, checklist, rule-set version,
decision note, actor, and timestamps.

### 5.10 Reports and Analytics (`/fdr/reports`)

The page provides counts and downloadable CSV reports for:

- complete FDR registry;
- pending verifications;
- overdue instruments;
- open discrepancies;
- renewal/replacement history.

Exports are scope-filtered so a non-admin cannot export records outside the
user's authorized institutions.

### 5.11 Institutions (`/fdr/institutions`)

Bureau Admins can:

- create an institution and region;
- assign existing user accounts to an institution;
- review current assignments.

Scope assignment is part of the server-side access control model.

### 5.12 Audit Trail (`/fdr/audit`)

Bureau Admins can inspect recent FDR events and verify the canonical
SHA-256 chain. Each event includes actor, role, action, entity, summary,
timestamp, previous hash, and current event hash.

This is tamper-evident application history, not an externally immutable
blockchain or independent ledger.

### 5.13 Prototype Settings (`/fdr/settings`)

Bureau Admins can configure:

- reminder thresholds such as `90,60,30,7`;
- a virtual demo-date offset;
- whether release eligibility requires a supporting document;
- whether all critical fields must be bank-confirmed;
- whether open discrepancies block release.

Saving settings creates a new rule-set version. Existing release evaluations
retain the version with which they were calculated. Settings are sample
controls and must be validated against current official policy.

---

## 6. Retained LexGuard forensic workspace

The left navigation after login also contains the original LexGuard features.
Depending on role and vault state, the user can access:

### Dashboard (`/dashboard`)

Shows database-derived document and evidence totals, recent ledger activity,
recent audit activity, and recent uploads.

### Documents (`/documents`)

Users can:

- register a document against a case;
- select document type and upload a file;
- open document details;
- maintain document versions;
- view the current version;
- inspect the hash-chain ledger;
- run forensic analysis;
- verify document integrity.

Document versions and hashes help show whether a file has changed.

### Forensic analysis

The document forensic workflow can include:

- metadata extraction;
- image/PDF analysis;
- OCR/text extraction;
- tamper detection;
- AI-generated-content detection;
- forensic result review;
- a heatmap where available.

The application displays results as analysis, not as an unquestionable legal
conclusion. A human reviewer remains responsible for interpretation.

### Evidence (`/evidence`)

The evidence workspace supports:

- adding evidence files;
- calculating SHA-256 hashes;
- searching evidence;
- viewing evidence details;
- previewing permitted content;
- verifying evidence;
- viewing the evidence timeline;
- recording verification results and alerts.

The evidence search/details/timeline workflow is intentionally unified around
the evidence page.

### Metadata Analysis (`/metadata`)

Users can extract and inspect metadata from supported images, PDFs, and files.
The metadata results can be exported from the metadata export action.

### Chain of Custody (`/custody`)

Authorized Admins and Investigators can add custody events for evidence.
The page shows evidence ID, action, person, and timestamp, preserving the
movement and handling history.

### Case Management (`/cases`)

Authorized Admins and Investigators can:

- create a case;
- set case ID, name, investigator, priority, and status;
- open case details;
- attach evidence;
- update the case;
- close and sign the case;
- download a signed case report;
- delete a case when permitted.

### Secure Evidence Vault (`/vault`)

Authorized Admins and Analysts can configure and unlock the encrypted vault.
The vault gates protected forensic routes after login. It can be explicitly
locked from the sidebar.

### Report Signature Verification

Admins, Investigators, and Analysts can verify a signed case summary/report
using the report-signing workflow.

### Activity Monitoring (`/activity`)

This is the consolidated audit-log view. Users can filter by user, action,
or search text and export the activity log as CSV.

### Integrity Ledger (`/ledger`)

The ledger view exposes document/evidence integrity events and hash-linked
history used to detect changes.

### User Management (`/users`)

Admins can:

- see role counts;
- search users;
- create users;
- assign `Admin`, `Investigator`, `Analyst`, or `Viewer` roles;
- delete another user.

An admin cannot delete the currently logged-in account from the displayed
control.

---

## 7. End-to-end demonstration flow

For a reliable live demo, use this order:

1. Start the server and open the login page.
2. Sign in as `demo-admin`.
3. Show the FDR overview KPIs and DEMO MODE banner.
4. Open the registry and select a synthetic record.
5. Show claimed, OCR-candidate, and bank-confirmed columns.
6. Open Verification Center and explain pending versus confirmed fields.
7. Show the maturity radar and an overdue/expiring item.
8. Open Release Requests and explain the scrutiny/recommendation/approval
   separation.
9. Open Institutions, Audit Trail, and Prototype Settings as administrator
   features.
10. Sign out and sign in as `demo-institution`.
11. Show the restricted institution scope and New Submission screen.
12. Explain receipt upload, OCR candidates, manual claims, and supporting
    documents.
13. Sign out and sign in as `demo-officer`.
14. Show verification-link generation, discrepancy resolution, and officer
    release actions.
15. Optionally return to the LexGuard menu and briefly show Documents,
    Evidence, Metadata, Cases, Vault, and Activity Monitoring.
16. End by restating that the prototype demonstrates the workflow and trust
    model; it is not connected to a live bank or AICTE.

Use seeded synthetic data so that the demo includes active, pending,
matured, duplicate, mismatch, renewal, and release-request examples.

---

## 8. Four-to-five-minute video script

The following script is written to be spoken while recording the website.
The timestamps are approximate and total about 4 minutes 30 seconds.

### 0:00-0:25 — Introduction and problem

“Hello, this is LexGuard, with its AICTE FDR Guard security-deposit portal.
The problem we are solving is the difficulty of managing Fixed Deposit
Receipts and security deposits through disconnected spreadsheets, email, and
manual verification. That approach makes it hard to identify expiring
instruments, detect duplicate or mismatched values, prove who reviewed a
record, and safely manage release requests.”

### 0:25-0:50 — Solution overview

“LexGuard provides one controlled workspace for institutions, regional
officers, and bureau administrators. It keeps an institution claim separate
from an OCR suggestion and from an independent bank confirmation. It also
keeps documents private, records hashes, tracks discrepancies, preserves
renewal history, and creates an auditable release workflow.”

### 0:50-1:15 — Login and dashboard

“I will begin at the login page. Access is role-based and scoped to assigned
institutions. After I sign in as the Bureau Admin, I reach the overview
dashboard. The dashboard shows total instruments, deposit value, active
records, instruments expiring soon, pending verification, discrepancies,
release requests, overdue instruments, matured records, and pending renewals.
The demo banner is important: this is synthetic data and bank responses are
simulated.”

### 1:15-1:50 — Registry and record details

“From the FDR Registry, I can search by FDR number, bank, or institution and
filter by lifecycle status. I will open one instrument. The detail page shows
the institution, bank, amount, maturity date, documents, replacement
relationships, discrepancies, and the action timeline. Most importantly, each
field has separate institution-claimed and bank-confirmed values. OCR values
are shown only as candidates. This prevents an extracted value from being
mistaken for independent confirmation.”

### 1:50-2:25 — Submission and verification

“An Institution User can start a New Submission by uploading a PDF or image
receipt. The system extracts labelled text candidates, but the user must
review and submit the actual claimed values manually. The receipt is stored
privately and receives a SHA-256 digest. A Regional Officer can then choose a
specific field and generate a secure verification link. The bank verifier does
not need a normal login. The link is single-use, expires after 24 hours, and
the server stores only its token hash. A confirmed response updates the
independent value; a different response creates a discrepancy for review.”

### 2:25-2:55 — Maturity, duplicate detection, and renewal

“The Maturity Radar highlights instruments that are approaching maturity or
are overdue. Reminder thresholds are configurable for the prototype, and the
system does not assume that maturity means release. The registry also exposes
duplicate references and mismatched fields. When an FDR is renewed, the
replacement points back to the original, so the history is preserved instead
of being overwritten.”

### 2:55-3:35 — Release workflow

“The Release Requests page demonstrates separation of duties. An institution
submits a reason and the system records a versioned eligibility evaluation.
The officer begins scrutiny, requests clarification or recommends an eligible
request. The Bureau Admin separately approves or rejects it and then confirms
the release process. The instrument becomes Released only after the final
action. This prevents a single unreviewed click from turning maturity into an
automatic refund.”

### 3:35-4:05 — Administration and audit

“The Bureau Admin can create institutions, assign user scopes, configure
sample reminder and eligibility rules, and inspect the audit trail. Every FDR
event records the actor, role, action, entity, time, previous hash, and event
hash. The audit chain is tamper-evident within the application. Reports can
be downloaded as scope-filtered CSV files for the registry, pending
verification, overdue instruments, discrepancies, and renewals.”

### 4:05-4:30 — Retained forensic workspace and conclusion

“LexGuard also retains a forensic workspace for documents, evidence, metadata,
chain of custody, cases, signed reports, secure vault access, and activity
monitoring. These features help preserve file integrity and investigation
history. In conclusion, the project provides a traceable, role-controlled
workflow from submission to independent verification, review, renewal, and
release. It is a prototype, so the simulated bank integration and sample
policy rules must be replaced and validated before real deployment.”

---

## 9. What to say if asked about security

- Passwords are handled through the existing authentication module.
- Sessions use a required secret key and signed session middleware.
- State-changing forms use CSRF tokens.
- FDR records and downloads are checked against institution scope server-side.
- Uploaded FDR files are stored outside the static web root.
- File types and upload size are restricted.
- File and document SHA-256 digests support integrity checking.
- Verification links are random, hashed at rest, time-limited, and single-use.
- Audit events are linked with SHA-256 previous/current hashes.
- The encrypted vault protects the retained forensic workspace after login.

These controls improve the prototype, but they do not by themselves make it a
production financial system. Production deployment would still require
managed secrets, HTTPS, hardened account provisioning, a managed database,
durable background jobs, retention controls, external audit storage, and
formal policy validation.

---

## 10. Known limitations to disclose in a presentation

1. Bank verification is simulated; there is no bank API or bank identity
   integration.
2. Synthetic demo data is not real AICTE or institutional data.
3. OCR confidence is unavailable and OCR is never treated as confirmation.
4. The reminder worker is in-process and is not durable across downtime.
5. Email delivery and external escalation are not configured.
6. Release rules are configurable prototype rules, not official policy.
7. The audit chain is tamper-evident but not externally immutable.
8. Tesseract must be installed for OCR functionality to work fully.
9. Production deployment needs HTTPS, managed secrets, a production database,
   retention policy, monitoring, and formal authorization controls.

---

## 11. Main implementation map

| Area | Main source |
|---|---|
| FastAPI entry point and legacy routes | `app.py` |
| FDR routes, schema, verification, release, audit | `fdr_portal.py` |
| Authentication and roles | `auth.py` |
| Database initialization | `database.py` |
| Synthetic demo users and records | `seed_demo.py` |
| FDR page templates | `templates/fdr_*.html` |
| Legacy page templates | `templates/*.html` |
| Shared visual styles | `static/style.css`, `static/fdr.css` |
| Automated FDR tests | `tests/test_fdr_portal.py` |
| Setup and limitations | `README.md` |

---

## 12. Does this project solve the given problem statement?

### Short answer

**Yes, the current prototype is strongly aligned with the problem statement
and expected solution.** It demonstrates the main administrative lifecycle:

**submission -> document storage -> claimed-value review -> independent
verification -> discrepancy handling -> maturity monitoring -> renewal ->
release/refund approval -> audit/reporting**

It is not yet a production-ready AICTE system because the problem statement
also expects legitimate external verification, formal AICTE compliance,
production security, stakeholder notifications, and integration with existing
systems. Those are implementation and deployment gaps, not a mismatch in the
core product direction.

### Requirement-by-requirement fit

| Problem-statement requirement | Current prototype | Production work still required |
|---|---|---|
| Centralized institution/instrument repository | Implemented with SQLite institution and FDR records | Move to a managed production database, data migration, backup, retention, and disaster recovery |
| Institution-wise and instrument-wise records | Implemented with institution scopes and FDR detail pages | Integrate authoritative institution master data and official identifiers |
| Digital FDR document management | Implemented for PDF, PNG, JPG, and JPEG uploads with private storage and SHA-256 | Object storage, malware scanning, encryption keys, retention policy, legal hold, and high-availability downloads |
| Verification through authorized sources | Demonstrated with a secure simulated verification link | Obtain bank/financial-source agreements, use official APIs or signed bank responses, authenticate the responding institution, and maintain integration logs |
| Claimed versus independently confirmed values | Implemented explicitly at field level | Define an official data provenance policy and signed evidence format |
| Missing/inconsistent information detection | Implemented through required fields, pending states, mismatches, duplicate flags, and discrepancies | Add a formal rules engine, configurable validation catalog, and policy-approved exception handling |
| Maturity and validity tracking | Implemented with maturity radar, virtual demo date, overdue states, and thresholds | Use authoritative business calendars, durable scheduled jobs, escalation rules, and notification delivery |
| Renewal/replacement monitoring | Implemented through linked replacement instruments and renewal history | Enforce official renewal windows, document requirements, and approval policies |
| Release/refund workflow | Implemented with versioned eligibility evaluation and separated scrutiny, recommendation, approval, and release | Obtain approved policy rules, integrate finance/ERP controls, add maker-checker enforcement and payment/reconciliation references |
| Alerts and escalation | In-app notifications are implemented | Add email/SMS/official messaging, delivery status, retry queues, escalation ladders, and acknowledgement tracking |
| Dashboard and reports | Implemented with dashboards and scope-filtered CSV reports | Add official reporting formats, scheduled reports, analytics, data warehouse support, and export access logging |
| Audit trail and access control | Implemented with roles, institution scopes, CSRF, session control, and hash-linked audit events | Add SSO/MFA, centralized identity, immutable/WORM audit storage, security monitoring, and periodic access reviews |
| System integration | Application routes are ready for integration boundaries | Define API contracts, OAuth/mTLS, webhooks, idempotency, retries, reconciliation, and integration governance |
| Measurable improvement | Workflow is demonstrable and testable | Establish baseline and target metrics with real pilot data |

### Suggested measurable success criteria

For a pilot, measure the following before and after deployment:

- percentage of FDR records with all required fields complete;
- percentage of instruments independently verified;
- average submission-to-verification turnaround time;
- percentage of maturity reminders sent before the configured deadline;
- number of missed or overdue renewals;
- number of duplicate FDR references detected;
- number of unresolved discrepancies and average resolution time;
- average time required to prepare a compliance report;
- reduction in spreadsheet/email/manual tracking effort;
- percentage of release requests with complete approval evidence;
- unauthorized-access and failed-login events detected and reviewed.

Do not claim improvement percentages until they are measured using an agreed
pilot baseline.

---

## 13. How to solve the current limitations for real data

The correct approach is to treat the current application as a workflow
prototype and replace each simulation with an authorized production service.
Do not simply remove the DEMO MODE banner or insert real records into the
prototype database without the controls below.

### 13.1 Replace simulated bank verification

**Current limitation:** The verifier link accepts a simulated response and
does not prove that the responder is a real bank.

**Production solution:**

1. Establish formal agreements with participating banks or an authorized
   financial verification network.
2. Prefer bank-provided APIs or signed digital responses over user-entered
   responses.
3. Use mutual TLS, OAuth 2.0 client credentials, or another approved
   institution-to-institution authentication method.
4. Send only the minimum required lookup data, such as a normalized FDR
   number, bank reference, institution identifier, and consent/reference
   number.
5. Validate the response signature, certificate chain, timestamp, nonce, and
   response ID.
6. Store the raw signed response, normalized result, provider, request ID,
   response time, and verification status.
7. Make responses idempotent and preserve every correction as a new version.
8. Maintain a manual fallback only as a formally approved exception path with
   dual review and mandatory supporting evidence.
9. Keep the existing claimed/confirmed separation even after integration.

**Important:** A public link alone is not sufficient for real bank identity.
The prototype link is useful for demonstrating the workflow, not for
production financial verification.

### 13.2 Replace synthetic data with real institutional data

1. Define an approved data model and data dictionary with AICTE stakeholders.
2. Obtain authoritative institution IDs, names, regions, and user identities
   from the approved source system.
3. Build a controlled migration/import pipeline rather than editing SQLite
   directly.
4. Validate amount formats, dates, bank identifiers, FDR-number normalization,
   duplicate references, and institution ownership during import.
5. Quarantine invalid rows for review instead of silently accepting them.
6. Record source system, import batch, source record ID, import actor, and
   validation result for every imported record.
7. Reconcile totals and sampled records with the source system before
   activation.
8. Keep synthetic demo data in a separate environment and separate database.
9. Mask or tokenize sensitive values in development, testing, logs, and
   screenshots.

### 13.3 Make OCR reliable and safe

**Current limitation:** OCR confidence is unavailable and Tesseract is an
optional local dependency.

**Production solution:**

- deploy a pinned OCR service or approved cloud OCR provider;
- install language packs required for Indian bank documents;
- preprocess scans for rotation, skew, contrast, and resolution;
- preserve the original document and OCR output separately;
- store OCR engine version, language, timestamp, and extracted bounding boxes;
- calculate field-level confidence and define a human-review threshold;
- never allow OCR alone to mark a field as bank-confirmed;
- create a manual correction/review queue for low-confidence fields;
- test OCR against a representative, consented document corpus;
- monitor extraction accuracy, false positives, and false negatives;
- redact sensitive data from OCR logs.

### 13.4 Make reminders and escalation durable

**Current limitation:** The reminder worker runs inside the web process and
does not survive downtime.

**Production solution:**

1. Move scheduling to a durable job system such as a managed queue, workflow
   engine, or scheduled container job.
2. Use a database-backed outbox table so a committed maturity event cannot be
   lost before notification delivery.
3. Make every job idempotent using an event key and delivery attempt ID.
4. Add retry with backoff, dead-letter handling, and operator visibility.
5. Record notification recipient, channel, template version, sent time,
   provider message ID, delivery result, and acknowledgement.
6. Configure escalation from institution user to officer to administrator
   based on approved timelines.
7. Use a trusted time source and timezone policy; do not rely on a virtual
   demo offset in production.
8. Test leap years, timezone boundaries, weekends, holidays, renewal grace
   periods, and downtime recovery.

### 13.5 Configure real policy-compliant release rules

**Current limitation:** The release rules are sample prototype rules.

**Production solution:**

- obtain the current AICTE handbook, circulars, finance instructions, and
  competent-authority approvals;
- have legal, compliance, finance, and operations stakeholders approve each
  rule;
- encode rules as a versioned policy package with effective-from and
  effective-to dates;
- record the exact policy version used for every evaluation;
- require all mandatory documents, verification states, clearances, and
  approvals specified by policy;
- prevent a release when a mandatory condition is unknown, not merely false;
- enforce maker-checker separation so the requester cannot approve their own
  request;
- integrate the final approval with the authorized finance/payment process;
- reconcile released amount, payment reference, bank confirmation, and ledger;
- require a reason and decision note for every exception or rejection;
- obtain a new formal approval and regression-test suite for every rule
  change.

The portal should assist officials; it should not make unapproved policy
decisions automatically.

### 13.6 Add real email, SMS, and escalation

Use an approved notification provider or government messaging service:

- verify recipient ownership and institution association;
- use templates approved by the organization;
- avoid putting full financial details in email/SMS;
- include a secure authenticated portal link;
- track delivery and acknowledgement separately;
- support opt-out only where policy permits;
- protect provider credentials in a secret manager;
- redact message contents from ordinary application logs.

### 13.7 Harden document storage and encryption

For production documents:

- use encrypted object storage with private buckets;
- encrypt in transit with TLS and at rest with managed KMS keys;
- rotate keys and maintain a documented key-ownership model;
- scan uploads for malware and reject active content;
- validate MIME type from file content, not only file extension;
- enforce size, page-count, and decompression-bomb limits;
- generate short-lived authorized download URLs;
- log every view/download without logging document contents;
- apply retention, archival, deletion, and legal-hold policies;
- replicate and back up documents with tested restore procedures.

### 13.8 Strengthen identity and access control

Replace local demonstration accounts with:

- approved SSO or government identity integration;
- MFA for privileged users;
- centralized provisioning and de-provisioning;
- least-privilege roles and institution/region attributes;
- periodic access certification;
- session timeout, revocation, device/risk controls, and login alerts;
- separate service accounts for integrations;
- no shared accounts and no passwords in documentation or screenshots.

Keep authorization checks in the backend. A hidden menu is never an access
control.

### 13.9 Make the audit trail independently defensible

The current hash chain detects modification within the application database,
but a privileged database administrator could still alter the database.
Production improvements should include:

- append-only audit events in a separate security account or service;
- immutable/WORM storage or an approved archival system;
- trusted timestamps and, where required, digital signatures;
- centralized SIEM forwarding with alerting;
- restricted audit-reader access;
- regular chain and storage-integrity verification;
- documented retention and evidence export procedures;
- audit events for reads/downloads as well as writes/approvals.

### 13.10 Production infrastructure and operations

Before real deployment, add:

- managed PostgreSQL or an approved enterprise database;
- separate development, test, staging, and production environments;
- infrastructure-as-code and controlled release approvals;
- HTTPS everywhere and secure headers;
- secret manager and key management service;
- backups, restore drills, disaster recovery, and availability targets;
- centralized logs, metrics, tracing, and alerting;
- vulnerability scanning, dependency pinning, patching, and penetration tests;
- privacy impact assessment and data classification;
- incident response and breach notification procedures;
- formal user acceptance testing with AICTE stakeholders.

---

## 14. USP and positioning

### One-line USP

**LexGuard is a provenance-first FDR lifecycle platform that separates
institution claims, OCR candidates, and independent confirmations while
connecting verification, maturity, renewal, discrepancy, release, and audit
workflows in one role-controlled portal.**

### What makes the project different

1. **Trust separation by design**  
   The system does not treat an uploaded document or OCR result as proof. It
   displays claimed, extracted, and independently confirmed values separately.

2. **Full lifecycle traceability**  
   It does not stop at storing an FDR. It follows submission, scrutiny,
   verification, maturity, renewal, discrepancy, release, and audit history.

3. **Field-level verification**  
   Officers can request confirmation for a particular field instead of
   treating an entire document as uniformly verified.

4. **Controlled release workflow**  
   Requesting, scrutinizing, recommending, approving, and releasing are
   separate actions with recorded decisions.

5. **Scope-aware governance**  
   Institution and regional users see only authorized records, while
   administrators manage scopes and policy configuration.

6. **Renewal history instead of overwrite**  
   Replacement instruments remain linked to originals, preserving the chain
   of financial-instrument history.

7. **Forensic integrity foundation**  
   The retained LexGuard workspace adds document versions, hashes, evidence
   custody, metadata, signed reports, and a secure vault.

8. **Action-oriented dashboards**  
   KPIs link directly to pending work such as expiring, overdue, unverified,
   discrepant, or release-pending records.

### Recommended pitch

“Most FDR systems are repositories or reminder lists. LexGuard is a
provenance-first lifecycle and decision-control platform. It answers not only
‘Which FDRs exist?’ but also ‘Who claimed each value, what was independently
confirmed, what evidence supports it, what action is due, who approved the
action, and can the complete history be audited?’”

---

## 15. Main website features for a presentation slide

### FDR Guard

- Role-based login and institution-scoped access
- Central FDR registry
- Digital receipt upload and private document storage
- OCR-assisted data entry
- Claimed/OCR/confirmed value separation
- Secure bank-verification workflow
- Duplicate and mismatch detection
- Discrepancy review and resolution
- Maturity radar and deadline reminders
- Renewal and replacement history
- Release/refund request workflow
- Versioned eligibility rules
- Dashboard KPIs and lifecycle charts
- CSV reports and analytics
- Institution administration
- Hash-linked audit trail

### LexGuard forensic workspace

- Evidence registration and SHA-256 hashing
- Document version history
- Forensic analysis and tamper review
- Metadata extraction
- Evidence search and preview
- Chain of custody
- Case management
- Signed case reports
- Report signature verification
- Encrypted secure vault
- Activity monitoring and audit export
- Admin user and role management

---

## 16. Recommended implementation phases

### Phase 1 - controlled pilot

- Confirm requirements and official policy rules.
- Deploy managed database and private object storage.
- Implement SSO/MFA and institution master-data import.
- Keep bank verification as an approved manual workflow with dual review.
- Add durable reminders and email notifications.
- Migrate a small, consented pilot dataset.
- Measure the success criteria above.

### Phase 2 - authorized integrations

- Integrate official institution data.
- Integrate participating bank verification APIs or signed responses.
- Add finance/release reconciliation.
- Add SIEM, immutable audit archive, operational dashboards, and escalation.
- Complete security, privacy, accessibility, and performance testing.

### Phase 3 - production scale

- Expand institution and bank coverage.
- Add high availability, disaster recovery, queue scaling, and capacity
  monitoring.
- Review policy changes through versioned governance.
- Run periodic access reviews, penetration tests, data-quality audits, and
  disaster-recovery exercises.

---

## 17. Final answer for evaluators

If asked whether the project meets the given PS, answer:

“Yes. The prototype directly implements the expected centralized repository,
document management, verification states, discrepancy detection, maturity and
renewal monitoring, release workflow, dashboards, reports, role-based access,
secure storage boundaries, and auditability. The main items still simulated
are external bank integration, official policy validation, durable
notifications, production identity, and enterprise infrastructure. The
prototype makes those boundaries explicit and provides a realistic foundation
for implementing them through authorized APIs, policy versioning, durable
queues, secure identity, managed storage, and immutable audit services.”
