# AICTE FDR Guard

AICTE FDR Guard is a local, database-backed prototype for security-deposit and Fixed Deposit Receipt (FDR) workflows. It extends the existing LexGuard FastAPI/SQLite application and retains the original forensic document features.

> **Prototype notice:** All bank responses are simulated. No AICTE, bank, email or government system is connected. Synthetic data is explicitly labelled. Sample reminder thresholds and release checks are not official policy and must be validated against current AICTE requirements before operational use.

## Windows setup

Use Python 3.11 or newer. From PowerShell in the repository directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:LEXGUARD_SESSION_SECRET = (python -c "import secrets; print(secrets.token_urlsafe(48))")
python -m uvicorn app:app --reload --port 8000
```

Open <http://127.0.0.1:8000>. The session secret is required at startup and should be stored in a local environment or secret manager for repeatable sessions; do not commit it. For HTTPS deployments, set `LEXGUARD_HTTPS_ONLY=true`. The application no longer creates the old `admin` / `admin123` account. Login with an account created by the original app or seed the synthetic demo users below.

### Synthetic demo accounts

Run this explicit, repeatable initializer from the repository directory:

```powershell
python seed_demo.py --allow-demo-seed
```

It creates fictional records and these local-only accounts:

| Role | Username | Password |
|---|---|---|
| Bureau Admin | `demo-admin` | `DemoAdmin!2026` |
| Institution User | `demo-institution` | `DemoInstitution!2026` |
| Regional Officer | `demo-officer` | `DemoOfficer!2026` |

Change or remove these accounts before any shared or deployed use. The bank verifier does not log in: an officer generates a random, single-use, time-limited field-verification URL from an FDR detail page. The response is clearly marked simulated.

## Main workflows

- **Dashboard and registry:** Database-derived totals, institution-scoped listing, status/search filters, maturity and discrepancy indicators, and scoped CSV exports.
- **Institution submissions:** PDF/PNG/JPEG validation, private storage, SHA-256 metadata, OCR text extraction using the existing LexGuard OCR module, labelled field-candidate parsing, and human-entered claimed values. OCR confidence is marked unavailable; OCR is never treated as bank confirmation.
- **Trust layer:** Claimed, OCR-candidate and independently confirmed values are stored separately. Officers can generate single-use tokens whose hashes are stored server-side. Expiry and atomic one-time consumption are enforced, and mismatch responses create discrepancy records.
- **Maturity radar:** Sample thresholds are configurable. The virtual date offset does not modify the machine clock or FDR dates. Deduplicated in-app reminder creation runs hourly while the app process is alive and when the dashboard or radar is opened.
- **Renewal and release:** Replacement instruments can link to their original. Release requests record versioned eligibility evaluations and enforce separate scrutiny, recommendation, approval and release actions. Prototype eligibility rules are intentionally conservative and not official criteria.
- **Audit:** FDR actions are recorded in a canonical SHA-256 hash chain with a verification view. A local hash chain is tamper-evident, not an independently immutable external ledger.
- **Access control:** Institution and regional scopes are assignable by a Bureau Admin and checked server-side for FDR detail, documents, lists and exports. Privileged routes enforce roles in the backend. Bank links expose only the one requested field.

## Development and tests

```powershell
python -m pytest -q
```

The FDR schema is additive and initialized on application startup. `FDR_DATABASE_PATH` and `FDR_UPLOAD_DIR` can be set for isolated local environments. Uploaded documents are stored outside the static web root and require an authorized FDR scope to download.

## Known limitations and next steps

- The in-process hourly reminder worker is not durable across downtime; email delivery is not configured.
- The prototype has configurable maturity reminders but not a full institution/officer/admin escalation ladder or a durable job queue.
- The simulated verifier proves the single-use token flow, not a real bank identity or bank integration.
- OCR depends on Tesseract being installed and available to `pytesseract`. Candidate confidence is unavailable. Extraction errors are shown to the user; manual entry remains available.
- The prototype does not implement full institution user provisioning, externally immutable audit storage, release-request-specific attachments, or a formal institution/officer/admin escalation ladder.
- Validate all financial and release rules against the current AICTE Approval Process Handbook before real-world use. Configure TLS, managed secrets, production database and retention controls before deployment.

## Retained LexGuard features

`app.py` remains the FastAPI entry point; existing evidence, vault, case, document-version and forensic routes remain available. `webapp.py` is the historical raw-HTTP entry point and is not the recommended way to run the application.

The existing evidence search/details/timeline workflow remains unified on its evidence page; activity monitoring is the consolidated audit-log view; and the signed case-report workflow remains the canonical report-signing path.
