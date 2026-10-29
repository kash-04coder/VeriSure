"""Authorized mock bank-verification endpoint for the SIH prototype."""

import sqlite3

from fastapi import APIRouter, Depends, Form
from fastapi.responses import JSONResponse

from routes.dependencies import require_role
from config import DATABASE_PATH


router = APIRouter(prefix="/api/bank", tags=["bank"])
DATABASE = DATABASE_PATH


@router.post("/verify")
async def verify_bank_record(
    csrf: str = Form(...),
    fdr_number: str = Form(...),
    amount: str = Form(...),
    issue_date: str = Form(...),
    maturity_date: str = Form(...),
    user=Depends(require_role("Bank Verifier", "Scrutiny Officer")),
):
    """Compare submitted values with synthetic bank records.

    This endpoint intentionally uses the seeded bank_records table only. It
    never treats an institution submission as independently confirmed.
    """
    del csrf, user
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT fdr_number,bank_name,amount,issue_date,maturity_date,"
        "verification_status FROM bank_records WHERE fdr_number=?",
        (fdr_number.strip(),),
    ).fetchone()
    conn.close()
    if not row:
        return JSONResponse({"result": "not_found", "message": "No bank record found."})

    submitted = {
        "amount": amount.strip(),
        "issue_date": issue_date.strip(),
        "maturity_date": maturity_date.strip(),
    }
    expected = {
        "amount": row["amount"],
        "issue_date": row["issue_date"],
        "maturity_date": row["maturity_date"],
    }
    mismatches = [
        field for field in expected
        if submitted[field] != expected[field]
    ]
    if mismatches:
        return JSONResponse({
            "result": "mismatch",
            "fdr_number": row["fdr_number"],
            "bank_name": row["bank_name"],
            "mismatches": mismatches,
        })
    return JSONResponse({
        "result": "confirmed",
        "fdr_number": row["fdr_number"],
        "bank_name": row["bank_name"],
        "verification_status": row["verification_status"],
    })
