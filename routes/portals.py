"""Role-specific portal landing pages."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from routes.dependencies import require_role


router = APIRouter()
templates = Jinja2Templates(directory="templates")


def render_portal(request, template, user, title, description, links):
    return templates.TemplateResponse(request, template, {
        "user": user,
        "title": title,
        "description": description,
        "links": links,
        "csrf_token": request.session.get("_csrf_token", ""),
        "messages": [],
    })


@router.get("/institution", response_class=HTMLResponse)
async def institution_portal(
    request: Request,
    user=Depends(require_role("Institution")),
):
    return render_portal(
        request, "portal_home.html", user, "Institution workspace",
        "Submit and monitor your institution's security deposits and FDRs.",
        [
            ("New FDR submission", "/fdr/new"),
            ("My FDR registry", "/fdr/registry"),
            ("Notifications", "/fdr/maturity"),
        ],
    )


@router.get("/officer", response_class=HTMLResponse)
async def officer_portal(
    request: Request,
    user=Depends(require_role("Scrutiny Officer")),
):
    return render_portal(
        request, "portal_home.html", user, "Scrutiny officer workspace",
        "Review assigned FDRs, resolve discrepancies and progress release requests.",
        [
            ("Verification center", "/fdr/verification"),
            ("FDR registry", "/fdr/registry"),
            ("Release requests", "/fdr/releases"),
            ("Maturity radar", "/fdr/maturity"),
        ],
    )


@router.get("/authority", response_class=HTMLResponse)
async def authority_portal(
    request: Request,
    user=Depends(require_role("Competent Authority")),
):
    return render_portal(
        request, "portal_home.html", user, "Competent authority workspace",
        "Review recommendations, approve controlled releases and monitor bureau-wide status.",
        [
            ("Release requests", "/fdr/releases"),
            ("FDR dashboard", "/fdr/dashboard"),
            ("Reports & analytics", "/fdr/reports"),
            ("Audit trail", "/fdr/audit"),
        ],
    )


@router.get("/admin", response_class=HTMLResponse)
async def admin_portal(
    request: Request,
    user=Depends(require_role("Admin")),
):
    return render_portal(
        request, "portal_home.html", user, "System administration",
        "Manage protected forensic operations, users and system access.",
        [
            ("User management", "/users"),
            ("FDR dashboard", "/fdr/dashboard"),
            ("Secure vault", "/vault"),
            ("Activity monitoring", "/activity"),
        ],
    )


@router.get("/bank", response_class=HTMLResponse)
async def bank_portal(
    request: Request,
    user=Depends(require_role("Bank Verifier")),
):
    return render_portal(
        request, "portal_home.html", user, "Bank verification workspace",
        "Review and respond to verification requests assigned to your bank account.",
        [
            ("Verification requests", "/fdr/verification"),
            ("FDR registry", "/fdr/registry"),
        ],
    )
