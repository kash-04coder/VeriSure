"""Reusable request authentication and role authorization dependencies."""

from fastapi import HTTPException, Request


ROLE_GROUPS = {
    "Institution": {"Institution", "Institution User", "Viewer"},
    "Scrutiny Officer": {"Scrutiny Officer", "Regional Officer", "Investigator", "Analyst"},
    "Competent Authority": {"Competent Authority", "Bureau Admin"},
    "Bank Verifier": {"Bank Verifier"},
    "Admin": {"Admin"},
}


def canonical_role(role):
    for portal_role, stored_roles in ROLE_GROUPS.items():
        if role in stored_roles:
            return portal_role
    return role


def require_role(*roles):
    """Return a FastAPI dependency that requires one of the supplied roles."""
    allowed = set(roles)

    async def dependency(request: Request):
        user = request.session.get("user")
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required.")
        role = canonical_role(user.get("role", ""))
        if role not in allowed and user.get("role") not in allowed:
            raise HTTPException(status_code=403, detail="You are not authorised for this portal.")
        return user

    return dependency


def portal_for_role(role):
    return {
        "Institution": "/institution",
        "Institution User": "/institution",
        "Viewer": "/institution",
        "Scrutiny Officer": "/officer",
        "Regional Officer": "/officer",
        "Investigator": "/officer",
        "Analyst": "/officer",
        "Competent Authority": "/authority",
        "Bureau Admin": "/authority",
        "Admin": "/admin",
        "Bank Verifier": "/bank",
    }.get(role, "/login")
