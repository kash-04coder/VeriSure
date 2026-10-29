"""Environment-backed application configuration."""

import os
from pathlib import Path


def _load_dotenv(path=".env"):
    dotenv_path = Path(path)
    if not dotenv_path.is_file():
        return
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        os.environ.setdefault(key, value)


_load_dotenv()

SESSION_SECRET = os.environ.get("LEXGUARD_SESSION_SECRET", "")
HTTPS_ONLY = os.environ.get("LEXGUARD_HTTPS_ONLY", "").lower() == "true"
ADMIN_USERNAME = os.environ.get("LEXGUARD_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("LEXGUARD_ADMIN_PASSWORD", "")
SMTP_HOST = os.environ.get("LEXGUARD_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("LEXGUARD_SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("LEXGUARD_SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("LEXGUARD_SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("LEXGUARD_SMTP_FROM", "")
