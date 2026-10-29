"""Shared upload and filename validation for user-provided files."""

import io
import re
from pathlib import Path

from fastapi import HTTPException


MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(filename):
    name = Path(filename or "").name
    name = _SAFE_FILENAME.sub("_", name).strip("._")
    if not name:
        raise HTTPException(400, "A valid filename is required.")
    return name[:160]


def validate_upload(content, filename):
    safe_name = sanitize_filename(filename)
    suffix = Path(safe_name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, "Upload a PDF, PNG or JPEG file.")
    if not content or len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(400, "File must be non-empty and no larger than 5 MB.")
    if suffix == ".pdf":
        if not content.startswith(b"%PDF-"):
            raise HTTPException(400, "The uploaded file is not a valid PDF.")
    else:
        try:
            from PIL import Image

            image = Image.open(io.BytesIO(content))
            image.verify()
            expected_format = "PNG" if suffix == ".png" else "JPEG"
            if image.format != expected_format:
                raise ValueError("The file extension does not match its image format.")
        except Exception as exc:
            raise HTTPException(400, "The uploaded image could not be validated.") from exc
    return safe_name
