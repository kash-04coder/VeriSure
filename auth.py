"""
User authentication.

Passwords are hashed with PBKDF2-HMAC-SHA256 (stdlib hashlib), the same
construction used in vault_security.py -- this replaces the third-party
`bcrypt` package with an equivalent stdlib-only approach.

Stored format (single TEXT column, so salt/iterations/hash are packed
into one string, separated by '$'):

    pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>

This keeps the existing `password TEXT` column in the users table
untouched -- no schema migration needed.
"""

import sqlite3
import hashlib
import hmac
import secrets
import time

from config import ADMIN_PASSWORD, ADMIN_USERNAME


MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60
_LOGIN_FAILURES = {}

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
KEY_LENGTH = 32


def _hash_password(password, iterations=PBKDF2_ITERATIONS):
    salt = secrets.token_bytes(SALT_SIZE)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=KEY_LENGTH
    )
    return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"


def _verify_password(password, stored):
    try:
        scheme, iterations, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iterations)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=len(expected)
    )
    return hmac.compare_digest(derived, expected)


def create_default_admin():
    """Optionally bootstrap one administrator from environment configuration."""
    if not ADMIN_PASSWORD:
        return None
    conn = sqlite3.connect("forensic.db")
    existing = conn.execute(
        "SELECT 1 FROM users WHERE username=?", (ADMIN_USERNAME,)
    ).fetchone()
    conn.close()
    if existing:
        return None
    return create_user(ADMIN_USERNAME, ADMIN_PASSWORD, "Admin")


def login(username, password):
    if username == ADMIN_USERNAME and not ADMIN_PASSWORD:
        return None
    now = time.monotonic()
    failure = _LOGIN_FAILURES.get(username)
    if failure and now - failure["started"] < LOCKOUT_SECONDS:
        return None
    if failure:
        _LOGIN_FAILURES.pop(username, None)
    conn = sqlite3.connect("forensic.db")
    c = conn.cursor()
    c.execute(
        "SELECT password,role FROM users WHERE username=?",
        (username,)
    )
    result = c.fetchone()
    conn.close()
    if result:
        stored_password, role = result
        if _verify_password(password, stored_password):
            _LOGIN_FAILURES.pop(username, None)
            return role
    record = _LOGIN_FAILURES.setdefault(
        username, {"count": 0, "started": now}
    )
    if now - record["started"] >= LOCKOUT_SECONDS:
        record.update(count=0, started=now)
    record["count"] += 1
    if record["count"] >= MAX_LOGIN_ATTEMPTS:
        record["started"] = now
    return None


def create_user(username, password, role):
    conn = sqlite3.connect("forensic.db")
    c = conn.cursor()
    hashed_password = _hash_password(password)
    try:
        c.execute(
            """
            INSERT INTO users(
            username,
            password,
            role
            )
            VALUES(?,?,?)
            """,
            (
                username,
                hashed_password,
                role
            )
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_users():
    conn = sqlite3.connect("forensic.db")
    users = conn.execute("""
        SELECT id, username, role
        FROM users
        ORDER BY username
    """).fetchall()
    conn.close()
    return users


def delete_user(user_id):
    conn = sqlite3.connect("forensic.db")
    conn.execute(
        "DELETE FROM users WHERE id=?",
        (user_id,)
    )
    conn.commit()
    conn.close()


def update_role(user_id, role):
    conn = sqlite3.connect("forensic.db")
    conn.execute(
        "UPDATE users SET role=? WHERE id=?",
        (role, user_id)
    )
    conn.commit()
    conn.close()