"""
Hash-chain integrity ledger.

This is what turns "we hash files" into "we can prove the entire history
of a document is untampered" -- the actual Blockchain & Cybersecurity
differentiator for the hackathon.

Design (deliberately simple -- this is a *ledger*, not a consensus
network; we don't need mining, peers, or a token, we need tamper-evidence):

Each document has its own hash chain. Every meaningful event on that
document (created, new version uploaded, verified, shared, signed,
permission changed) appends one block. A block commits to:

    chain_hash = SHA256(previous_hash + content_hash + action + actor + timestamp + document_id)

Because each block's hash depends on the previous block's hash, changing
or deleting *any* historical block changes that block's own chain_hash,
which no longer matches what the next block committed to as its
"previous_hash" -- so verify_chain() can walk the whole history and
pinpoint exactly where (and therefore prove nothing after it can be
trusted) tampering occurred. This is the same core idea as a blockchain's
tamper-evidence, scoped to a single document's audit trail instead of a
distributed ledger.

Genesis block: previous_hash = "0" * 64 (64 zeros, same width as a
SHA-256 hex digest), same convention as Bitcoin's genesis block.
"""

import hashlib
import sqlite3
from config import DATABASE_PATH
from datetime import datetime

DB = DATABASE_PATH
GENESIS_HASH = "0" * 64


def _compute_chain_hash(previous_hash, content_hash, action, actor, timestamp, document_id):
    payload = f"{previous_hash}|{content_hash}|{action}|{actor}|{timestamp}|{document_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_last_block(document_id):
    conn = sqlite3.connect(DB)
    row = conn.execute("""
        SELECT chain_hash
        FROM hash_chain
        WHERE document_id=?
        ORDER BY id DESC
        LIMIT 1
    """, (document_id,)).fetchone()
    conn.close()
    return row[0] if row else GENESIS_HASH


def add_block(document_id, version_number, action, actor, content_hash):
    """
    Append a new block to a document's hash chain.

    Call this on every meaningful lifecycle event: document created,
    new version uploaded, verified, signed, shared, permission changed.
    Returns the new block's chain_hash.
    """
    previous_hash = get_last_block(document_id)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    chain_hash = _compute_chain_hash(
        previous_hash, content_hash, action, actor, timestamp, document_id
    )

    conn = sqlite3.connect(DB)
    conn.execute("""
        INSERT INTO hash_chain(
            document_id, version_number, action, actor,
            timestamp, content_hash, previous_hash, chain_hash
        )
        VALUES(?,?,?,?,?,?,?,?)
    """, (
        document_id, version_number, action, actor,
        timestamp, content_hash, previous_hash, chain_hash
    ))
    conn.commit()
    conn.close()

    return chain_hash


def get_chain(document_id):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT *
        FROM hash_chain
        WHERE document_id=?
        ORDER BY id ASC
    """, (document_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def verify_chain(document_id):
    """
    Walk a document's entire hash chain from genesis and recompute every
    block's chain_hash from its stored fields.

    Returns:
        (is_valid: bool, broken_at_block: int | None, details: list[dict])

    `broken_at_block` is the id of the first block whose stored chain_hash
    no longer matches what its own fields recompute to (or whose
    previous_hash no longer matches the prior block's chain_hash) --
    i.e. the earliest point after which nothing in the chain can be
    trusted.
    """
    chain = get_chain(document_id)
    details = []
    expected_previous = GENESIS_HASH

    for block in chain:
        recomputed = _compute_chain_hash(
            block["previous_hash"],
            block["content_hash"],
            block["action"],
            block["actor"],
            block["timestamp"],
            document_id,
        )

        link_ok = block["previous_hash"] == expected_previous
        hash_ok = recomputed == block["chain_hash"]
        block_valid = link_ok and hash_ok

        details.append({
            "block_id": block["id"],
            "action": block["action"],
            "actor": block["actor"],
            "timestamp": block["timestamp"],
            "valid": block_valid,
            "link_ok": link_ok,
            "hash_ok": hash_ok,
        })

        if not block_valid:
            return False, block["id"], details

        expected_previous = block["chain_hash"]

    return True, None, details


def get_global_ledger(limit=50):
    """
    Cross-document view of the ledger -- useful for a compliance
    dashboard ("everything that has happened across the system").
    """
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT hc.*, d.title AS document_title, d.doc_type, d.case_id
        FROM hash_chain hc
        JOIN documents d ON d.id = hc.document_id
        ORDER BY hc.id DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]
