"""
ids_api/auth.py — API key authentication dependency for the IDS API.

Reads the expected key from the IDS_API_KEY environment variable
(set via the .env file loaded by python-dotenv at startup).
"""
from __future__ import annotations

import logging
import os

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

_HEADER_NAME    = "X-API-Key"
_api_key_header = APIKeyHeader(name=_HEADER_NAME, auto_error=False)


def require_api_key(
    api_key: str | None = Security(_api_key_header),
) -> str:
    """FastAPI dependency — raises 401 if X-API-Key is missing or incorrect."""
    expected = os.environ.get("IDS_API_KEY", "").strip()
    if not expected:
        raise RuntimeError(
            "IDS_API_KEY is not set. Copy .env.example to .env and fill in a value."
        )
    # Strip incoming key to avoid copy-paste trailing spaces/newlines from terminal
    clean_key = api_key.strip() if api_key else None
    if clean_key != expected:
        received_prefix = clean_key[:6] if clean_key else ""
        expected_prefix = expected[:6] if expected else ""
        logger.warning(
            f"[AUTH] Key mismatch! Received: '{received_prefix}...' (len={len(clean_key) if clean_key else 0}), "
            f"Expected: '{expected_prefix}...' (len={len(expected) if expected else 0})"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return clean_key
