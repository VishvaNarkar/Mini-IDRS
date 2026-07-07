"""
ids_api/auth.py — API key authentication dependency for the IDS API.

Reads the expected key from the IDS_API_KEY environment variable
(set via the .env file loaded by python-dotenv at startup).
"""
from __future__ import annotations

import os

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

_HEADER_NAME    = "X-API-Key"
_api_key_header = APIKeyHeader(name=_HEADER_NAME, auto_error=False)


def require_api_key(
    api_key: str | None = Security(_api_key_header),
) -> str:
    """FastAPI dependency — raises 401 if X-API-Key is missing or incorrect."""
    expected = os.environ.get("IDS_API_KEY", "")
    if not expected:
        raise RuntimeError(
            "IDS_API_KEY is not set. Copy .env.example to .env and fill in a value."
        )
    if api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key
