"""Session-token auth for mutating endpoints."""
from __future__ import annotations

import secrets
from flask import Request

from core import config as cfg

# Single token generated at import time (process lifetime).
_TOKEN: str = secrets.token_hex(32)


def generate_token() -> str:
    """Return the current session token (generated once at startup)."""
    return _TOKEN


def require_token(request: Request) -> bool:
    """Return True if the request carries a valid token or auth is disabled."""
    auth_cfg = cfg.get().get("auth", {})
    if not auth_cfg.get("enabled", False):
        return True  # default: auth off (localhost-only dev tool)

    provided = (
        request.headers.get("X-Dashboard-Token")
        or request.args.get("token")
    )
    return provided == _TOKEN


def print_startup_token() -> None:
    """Print the session token to stdout so the operator can copy it."""
    print(f"[auth] Dashboard token: {_TOKEN}")
    print(f"[auth] Pass as header  X-Dashboard-Token: {_TOKEN}")
    print(f"[auth] Or query param  ?token={_TOKEN}")
