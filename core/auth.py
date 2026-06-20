"""Session-token auth for mutating endpoints.

SSE note
--------
EventSource (browser API) cannot send custom headers, so the main session
token must not be passed as a query-string parameter (it would appear in
access logs).  Instead callers POST to /api/fix/ticket with the main token
in the header to receive a single-use 30-second ticket, then open the
EventSource URL with ``?ticket=<ticket>``.  Tickets are validated and
immediately consumed by require_sse_ticket().
"""
from __future__ import annotations

import secrets
import time
from flask import Request

from core import config as cfg

# Single token generated at import time (process lifetime).
_TOKEN: str = secrets.token_hex(32)

# Short-lived SSE tickets: {ticket_hex: expiry_timestamp}
_SSE_TICKETS: dict[str, float] = {}
_TICKET_TTL = 30.0  # seconds


def generate_token() -> str:
    """Return the current session token (generated once at startup)."""
    return _TOKEN


def require_token(request: Request) -> bool:
    """Return True if the request carries a valid token or auth is disabled."""
    auth_cfg = cfg.get().get("auth", {})
    if not auth_cfg.get("enabled", False):
        return True  # default: auth off (localhost-only dev tool)

    provided = request.headers.get("X-Dashboard-Token")
    return provided == _TOKEN


def issue_sse_ticket() -> str:
    """Create and store a single-use 30-second SSE ticket; return the ticket."""
    _purge_expired_tickets()
    ticket = secrets.token_hex(24)
    _SSE_TICKETS[ticket] = time.monotonic() + _TICKET_TTL
    return ticket


def require_sse_ticket(ticket: str | None) -> bool:
    """Validate and consume a single-use SSE ticket.

    Returns True if auth is disabled OR the ticket is valid and not expired.
    Consumes the ticket on success so it cannot be reused.
    """
    auth_cfg = cfg.get().get("auth", {})
    if not auth_cfg.get("enabled", False):
        return True

    if not ticket:
        return False
    _purge_expired_tickets()
    expiry = _SSE_TICKETS.pop(ticket, None)
    if expiry is None:
        return False
    return time.monotonic() <= expiry


def _purge_expired_tickets() -> None:
    now = time.monotonic()
    expired = [t for t, exp in _SSE_TICKETS.items() if exp < now]
    for t in expired:
        del _SSE_TICKETS[t]


def print_startup_token() -> None:
    """Print the session token to stdout so the operator can copy it."""
    print(f"[auth] Dashboard token: {_TOKEN}")
    print(f"[auth] Pass as header  X-Dashboard-Token: {_TOKEN}")
    print("[auth] NOTE: SSE endpoint /api/fix/stream uses short-lived tickets.")
    print("[auth]       POST /api/fix/ticket with the header to get a ticket.")
