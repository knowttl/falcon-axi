"""Passive RTR session metadata and audit reads (design §4.5, slice R1)."""

from falcon_axi.collection import Collection

SESSIONS = Collection(
    "rtr session",
    "sessions",
    "RTR_ListAllSessions",
    ("id", "hostname", "user_id", "created_at"),
    5000,
    "RTR_ListSessions",
)
AUDIT = Collection(
    "rtr audit",
    "audit_sessions",
    "RTRAuditSessions",
    ("id", "hostname", "user_id", "created_at"),
    1000,
)
COMMAND_SPECS = (*SESSIONS.commands(show=True), *AUDIT.commands())
