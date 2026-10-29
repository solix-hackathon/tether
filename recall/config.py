"""Static configuration for the prototype. All names and domains are synthetic."""

ORG_NAME = "St. Mary's Health (synthetic)"
ORG_DOMAIN = "stmarys-health.example"
PRIVACY_CONTACT = f"privacy@{ORG_DOMAIN}"

LINK_BASE = f"https://recall.{ORG_DOMAIN}/l/"
SHARE_BASE = f"https://files.{ORG_DOMAIN}/s/"

LINK_TTL = 7 * 86400          # rewritten links expire after 7 days
HOLD_SECONDS = 15 * 60        # irreversible actions wait this long for approval
CLOCK_TOLERANCE = 2           # seconds of drift allowed between a log and the reference clock
LOG_RETENTION = 30 * 86400

MODEL = "claude-opus-5-5"


def is_internal(actor: str) -> bool:
    """True for identities that belong to the organization (staff, services, internal network)."""
    a = actor.lower()
    return a.endswith("@" + ORG_DOMAIN) or a.startswith("svc:") or a.startswith("ip:10.")
