import re
from sqlalchemy.orm import Session
from app.models import AuditLog

_SENSITIVE = re.compile(r"pass(word)?|secret|token|credential|authorization|cookie|api[_-]?key|mfa|totp", re.I)


def scrub(obj):
    """Audit details must never contain credentials, whatever a caller passes."""
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if _SENSITIVE.search(str(k)) else scrub(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    return obj


def audit(db: Session, *, actor_id, action, resource_type, resource_id=None, assessment_id=None,
          details=None, outcome="success", commit=False):
    row = AuditLog(actor_id=actor_id, action=action, resource_type=resource_type, resource_id=resource_id,
                   assessment_id=assessment_id, details=scrub(details or {}), outcome=outcome)
    db.add(row)
    if commit:
        db.commit()
    return row
