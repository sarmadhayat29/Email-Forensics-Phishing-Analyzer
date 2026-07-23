import os
import re
from datetime import datetime, timezone

def format_iso(dt):
    """Format a datetime object to an ISO 8601 string."""
    if dt is None:
        return datetime.now(timezone.utc).isoformat()
    if hasattr(dt, 'isoformat'):
        return dt.isoformat()
    return str(dt)

def sanitize_filename(filename: str) -> str:
    """Sanitize an uploaded file name to prevent path traversal or special character issues."""
    base = os.path.basename(filename)
    safe = re.sub(r'[^a-zA-Z0-9_\-\.]', '', base)
    if not safe:
        safe = "uploaded_message.eml"
    return safe
