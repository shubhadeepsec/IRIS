import json
import re
from typing import Any, Optional

def safe_parse_json(text: str) -> Optional[Any]:
    """Safely parse JSON text without throwing errors."""
    try:
        return json.loads(text)
    except Exception:
        return None

def strip_html_tags(text: str) -> str:
    """Remove HTML tags from a string using simple regex."""
    if not text:
        return ""
    clean = re.sub(r'<[^>]*>', '', text)
    # Decode basic HTML entities
    clean = clean.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
    return clean
