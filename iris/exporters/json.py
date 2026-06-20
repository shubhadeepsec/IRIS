import json
from typing import Dict, Any

def json_export(data: Dict[str, Any], filepath: str) -> None:
    """Export data to a JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, default=str)
