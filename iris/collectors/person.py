from typing import Dict, Any
from iris.collectors import BaseCollector

class PersonCollector(BaseCollector):
    """Collector for person-related intelligence (Social media, usernames)."""
    async def collect(self, target: str) -> Dict[str, Any]:
        return self.parse({"target": target, "status": "Not implemented in MVP"})

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {"Target": raw.get("target"), "Status": raw.get("status")}
