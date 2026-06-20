import asyncio
from typing import Dict, Any

from iris.collectors import BaseCollector
from iris.api_clients.github import GitHubClient

class CodeCollector(BaseCollector):
    """Collector for source code intelligence (GitHub, packages, secrets)."""
    
    def __init__(self):
        super().__init__()
        self.github_client = GitHubClient()

    async def collect(self, target: str) -> Dict[str, Any]:
        """Gather source code intelligence on a target (e.g., domain or org name)."""
        # Extract basic org/name from domain if applicable
        query = target.replace(".com", "").replace(".net", "").replace(".org", "")
        
        results = await asyncio.gather(
            self.github_client.search_repositories(query),
            self.github_client.search_code(query),
            return_exceptions=True
        )
        
        repos = results[0] if not isinstance(results[0], Exception) else []
        code_snippets = results[1] if not isinstance(results[1], Exception) else []

        raw_data = {
            "target": target,
            "repositories": repos,
            "code_snippets": code_snippets
        }
        
        return self.parse(raw_data)

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw data into a structured report format."""
        parsed = {
            "Target": raw.get("target"),
            "Public Repositories": len(raw.get("repositories", [])),
            "Code Mentions": len(raw.get("code_snippets", []))
        }
        
        if raw.get("repositories"):
            top_repos = []
            for r in raw.get("repositories", [])[:3]:
                top_repos.append(f"{r.get('name')} ({r.get('language') or 'Unknown'}, {r.get('stars')}⭐)")
            parsed["Top Repos"] = ", ".join(top_repos)

        parsed["_raw"] = raw
        return parsed
