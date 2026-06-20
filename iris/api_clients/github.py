import os
import aiohttp
from typing import List, Dict, Any, Optional

class GitHubClient:
    """Client for querying the GitHub API for repositories, code, and user details."""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "IRIS-OSINT"
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"

    async def search_repositories(self, query: str) -> List[Dict[str, Any]]:
        """Search public repositories matching a query term."""
        url = f"https://api.github.com/search/repositories?q={query}&sort=stars&order=desc"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get("items", [])
                        results = []
                        for item in items[:10]:
                            results.append({
                                "name": item.get("full_name"),
                                "url": item.get("html_url"),
                                "description": item.get("description"),
                                "stars": item.get("stargazers_count"),
                                "language": item.get("language"),
                                "updated_at": item.get("updated_at")
                            })
                        return results
                    elif resp.status == 403:
                        # Rate limited or forbidden
                        return []
        except Exception:
            pass
        return []

    async def search_code(self, query: str) -> List[Dict[str, Any]]:
        """Search public code matching a query term (e.g. domain name, secrets)."""
        url = f"https://api.github.com/search/code?q={query}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get("items", [])
                        results = []
                        for item in items[:10]:
                            results.append({
                                "name": item.get("name"),
                                "path": item.get("path"),
                                "repo": item.get("repository", {}).get("full_name"),
                                "html_url": item.get("html_url")
                            })
                        return results
        except Exception:
            pass
        return []
