import aiohttp
from typing import Dict, Any, Optional
from iris import config

class ShodanClient:
    """Client for querying the Shodan API for host details."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or config.get_api_key("SHODAN_API_KEY")
        self.base_url = "https://api.shodan.io"

    async def get_host(self, ip: str) -> Dict[str, Any]:
        """Get host details including open ports, services, and vulnerabilities."""
        if not self.api_key:
            return {"error": "SHODAN_API_KEY not configured. Use /config set SHODAN_API_KEY=xxx"}
            
        url = f"{self.base_url}/shodan/host/{ip}?key={self.api_key}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    elif resp.status == 401:
                        return {"error": "Invalid Shodan API key"}
                    elif resp.status == 404:
                        return {"error": "No information available on Shodan"}
                    else:
                        data = await resp.json()
                        return {"error": data.get("error", f"Shodan error {resp.status}")}
        except Exception as e:
            return {"error": f"Shodan request failed: {str(e)}"}
