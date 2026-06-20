import socket
from typing import Dict, Any

from iris.collectors import BaseCollector

class NetworkCollector(BaseCollector):
    """Collector for network-related intelligence (IPs, Ports, Geolocation)."""
    
    async def collect(self, target: str) -> Dict[str, Any]:
        """Gather intelligence on an IP or hostname target."""
        target = target.strip()
        
        # Try to resolve hostname to IP if it's not an IP
        ip_address = target
        try:
            socket.inet_aton(target) # test if valid IPv4
        except OSError:
            try:
                ip_address = socket.gethostbyname(target)
            except socket.gaierror:
                return self.parse({"target": target, "error": "Could not resolve IP."})

        # Use ip-api for free geolocation (http is required for free tier, or https if paid)
        # We use http to ensure free tier works without API key
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as"
        data = await self._fetch(url)
        
        if not data or data.get("status") != "success":
             return self.parse({"target": target, "ip": ip_address, "error": data.get("message", "API query failed") if data else "Network error"})

        raw_data = {
            "target": target,
            "ip": ip_address,
            "geo": data
        }
        
        return self.parse(raw_data)

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw data into a structured report format."""
        if "error" in raw:
            return {"Target": raw.get("target"), "Error": raw.get("error")}

        geo = raw.get("geo", {})
        parsed = {
            "Target": raw.get("target"),
            "Resolved IP": raw.get("ip"),
            "Location": f"{geo.get('city', 'Unknown')}, {geo.get('regionName', 'Unknown')}, {geo.get('country', 'Unknown')}",
            "ISP": geo.get("isp", "Unknown"),
            "Organization": geo.get("org", "Unknown"),
            "ASN": geo.get("as", "Unknown")
        }
        parsed["_raw"] = raw
        return parsed
