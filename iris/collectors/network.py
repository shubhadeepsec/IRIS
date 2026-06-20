import asyncio
import ipaddress
import socket
from typing import Dict, Any

from iris.collectors import BaseCollector
from iris.api_clients.shodan import ShodanClient
from iris.db import cache


class NetworkCollector(BaseCollector):
    """Collector for network-related intelligence (IPs, Geolocation, ASN, Shodan)."""

    def __init__(self):
        super().__init__()
        self.shodan_client = ShodanClient()

    async def collect(self, target: str) -> Dict[str, Any]:
        """Gather intelligence on an IP target."""
        target = target.strip()

        # Resolve hostname to IP if needed
        ip_address = target
        try:
            ipaddress.ip_address(target)
        except ValueError:
            try:
                loop_ip = socket.gethostbyname(target)
                ip_address = loop_ip
            except socket.gaierror:
                return self.parse({"target": target, "error": "Could not resolve to an IP address."})

        # Check cache
        cached_data = cache.get_cached_ip(target)
        if cached_data:
            return self.parse({
                "target": cached_data["target"],
                "ip": cached_data["ip_address"],
                "geo": cached_data["geo"],
                "shodan": cached_data.get("shodan", {})
            })

        # Fetch IP-API and Shodan concurrently
        geo_url = (
            f"http://ip-api.com/json/{ip_address}"
            f"?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,reverse,mobile,proxy,hosting"
        )
        
        loop = asyncio.get_running_loop()
        results = await asyncio.gather(
            self._fetch(geo_url),
            self.shodan_client.get_host(ip_address),
            return_exceptions=True
        )

        geo_data = results[0] if not isinstance(results[0], Exception) else {}
        shodan_data = results[1] if not isinstance(results[1], Exception) else {}

        if not geo_data or geo_data.get("status") != "success":
            msg = geo_data.get("message", "API query failed") if geo_data else "Network error"
            return self.parse({"target": target, "ip": ip_address, "error": msg})

        raw_data = {
            "target":  target,
            "ip":      ip_address,
            "geo":     geo_data,
            "shodan":  shodan_data
        }

        cache.save_ip(
            target=target,
            ip_address=ip_address,
            geo_data=geo_data,
            shodan_data=shodan_data
        )

        return self.parse(raw_data)

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw data into a structured report format."""
        if "error" in raw:
            return {"Target": raw.get("target"), "Error": raw.get("error"), "_raw": raw}

        geo = raw.get("geo", {})
        shodan = raw.get("shodan", {})
        
        flags = []
        if geo.get("proxy"):
            flags.append("Proxy")
        if geo.get("hosting"):
            flags.append("Hosting/VPN")
        if geo.get("mobile"):
            flags.append("Mobile")

        parsed = {
            "Target":       raw.get("target"),
            "Resolved IP":  raw.get("ip"),
            "Hostname":     geo.get("reverse", "—"),
            "Location":     f"{geo.get('city', '?')}, {geo.get('regionName', '?')}, {geo.get('country', '?')}",
            "Coordinates":  f"{geo.get('lat', '?')}, {geo.get('lon', '?')}",
            "ISP":          geo.get("isp", "Unknown"),
            "Organization": geo.get("org", "Unknown"),
            "ASN":          geo.get("as", "Unknown"),
            "Flags":        ", ".join(flags) if flags else "None",
        }
        
        if shodan and "error" not in shodan:
            ports = shodan.get("ports", [])
            parsed["Open Ports"] = ", ".join([str(p) for p in ports]) if ports else "None"
            
            vulns = shodan.get("vulns", [])
            parsed["Vulnerabilities"] = ", ".join(vulns) if vulns else "None"
            
            tags = shodan.get("tags", [])
            if tags:
                parsed["Shodan Tags"] = ", ".join(tags)

        elif shodan and "error" in shodan:
            parsed["Shodan"] = shodan["error"]

        parsed["_raw"] = raw
        return parsed
