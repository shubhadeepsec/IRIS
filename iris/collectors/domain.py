import asyncio
from typing import Dict, Any

from iris.collectors import BaseCollector
from iris.api_clients.free_sources import FreeSourcesClient
from iris.db import cache

class DomainCollector(BaseCollector):
    """Collector for domain-related intelligence."""
    
    def __init__(self):
        super().__init__()
        self.client = FreeSourcesClient()

    async def collect(self, target: str) -> Dict[str, Any]:
        """Gather intelligence on a domain target."""
        domain = target.strip().lower()
        
        # Check cache first
        cached_data = cache.get_cached_domain(domain)
        if cached_data:
            return self.parse(cached_data)

        # Collect data concurrently
        results = await asyncio.gather(
            self.client.get_subdomains_crtsh(domain),
            self.client.get_dns_records(domain),
            self.client.get_ssl_cert(domain),
            return_exceptions=True
        )
        
        subdomains = results[0] if not isinstance(results[0], Exception) else []
        dns_records = results[1] if not isinstance(results[1], Exception) else {}
        ssl_cert = results[2] if not isinstance(results[2], Exception) else {}
        
        # WHOIS is synchronous in our client, but we could wrap it if needed.
        # Calling it directly here as it's typically fast enough for this scope.
        whois_data = self.client.get_whois(domain)

        raw_data = {
            "domain": domain,
            "whois_data": whois_data,
            "dns_records": dns_records,
            "subdomains": subdomains,
            "ssl_cert": ssl_cert
        }
        
        # Save to cache
        cache.save_domain(
            domain_name=domain,
            whois_data=whois_data,
            dns_records=dns_records,
            subdomains=subdomains,
            ssl_cert=ssl_cert
        )
        
        return self.parse(raw_data)

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw data into a structured report format."""
        parsed = {
            "Domain": raw.get("domain"),
            "Registrar": raw.get("whois_data", {}).get("registrar", "Unknown"),
            "Created": raw.get("whois_data", {}).get("creation_date", "Unknown"),
            "Expires": raw.get("whois_data", {}).get("expiration_date", "Unknown"),
            "Status": ", ".join(raw.get("whois_data", {}).get("status", []))[:50] if raw.get("whois_data", {}).get("status") else "Unknown",
            "A Records": ", ".join(raw.get("dns_records", {}).get("A", []))[:50] if raw.get("dns_records", {}).get("A") else "None",
            "MX Records": ", ".join(raw.get("dns_records", {}).get("MX", []))[:50] if raw.get("dns_records", {}).get("MX") else "None",
            "Subdomains Found": len(raw.get("subdomains", [])),
            "SSL Issuer": raw.get("ssl_cert", {}).get("issuer_cn", "Unknown"),
            "SSL Expires": raw.get("ssl_cert", {}).get("expires", "Unknown")
        }
        
        # Keep full lists for potential exporters, but summarize for TUI
        parsed["_raw"] = raw 
        return parsed
