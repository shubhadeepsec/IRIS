import asyncio
import dns.resolver
from typing import Dict, Any

from iris.collectors import BaseCollector
from iris.api_clients.hibp import HIBPClient
from iris.db import cache

class EmailCollector(BaseCollector):
    """Collector for email-related intelligence."""
    
    def __init__(self):
        super().__init__()
        self.hibp_client = HIBPClient()

    async def check_smtp(self, domain: str) -> bool:
        """Perform a basic check to see if the domain has MX records."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            loop = asyncio.get_running_loop()
            answers = await loop.run_in_executor(None, resolver.resolve, domain, "MX")
            return len(answers) > 0
        except Exception:
            return False

    async def collect(self, target: str) -> Dict[str, Any]:
        """Gather intelligence on an email target."""
        email = target.strip().lower()
        
        # Check cache first
        cached_data = cache.get_cached_email(email)
        if cached_data:
            # We still might want to re-run SMTP check as it's not cached, but for MVP returning cache is fine
            return self.parse(cached_data)

        domain_part = email.split("@")[1] if "@" in email else ""
        
        # Collect data concurrently
        results = await asyncio.gather(
            self.hibp_client.check_email_breached(email),
            self.hibp_client.get_breaches(email),
            self.check_smtp(domain_part),
            return_exceptions=True
        )
        
        is_breached = results[0] if not isinstance(results[0], Exception) else False
        breaches = results[1] if not isinstance(results[1], Exception) else []
        has_smtp = results[2] if not isinstance(results[2], Exception) else False
        
        sources = [b.get("Name", "Unknown") for b in breaches]
        
        # Ensure domain exists in DB for correlation
        # Ideally this would trigger a full domain collection if not exists, but for now just basic insert
        # We'll skip inserting a blank domain record for now to keep things clean.
        
        cache.save_email(
            email_address=email,
            breached=is_breached,
            sources=sources
        )

        raw_data = {
            "email": email,
            "breached": is_breached,
            "breach_details": breaches,
            "has_smtp": has_smtp,
            "sources": sources
        }
        
        return self.parse(raw_data)

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw data into a structured report format."""
        parsed = {
            "Email": raw.get("email"),
            "Breached": "⚠️ YES" if raw.get("breached") else "✅ NO",
            "Valid SMTP": "✓ YES" if raw.get("has_smtp") else "✗ NO",
            "Breach Sources": ", ".join(raw.get("sources", [])) if raw.get("sources") else "None found"
        }
        parsed["_raw"] = raw
        return parsed
