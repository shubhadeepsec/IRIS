from typing import List, Dict, Any
from iris.db import cache

class CorrelationEngine:
    """Finds relationships between entities based on cached intelligence."""
    
    def analyze_domain(self, domain_data: Dict[str, Any]) -> None:
        """Analyze domain data to find relationships."""
        domain = domain_data.get("Domain")
        if not domain:
            return
            
        raw = domain_data.get("_raw", {})
        
        # Link domain to IP addresses
        dns_records = raw.get("dns_records", {})
        a_records = dns_records.get("A", [])
        for ip in a_records:
            cache.save_correlation(domain, ip, "resolves_to", confidence=1.0)
            
        # Link domain to registrar
        whois_data = raw.get("whois_data", {})
        registrar = whois_data.get("registrar")
        if registrar:
            cache.save_correlation(domain, registrar, "registered_via", confidence=1.0)

    def analyze_email(self, email_data: Dict[str, Any]) -> None:
        """Analyze email data to find relationships."""
        email = email_data.get("Email")
        if not email:
            return
            
        if "@" in email:
            domain = email.split("@")[1]
            cache.save_correlation(email, domain, "belongs_to_domain", confidence=1.0)
            
            # Simple username reuse heuristic
            username = email.split("@")[0]
            cache.save_correlation(email, username, "uses_username", confidence=0.9)

    def get_correlations(self, entity: str) -> List[Dict[str, Any]]:
        """Retrieve correlations for a specific entity."""
        return cache.get_correlations(entity)
