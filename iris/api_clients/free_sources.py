import asyncio
import socket
import ssl
from typing import List, Dict, Any, Optional
import aiohttp
import dns.resolver
import whois

class FreeSourcesClient:
    """Client for gathering data from free and passive OSINT sources."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def get_subdomains_crtsh(self, domain: str) -> List[str]:
        """Fetch subdomains from crt.sh certificate transparency logs."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subdomains = set()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data:
                            name = item.get("name_value", "")
                            # name_value can contain wildcards and multiple names separated by newlines
                            for part in name.split("\n"):
                                part = part.strip().lower()
                                if part.endswith(domain) and "*" not in part:
                                    subdomains.add(part)
        except Exception:
            # Silence exception, crt.sh frequently times out or returns 502
            pass
        return sorted(list(subdomains))

    def get_whois(self, domain: str) -> Dict[str, Any]:
        """Perform a WHOIS lookup for the domain."""
        try:
            # whois.whois is synchronous
            w = whois.whois(domain)
            # Normalize dates and other attributes to JSON-serializable types
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                creation_date = creation_date.isoformat() if hasattr(creation_date, "isoformat") else str(creation_date)
            
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if expiration_date:
                expiration_date = expiration_date.isoformat() if hasattr(expiration_date, "isoformat") else str(expiration_date)
            
            updated_date = w.updated_date
            if isinstance(updated_date, list):
                updated_date = updated_date[0]
            if updated_date:
                updated_date = updated_date.isoformat() if hasattr(updated_date, "isoformat") else str(updated_date)

            return {
                "registrar": w.registrar,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "updated_date": updated_date,
                "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                "emails": w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
                "name_servers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else []
            }
        except Exception as e:
            return {"error": f"WHOIS lookup failed: {str(e)}"}

    async def get_dns_records(self, domain: str) -> Dict[str, Any]:
        """Query common DNS records (A, AAAA, MX, TXT, CNAME, NS)."""
        records = {}
        record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"]
        
        loop = asyncio.get_running_loop()
        
        def query_dns(domain_name: str, rtype: str):
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3.0
                resolver.lifetime = 3.0
                answers = resolver.resolve(domain_name, rtype)
                return [str(rdata) for rdata in answers]
            except Exception:
                return []

        for rtype in record_types:
            res = await loop.run_in_executor(None, query_dns, domain, rtype)
            if res:
                records[rtype] = res
                
        # Also parse SPF and DMARC specifically from TXT/subdomains
        txt_records = records.get("TXT", [])
        records["SPF"] = [r for r in txt_records if "v=spf1" in r]
        
        # Query DMARC
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_res = await loop.run_in_executor(None, query_dns, dmarc_domain, "TXT")
        records["DMARC"] = [r for r in dmarc_res if "v=DMARC1" in r]
        
        return records

    async def get_ssl_cert(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """Fetch and analyze the SSL/TLS certificate for the domain."""
        loop = asyncio.get_running_loop()
        
        def fetch_cert():
            try:
                context = ssl.create_default_context()
                # Use wrap_socket with socket creation
                conn = socket.create_connection((domain, port), timeout=3.0)
                secure_conn = context.wrap_socket(conn, server_hostname=domain)
                cert = secure_conn.getpeercert()
                
                if not cert:
                    return {"error": "No certificate found"}
                
                # Helper to extract CN from subject or issuer fields
                def get_cn(rdn_sequence):
                    if not rdn_sequence:
                        return ""
                    for rdn in rdn_sequence:
                        for entry in rdn:
                            if entry[0] == "commonName":
                                return entry[1]
                    return ""

                subject_cn = get_cn(cert.get("subject", []))
                issuer_cn = get_cn(cert.get("issuer", []))
                
                # Extract alt names
                alt_names = []
                for name_entry in cert.get("subjectAltName", []):
                    if name_entry[0] == "DNS":
                        alt_names.append(name_entry[1])

                return {
                    "subject_cn": subject_cn,
                    "issuer_cn": issuer_cn,
                    "issued": cert.get("notBefore", ""),
                    "expires": cert.get("notAfter", ""),
                    "alt_names": alt_names
                }
            except Exception as e:
                return {"error": f"SSL cert retrieval failed: {str(e)}"}

        return await loop.run_in_executor(None, fetch_cert)
