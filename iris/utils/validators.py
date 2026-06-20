import re

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
IP_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

def is_valid_email(email: str) -> bool:
    """Validate email format."""
    if not email:
        return False
    return bool(EMAIL_REGEX.match(email.strip()))

def is_valid_domain(domain: str) -> bool:
    """Validate domain format."""
    if not domain:
        return False
    # Remove protocol if present
    d = domain.strip().lower()
    if d.startswith("http://"):
        d = d[7:]
    elif d.startswith("https://"):
        d = d[8:]
    if "/" in d:
        d = d.split("/")[0]
    return bool(DOMAIN_REGEX.match(d))

def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    if not ip:
        return False
    return bool(IP_REGEX.match(ip.strip()))
