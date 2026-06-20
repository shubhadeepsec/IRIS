# Collectors

Collectors are the primary drivers of data gathering in IRIS.

## Implemented Collectors (MVP)

### DomainCollector (`domain.py`)
- **WHOIS**: Retrieves registration, creation, and expiration dates.
- **DNS**: Resolves A, MX, TXT (including SPF/DMARC), CNAME records.
- **Subdomains**: Queries the `crt.sh` transparency logs.
- **SSL**: Retrieves live SSL certificate details, including issuers and alternative names.

### EmailCollector (`email.py`)
- **Breaches**: Queries Have I Been Pwned for breach history. Includes simulation fallback if no API key is provided.
- **SMTP Check**: Verifies if the email's domain possesses valid MX records for receiving mail.

### NetworkCollector (`network.py`)
- **Geolocation**: Resolves IP and queries regional/city data alongside ISP and ASN.

### CodeCollector (`code.py`)
- **Repositories**: Searches GitHub for repositories related to the target domain or organization.
- **Snippets**: Finds potential code mentions (e.g., secrets, configs) on GitHub.

## Stub Collectors
The following collectors are mapped for future expansion:
- `PersonCollector`
- `CompanyCollector`
- `TechStackCollector`
- `ThreatsCollector`
