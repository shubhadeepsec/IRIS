# IRIS — Unified OSINT Intelligence Platform

**See everything. Know everyone. Intelligence, unified.**

IRIS is an open-source OSINT reconnaissance suite that consolidates fragmented intelligence sources into one cohesive, intelligent platform. Designed for bug bounty hunters, red teamers, and security researchers, IRIS gathers data across domains, emails, code repositories, and network infrastructure, intelligently correlating findings.

## Features
- **Domain Intelligence**: WHOIS, DNS records, Subdomain enumeration (crt.sh), SSL certificate analysis.
- **Email Intelligence**: Validation, SMTP enumeration, data breach lookups (Have I Been Pwned).
- **Code Intelligence**: GitHub repository search and public code mentions.
- **Network Intelligence**: IP Geolocation and ASN lookups.
- **Correlation Engine**: Automatically links discovered entities (e.g., domains to IP addresses, emails to domains).
- **TUI & CLI**: Beautiful neon cyan Terminal User Interface (TUI) powered by Textual, alongside scriptable Typer CLI commands.
- **Exporting**: Export comprehensive reports to JSON, CSV, or a styled HTML document.

## Quick Start
See `INSTALL.md` for installation instructions.

```bash
# Start the interactive TUI
iris

# Profile a target directly from CLI and export to HTML
iris profile example.com --export html
```

## Environment Variables
Copy `.env.example` to `.env` and fill in your API keys for enhanced functionality.
