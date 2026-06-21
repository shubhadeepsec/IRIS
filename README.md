<p align="center">
  <img src="assets/logo-dark.png" width="200" alt="IRIS — Unified OSINT Platform">
</p>

<h1 align="center">IRIS</h1>

<p align="center">
  <em>See everything. Know everyone. Intelligence, unified.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/malrobust/IRIS?style=flat-square&color=111111&label=stars" alt="Stars">
  <img src="https://img.shields.io/github/v/release/malrobust/IRIS?style=flat-square&color=111111&label=release" alt="Release">
  <img src="https://img.shields.io/badge/targets-Domain%20|%20Email%20|%20IP-111111?style=flat-square" alt="Supported targets">
  <img src="https://img.shields.io/badge/license-MIT-111111?style=flat-square" alt="MIT license">
</p>

<p align="center">
  <strong>WHOIS &middot; DNS &middot; Subdomains &middot; Breaches &middot; Socials &middot; Code &middot; Network &middot; Shodan &middot; Sherlock</strong>
</p>

---

You know the drill. Five different terminal tabs open. Running `whois` in one, `dig` in another, checking `crt.sh` in the browser, searching for breaches on HaveIBeenPwned, and hunting for secrets[...]

**IRIS puts it all into one prompt.**

Designed for modern penetration testers, bug bounty hunters, and threat intelligence analysts, IRIS is a high-performance CLI tool that unifies disparate OSINT data streams into beautifully format[...]

## 🚀 Features & Capabilities

IRIS automatically detects the type of target you provide (Domain, IP, or Email) and executes a highly specialized concurrent intelligence pipeline.

### 🌐 Domains
*   **WHOIS:** Registrar, Creation, Expiry, Status, Name Servers.
*   **DNS:** A, MX, NS, TXT, SPF, and DMARC record parsing.
*   **Subdomains:** Passive subdomain enumeration via `crt.sh`.
*   **SSL:** Live certificate extraction (Issuer, Expiry, Subject Alternative Names).

### 🖥️ Network (IPs)
*   **Geolocation & ASN:** Live IP tracking (City, Country, ISP, Organization).
*   **Shodan Intelligence:** Open ports, service banners, vulnerabilities, and hostnames.

### 📧 Emails (The "Ultimate" Collector)
*   **Breach Ledger (HIBP):** Checks if the email was involved in public data dumps.
*   **Account Discovery (Holehe):** Asynchronously checks password-reset endpoints across **120+ social media and web services** (Twitter, GitHub, Imgur, etc.) to reveal where the target has regis[...]
*   **Professional Profiling (Hunter.io):** Extracts First Name, Last Name, Job Title, Company, and LinkedIn/Twitter profiles.
*   **Gravatar & GitHub Cross-referencing:** Extracts display names, associated wallets, and active code commits.
*   **SMTP Validation:** Validates MX records to ensure the address is capable of receiving mail.

### 💻 Code
*   **GitHub Scanning:** The `/code` command instantly searches GitHub for repositories, sensitive files, or leaked secrets associated with your target.

### 👤 Usernames (Sherlock)
*   **Global Account Hunt:** The `/sherlock <username>` command dynamically searches across hundreds of social networks and websites to find every registered profile associated with a specific use[...]

---

## ⚡ Installation

We've made IRIS incredibly easy to install. It packages its own dependencies and injects an executable directly into your PATH.

### One-Line Install
We've automated the entire setup process. This script creates an isolated virtual environment (PEP-668 compliant) and registers `iris` as a global command.

```bash
curl -sSL https://raw.githubusercontent.com/malrobust/iris/master/install.sh | bash
```

### Running IRIS
Once installed, simply run the tool from anywhere in your terminal:
```bash
iris
```

---

## 🛠️ Usage & Commands

IRIS operates as a highly responsive, interactive REPL. You drop into the shell once, and it remembers your session state, export preferences, and history.

```bash
malrobust@kali:~$ iris

               ▄▄               
              ████              
             ██████             
            ████████            
           ██████████           
▄▄▄▄▄▄▄▄▄▄████████████▄▄▄▄▄▄▄▄▄▄
████████████████████████████████
▀▀▀▀▀▀▀▀▀██████████████▀▀▀▀▀▀▀▀▀
              ████              
             ██████             
              ████              
               ▀▀               

› example.com
```

### Interactive Loop Commands

| Command | What it does | Example |
|---------|--------------|---------|
| `<target>` | Profile a domain, IP, or email instantly. | `example.com`, `admin@example.com`, `1.1.1.1` |
| `/code <target>` | Search GitHub for repositories and secrets. | `/code example.com` |
| `/sherlock <target>` | Search across hundreds of platforms for a username. | `/sherlock admin123` |
| `/export` | Cycle through export modes (`none`, `html`, `json`, `csv`). | `/export` |
| `/config set <K>=<V>`| Set an API key securely (Stored in `~/.iris/config.json`). | `/config set SHODAN_API_KEY=xxx` |
| `/config del <K>`| Delete an API key securely. | `/config del GITHUB_TOKEN` |
| `/status` | Check which API keys are configured and active. | `/status` |
| `clear` | Wipe the console. | `clear` |
| `quit` | Exit the matrix. | `quit` |

---

## 🔑 Premium API Integrations

IRIS works incredibly well **out-of-the-box using free scraping and public APIs**. However, if you want "God Mode" intelligence, you can plug in premium API keys.

You never have to mess with `.env` files. Just drop them directly into the IRIS terminal using `/config set`:

```bash
# Unlock advanced open-port and vulnerability scanning
iris > /config set SHODAN_API_KEY=your_key_here

# Unlock GitHub code searching
iris > /config set GITHUB_TOKEN=your_token_here

# Unlock advanced professional email intelligence (Names, LinkedIn, Company)
iris > /config set HUNTER_API_KEY=your_key_here

# Unlock premium breach lookups
iris > /config set HIBP_API_KEY=your_key_here
```

IRIS encrypts and stores these in `~/.iris/config.json` with strict `0600` permissions. If you don't have a key, IRIS gracefully skips that specific check or falls back to a free alternative.



## 📜 License

[MIT](LICENSE). The clearest license there is. Build on it, break it, make it better.
