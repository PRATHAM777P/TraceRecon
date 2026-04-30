# Security Policy — TraceRecon

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Active  |
| 1.x     | ❌ EOL     |

---

## Ethical Use & Legal Disclaimer

TraceRecon is built exclusively for **authorized security research**, **educational purposes**, and **lawful OSINT investigations**.

> **You are solely responsible for how you use this tool.**
> Unauthorized scanning, tracking, or data collection against systems or individuals without explicit permission may violate local, national, and international laws — including but not limited to:
> - Computer Fraud and Abuse Act (CFAA) — USA
> - Computer Misuse Act — UK
> - General Data Protection Regulation (GDPR) — EU
> - IT Act 2000 — India
> - And equivalent laws in your jurisdiction.

**The authors accept zero liability for misuse.**

---

## What TraceRecon Does NOT Do

- Does **not** store, transmit, or log user inputs to any server
- Does **not** send telemetry or analytics anywhere
- Does **not** require authentication or account creation
- Does **not** perform any action without explicit user input per module run
- Does **not** contain any backdoors, keyloggers, or hidden network calls
- Does **not** persist sensitive data beyond the local `output/` folder

---

## Data Handling

All data produced by TraceRecon is written **locally only** to the `output/` directory in JSON and TXT format. No data is transmitted to the tool's authors or any third party beyond the public APIs used for lookups (e.g. `ipwho.is`, `api.ipify.org`).

**Review the APIs' own privacy policies:**
- https://ipwho.is — IP geolocation
- https://api.ipify.org — Public IP detection
- phonenumbers library — Offline, no network call

---

## Reporting a Vulnerability

If you discover a security issue in TraceRecon:

1. **Do NOT open a public GitHub issue.**
2. Open a **GitHub Security Advisory** (private disclosure) via the repository's Security tab → "Report a vulnerability".
3. Include:
   - Description of the issue
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

We aim to respond within **72 hours** and release a patch within **7 days** for confirmed critical issues.

---

## Responsible Disclosure

We follow a **coordinated disclosure** model. We ask that you:

- Give us reasonable time to fix the issue before public disclosure
- Not exploit the vulnerability beyond what is needed to demonstrate it
- Not access, modify, or delete data belonging to others

In return, we will:

- Acknowledge your contribution in the release notes (if desired)
- Work with you transparently to understand and fix the issue

---

## Secure Usage Recommendations

- Run TraceRecon in an **isolated virtual environment** (`python -m venv venv`)
- Do **not** run as root/Administrator unless strictly necessary
- Review the `output/` directory regularly and delete files you no longer need
- Do **not** pipe TraceRecon output to untrusted scripts

---

## Third-Party API Notice

TraceRecon makes outbound HTTP GET requests to third-party public APIs. These APIs:
- May log your IP address (the IP making the lookup request)
- Are subject to their own rate limits and terms of service
- Are not affiliated with or controlled by TraceRecon authors

Use a VPN or Tor if you require lookup anonymity.

---

*Last updated: 2025*
