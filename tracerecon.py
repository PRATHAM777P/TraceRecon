"""
TraceRecon — Open-Source Intelligence & Network Reconnaissance Toolkit
Version: 2.0.0
"""

# ──────────────────────────────────────────────────────────────────────────────
#  IMPORTS
# ──────────────────────────────────────────────────────────────────────────────
import json
import os
import re
import sys
import time
import socket
import ipaddress
import datetime
import threading
import urllib.parse
from sys import stderr
from pathlib import Path

try:
    import requests
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as ph_timezone
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Run:  pip install -r requirements.txt")
    sys.exit(1)

# Optional deps — gracefully degrade
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois as python_whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


# ──────────────────────────────────────────────────────────────────────────────
#  ANSI COLOURS
# ──────────────────────────────────────────────────────────────────────────────
class C:
    RST  = "\033[0m"
    BLD  = "\033[1m"
    DIM  = "\033[2m"
    RED  = "\033[1;31m"
    GRN  = "\033[1;32m"
    YEL  = "\033[1;33m"
    BLU  = "\033[1;34m"
    MAG  = "\033[1;35m"
    CYN  = "\033[1;36m"
    WHT  = "\033[1;37m"
    BRED = "\033[41m"
    BGRN = "\033[42m"


# ──────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────
VERSION  = "2.0.0"
TIMEOUT  = 8          # seconds for HTTP requests
MAX_THREADS = 10      # username scan concurrency
OUTPUT_DIR  = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; TraceRecon/2.0; +https://github.com/tracerecon)"
})


# ──────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def sep(color=C.GRN, char="─", width=58):
    print(f"{color}{char * width}{C.RST}")


def header(title: str, color=C.GRN):
    sep(color)
    print(f"{color}  {title}{C.RST}")
    sep(color)


def ok(msg):
    print(f" {C.WHT}[{C.GRN}+{C.WHT}]{C.RST} {msg}")


def warn(msg):
    print(f" {C.WHT}[{C.YEL}!{C.WHT}]{C.RST} {C.YEL}{msg}{C.RST}")


def err(msg):
    print(f" {C.WHT}[{C.RED}✗{C.WHT}]{C.RST} {C.RED}{msg}{C.RST}")


def _sanitize_info_value(label: str, value):
    """Mask sensitive values before printing to terminal output."""
    sensitive_labels = {"latitude", "longitude", "google maps"}
    if isinstance(label, str) and label.strip().lower() in sensitive_labels:
        return "[REDACTED]"
    return value


def info(label: str, value, label_color=C.WHT, val_color=C.GRN):
    safe_value = _sanitize_info_value(label, value)
    print(f"  {label_color}{label:<22}{C.RST}: {val_color}{safe_value}{C.RST}")


def save_result(filename: str, data: dict):
    """Persist results to JSON and TXT inside output/."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = OUTPUT_DIR / f"{filename}_{ts}"

    # Redact sensitive/private fields before persistence.
    safe_data = dict(data)
    sensitive_fields = {"latitude", "longitude", "maps"}
    for field in sensitive_fields:
        if field in safe_data:
            safe_data[field] = "[REDACTED]"

    # JSON
    json_path = base.with_suffix(".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(safe_data, f, indent=2, ensure_ascii=False)

    # Plain TXT
    txt_path = base.with_suffix(".txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"TraceRecon Export — {datetime.datetime.now().isoformat()}\n")
        f.write("=" * 60 + "\n")
        for k, v in safe_data.items():
            f.write(f"{k:<24}: {v}\n")

    ok(f"Results saved → {json_path.name}  &  {txt_path.name}")


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def safe_get(url: str, **kwargs) -> requests.Response | None:
    try:
        resp = SESSION.get(url, timeout=TIMEOUT, **kwargs)
        resp.raise_for_status()
        return resp
    except requests.exceptions.Timeout:
        err("Request timed out.")
    except requests.exceptions.ConnectionError:
        err("No network connection.")
    except requests.exceptions.HTTPError as e:
        err(f"HTTP error: {e.response.status_code}")
    except Exception as e:
        err(f"Unexpected error: {e}")
    return None


# ──────────────────────────────────────────────────────────────────────────────
#  BANNER / MENU
# ──────────────────────────────────────────────────────────────────────────────
BANNER = f"""{C.GRN}
  ████████╗██████╗  █████╗  ██████╗███████╗
     ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
     ██║   ██████╔╝███████║██║     █████╗  
     ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
     ██║   ██║  ██║██║  ██║╚██████╗███████╗
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
  {C.WHT}██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗{C.RST}
  {C.WHT}██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║{C.RST}
  {C.WHT}██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║{C.RST}
  {C.WHT}██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║{C.RST}
  {C.WHT}██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║{C.RST}
  {C.WHT}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{C.RST}
{C.GRN}
  ┌──────────────────────────────────────────────────┐
  │  OSINT & Network Reconnaissance Toolkit  v{VERSION}  │
  │  For authorized research & educational use only  │
  └──────────────────────────────────────────────────┘
{C.RST}"""

MENU_ITEMS = [
    (1,  "IP Address Tracker",        "ip",      C.GRN),
    (2,  "My Public IP",              "myip",    C.CYN),
    (3,  "Phone Number OSINT",        "phone",   C.BLU),
    (4,  "Username Recon (OSINT)",    "user",    C.MAG),
    (5,  "DNS Lookup",                "dns",     C.YEL),
    (6,  "WHOIS Domain Lookup",       "whois",   C.CYN),
    (7,  "Reverse DNS (PTR)",         "rdns",    C.GRN),
    (8,  "Subnet / CIDR Calculator",  "subnet",  C.BLU),
    (9,  "Port Scanner (Top Ports)",  "port",    C.RED),
    (0,  "Exit",                      None,      C.RED),
]


def show_menu():
    clear()
    stderr.write(BANNER)
    sep(C.GRN, "═")
    for num, label, _, color in MENU_ITEMS:
        bullet = f"{C.GRN}[{color}{num:>2}{C.GRN}]"
        print(f"  {bullet} {C.WHT}{label}{C.RST}")
    sep(C.GRN, "═")


# ──────────────────────────────────────────────────────────────────────────────
#  MODULE 1 — IP TRACKER
# ──────────────────────────────────────────────────────────────────────────────
def ip_tracker():
    header("IP ADDRESS TRACKER", C.GRN)
    raw = input(f"\n  {C.WHT}Enter target IP{C.RST} (leave blank for auto-detect): {C.GRN}").strip()
    print(C.RST, end="")

    if raw == "":
        r = safe_get("https://api.ipify.org/")
        if not r:
            return
        raw = r.text.strip()
        ok(f"Auto-detected: {raw}")

    if not validate_ip(raw):
        err("Invalid IP address format.")
        return

    print()
    warn("Querying ipwho.is API …")
    resp = safe_get(f"https://ipwho.is/{raw}")
    if not resp:
        return

    try:
        d = resp.json()
    except Exception:
        err("Failed to parse API response.")
        return

    if not d.get("success"):
        err(f"API error: {d.get('message', 'Unknown')}")
        return

    conn = d.get("connection", {})
    tz   = d.get("timezone", {})
    flag = d.get("flag", {})

    print()
    header("RESULT — IP INFORMATION", C.GRN)
    info("Target IP",       d.get("ip"),             C.WHT, C.GRN)
    info("Type",            d.get("type"),            C.WHT, C.CYN)
    info("Country",         f"{d.get('country')} {flag.get('emoji','')}", C.WHT, C.YEL)
    info("Country Code",    d.get("country_code"),    C.WHT, C.GRN)
    info("Region",          d.get("region"),          C.WHT, C.GRN)
    info("Region Code",     d.get("region_code"),     C.WHT, C.GRN)
    info("City",            d.get("city"),            C.WHT, C.GRN)
    info("Postal",          d.get("postal"),          C.WHT, C.GRN)
    info("Latitude",        d.get("latitude"),        C.WHT, C.CYN)
    info("Longitude",       d.get("longitude"),       C.WHT, C.CYN)
    lat = d.get("latitude", 0)
    lon = d.get("longitude", 0)
    info("Google Maps",     f"https://maps.google.com/?q={lat},{lon}", C.WHT, C.BLU)
    info("Continent",       d.get("continent"),       C.WHT, C.GRN)
    info("Is EU",           d.get("is_eu"),           C.WHT, C.GRN)
    info("Calling Code",    d.get("calling_code"),    C.WHT, C.GRN)
    info("Capital",         d.get("capital"),         C.WHT, C.GRN)
    info("Borders",         d.get("borders"),         C.WHT, C.GRN)
    info("ASN",             conn.get("asn"),          C.WHT, C.MAG)
    info("Organization",    conn.get("org"),          C.WHT, C.MAG)
    info("ISP",             conn.get("isp"),          C.WHT, C.MAG)
    info("Domain",          conn.get("domain"),       C.WHT, C.MAG)
    info("Timezone ID",     tz.get("id"),             C.WHT, C.YEL)
    info("UTC Offset",      tz.get("utc"),            C.WHT, C.YEL)
    info("Current Time",    tz.get("current_time"),   C.WHT, C.YEL)
    sep(C.GRN)

    export = input(f"\n  {C.WHT}Export results? {C.GRN}[y/N]{C.RST}: ").strip().lower()
    if export == "y":
        save_result("ip_tracker", {
            "ip": d.get("ip"), "type": d.get("type"),
            "country": d.get("country"), "city": d.get("city"),
            "latitude": lat, "longitude": lon,
            "isp": conn.get("isp"), "asn": conn.get("asn"),
            "maps": f"https://maps.google.com/?q={lat},{lon}",
            "timezone": tz.get("id"), "current_time": tz.get("current_time"),
        })


# ──────────────────────────────────────────────────────────────────────────────
#  MODULE 2 — MY PUBLIC IP
# ──────────────────────────────────────────────────────────────────────────────
def my_ip():
    header("MY PUBLIC IP ADDRESS", C.CYN)
    warn("Fetching your public IP …")

    # Try multiple providers for reliability
    providers = [
        ("https://api.ipify.org/",          lambda r: r.text.strip()),
        ("https://api64.ipify.org/",        lambda r: r.text.strip()),
        ("https://ipinfo.io/ip",            lambda r: r.text.strip()),
    ]

    public_ip = None
    for url, extractor in providers:
        r = safe_get(url)
        if r:
            public_ip = extractor(r)
            break

    if not public_ip:
        err("Could not determine public IP.")
        return

    print()
    info("Public IP", public_ip, C.WHT, C.GRN)

    # Extra info via ipwho.is
    r2 = safe_get(f"https://ipwho.is/{public_ip}")
    if r2:
        try:
            d = r2.json()
            info("Country",  f"{d.get('country')} {d.get('flag',{}).get('emoji','')}", C.WHT, C.YEL)
            info("City",     d.get("city"),                    C.WHT, C.GRN)
            info("ISP",      d.get("connection",{}).get("isp"), C.WHT, C.MAG)
        except Exception:
            pass
    sep(C.CYN)


# ──────────────────────────────────────────────────────────────────────────────
#  MODULE 3 — PHONE NUMBER OSINT
# ──────────────────────────────────────────────────────────────────────────────
def phone_osint():
    header("PHONE NUMBER OSINT", C.BLU)
    raw = input(f"\n  {C.WHT}Enter phone number {C.GRN}[+countrycode number]{C.WHT}: {C.GRN}").strip()
    print(C.RST, end="")

    if not raw:
        err("No input provided.")
        return

    # Auto-prepend + if missing
    if not raw.startswith("+"):
        raw = "+" + raw.lstrip("0")

    try:
        parsed = phonenumbers.parse(raw, None)
    except phonenumbers.NumberParseException as e:
        err(f"Parse error: {e}")
        return

    if not phonenumbers.is_valid_number(parsed):
        warn("Number may not be valid — showing available data anyway.")

    tz_list   = ph_timezone.time_zones_for_number(parsed)
    tz_str    = ", ".join(tz_list) if tz_list else "Unknown"
    provider  = carrier.name_for_number(parsed, "en")
    location  = geocoder.description_for_number(parsed, "en")
    region    = phonenumbers.region_code_for_number(parsed)
    num_type  = phonenumbers.number_type(parsed)

    type_map = {
        phonenumbers.PhoneNumberType.MOBILE:        "Mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE:    "Fixed Line",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE:     "Toll Free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE:  "Premium Rate",
        phonenumbers.PhoneNumberType.VOIP:          "VoIP",
        phonenumbers.PhoneNumberType.PAGER:         "Pager",
        phonenumbers.PhoneNumberType.SHARED_COST:   "Shared Cost",
    }
    readable_type = type_map.get(num_type, "Unknown")

    e164    = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    intl    = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national= phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

    print()
    header("RESULT — PHONE INFORMATION", C.BLU)
    info("Input Number",    raw,                   C.WHT, C.GRN)
    info("E.164 Format",    e164,                  C.WHT, C.GRN)
    info("International",   intl,                  C.WHT, C.GRN)
    info("National Format", national,              C.WHT, C.GRN)
    info("Country Code",    f"+{parsed.country_code}", C.WHT, C.CYN)
    info("Region",          region,                C.WHT, C.CYN)
    info("Location",        location or "Unknown", C.WHT, C.YEL)
    info("Carrier/Operator",provider or "Unknown", C.WHT, C.MAG)
    info("Number Type",     readable_type,         C.WHT, C.BLU)
    info("Valid",           phonenumbers.is_valid_number(parsed),  C.WHT, C.GRN)
    info("Possible",        phonenumbers.is_possible_number(parsed), C.WHT, C.GRN)
    info("Timezone(s)",     tz_str,                C.WHT, C.YEL)
    sep(C.BLU)

    export = input(f"\n  {C.WHT}Export results? {C.GRN}[y/N]{C.RST}: ").strip().lower()
    if export == "y":
        save_result("phone_osint", {
            "input": raw, "e164": e164, "international": intl,
            "region": region, "location": location,
            "carrier": provider, "type": readable_type,
            "timezone": tz_str,
        })


# ──────────────────────────────────────────────────────────────────────────────
#  MODULE 4 — USERNAME RECON
# ──────────────────────────────────────────────────────────────────────────────
SOCIAL_SITES = [
    ("Facebook",     "https://www.facebook.com/{}"),
    ("Twitter/X",    "https://x.com/{}"),
    ("Instagram",    "https://www.instagram.com/{}"),
    ("LinkedIn",     "https://www.linkedin.com/in/{}"),
    ("GitHub",       "https://github.com/{}"),
    ("GitLab",       "https://gitlab.com/{}"),
    ("Pinterest",    "https://www.pinterest.com/{}"),
    ("TikTok",       "https://www.tiktok.com/@{}"),
    ("YouTube",      "https://www.youtube.com/@{}"),
    ("Twitch",       "https://www.twitch.tv/{}"),
    ("Snapchat",     "https://www.snapchat.com/add/{}"),
    ("Reddit",       "https://www.reddit.com/user/{}"),
    ("Tumblr",       "https://{}.tumblr.com"),
    ("Medium",       "https://medium.com/@{}"),
    ("Quora",        "https://www.quora.com/profile/{}"),
    ("SoundCloud",   "https://soundcloud.com/{}"),
    ("Behance",      "https://www.behance.net/{}"),
    ("Dribbble",     "https://dribbble.com/{}"),
    ("Flickr",       "https://www.flickr.com/people/{}"),
    ("Steam",        "https://steamcommunity.com/id/{}"),
    ("Telegram",     "https://t.me/{}"),
    ("Product Hunt", "https://www.producthunt.com/@{}"),
    ("HackerNews",   "https://news.ycombinator.com/user?id={}"),
    ("Keybase",      "https://keybase.io/{}"),
    ("Pastebin",     "https://pastebin.com/u/{}"),
    ("Replit",       "https://replit.com/@{}"),
    ("Codepen",      "https://codepen.io/{}"),
    ("Dev.to",       "https://dev.to/{}"),
    ("Mastodon",     "https://mastodon.social/@{}"),
    ("Vimeo",        "https://vimeo.com/{}"),
]


def _check_site(name, url_tmpl, username, found, lock):
    url = url_tmpl.format(urllib.parse.quote(username))
    try:
        r = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)
        found_flag = r.status_code == 200 and "not found" not in r.text.lower()[:500]
    except Exception:
        found_flag = False
    with lock:
        found.append((name, url, found_flag))


def username_recon():
    header("USERNAME RECON — OSINT", C.MAG)
    uname = input(f"\n  {C.WHT}Enter username to hunt{C.WHT}: {C.MAG}").strip()
    print(C.RST, end="")

    if not uname or len(uname) < 1:
        err("Username cannot be empty.")
        return

    # Basic validation
    if not re.match(r"^[\w.\-@]+$", uname):
        warn("Username contains unusual characters — results may vary.")

    print()
    warn(f"Scanning {len(SOCIAL_SITES)} platforms for '{uname}' …")
    sep(C.MAG, "─")

    found   = []
    lock    = threading.Lock()
    threads = []

    for name, url_tmpl in SOCIAL_SITES:
        t = threading.Thread(
            target=_check_site,
            args=(name, url_tmpl, uname, found, lock),
            daemon=True
        )
        threads.append(t)

    # Throttle to MAX_THREADS at a time
    for i in range(0, len(threads), MAX_THREADS):
        batch = threads[i:i + MAX_THREADS]
        for t in batch:
            t.start()
        for t in batch:
            t.join()
        time.sleep(0.3)

    found.sort(key=lambda x: x[0])

    hit_count  = sum(1 for _, _, f in found if f)
    miss_count = len(found) - hit_count

    print()
    header(f"RESULT — {hit_count} MATCHES / {miss_count} NOT FOUND", C.MAG)
    for name, url, was_found in found:
        if was_found:
            print(f"  {C.GRN}[FOUND]{C.RST}   {C.WHT}{name:<16}{C.RST} → {C.GRN}{url}{C.RST}")
        else:
            print(f"  {C.RED}[---]{C.RST}     {C.WHT}{name:<16}{C.RST} → {C.DIM}not found{C.RST}")
    sep(C.MAG)

    export = input(f"\n  {C.WHT}Export results? {C.GRN}[y/N]{C.RST}: ").strip().lower()
    if export == "y":
        data = {"username": uname, "scanned": len(found), "found": hit_count}
        for name, url, was_found in found:
            data[name] = url if was_found else "NOT FOUND"
        save_result("username_recon", data)


# ──────────────────────────────────────────────────────────────────────────────
#  MODULE 5 — DNS LOOKUP
# ──────────────────────────────────────────────────────────────────────────────
def dns_lookup():
    header("DNS LOOKUP", C.YEL)

    if not HAS_DNS:
        err("dnspython not installed.  Run: pip install dnspython")
        return

    domain = input(f"\n  {C.WHT}Enter domain (e.g. example.com){C.WHT}: {C.YEL}").strip()
    print(C.RST, end="")

    if not domain:
        err("No domain provided.")
        return

    # Strip protocol if user pastes URL
    domain = re.sub(r"^https?://", "", domain).rstrip("/").split("/")[0]

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]
    results = {}

    print()
    warn(f"Resolving DNS records for: {domain}")
    sep(C.YEL, "─")

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=6)
            entries = []
            for ans in answers:
                entries.append(str(ans).strip())
            results[rtype] = entries

            color = C.GRN
            print(f"  {C.YEL}[{rtype:<5}]{C.RST} {color}{', '.join(entries)}{C.RST}")
        except dns.resolver.NoAnswer:
            print(f"  {C.YEL}[{rtype:<5}]{C.RST} {C.DIM}— no record —{C.RST}")
        except dns.resolver.NXDOMAIN:
            err(f"Domain '{domain}' does not exist.")
            return
        except Exception:
            print(f"  {C.YEL}[{rtype:<5}]{C.RST} {C.DIM}error{C.RST}")

    sep(C.YEL)
    export = input(f"\n  {C.WHT}Export results? {C.GRN}[y/N]{C.RST}: ").strip().lower()
    if export == "y":
        flat = {"domain": domain}
        for k, v in results.items():
            flat[k] = "; ".join(v)
        save_result("dns_lookup", flat)


# ──────────────────────────────────────────────────────────────────────────────
#  MODULE 6 — WHOIS LOOKUP
# ──────────────────────────────────────────────────────────────────────────────
def whois_lookup():
    header("WHOIS DOMAIN LOOKUP", C.CYN)

    if not HAS_WHOIS:
        err("python-whois not installed.  Run: pip install python-whois")
        return

    domain = input(f"\n  {C.WHT}Enter domain (e.g. example.com){C.WHT}: {C.CYN}").strip()
    print(C.RST, end="")

    if not domain:
        err("No domain provided.")
        return

    domain = re.sub(r"^https?://", "", domain).rstrip("/").split("/")[0]

    warn(f"Querying WHOIS for: {domain} …")
    print()

    try:
        w = python_whois.whois(domain)
    except Exception as e:
        err(f"WHOIS query failed: {e}")
        return

    def fmt(val):
        if val is None:
            return "N/A"
        if isinstance(val, list):
            return ", ".join(str(v) for v in val[:3])
        return str(val)

    header("RESULT — WHOIS INFORMATION", C.CYN)
    info("Domain Name",    fmt(w.get("domain_name")),    C.WHT, C.GRN)
    info("Registrar",      fmt(w.get("registrar")),      C.WHT, C.YEL)
    info("Created",        fmt(w.get("creation_date")),  C.WHT, C.GRN)
    info("Updated",        fmt(w.get("updated_date")),   C.WHT, C.GRN)
    info("Expires",        fmt(w.get("expiration_date")),C.WHT, C.RED)
    info("Status",         fmt(w.get("status")),         C.WHT, C.CYN)
    info("Name Servers",   fmt(w.get("name_servers")),   C.WHT, C.MAG)
    info("Registrant Org", fmt(w.get("org")),            C.WHT, C.YEL)
    info("Registrant Country", fmt(w.get("country")),   C.WHT, C.GRN)
    info("Emails",         fmt(w.get("emails")),         C.WHT, C.BLU)
    info("DNSSEC",         fmt(w.get("dnssec")),         C.WHT, C.GRN)
    sep(C.CYN)

    export = input(f"\n  {C.WHT}Export results? {C.GRN}[y/N]{C.RST}: ").strip().lower()
    if export == "y":
        save_result("whois_lookup", {
            "domain": fmt(w.get("domain_name")),
            "registrar": fmt(w.get("registrar")),
            "created": fmt(w.get("creation_date")),
            "expires": fmt(w.get("expiration_date")),
            "name_servers": fmt(w.get("name_servers")),
            "country": fmt(w.get("country")),
        })


# ──────────────────────────────────────────────────────────────────────────────
#  MODULE 7 — REVERSE DNS
# ──────────────────────────────────────────────────────────────────────────────
def reverse_dns():
    header("REVERSE DNS (PTR LOOKUP)", C.GRN)
    ip = input(f"\n  {C.WHT}Enter IP address{C.WHT}: {C.GRN}").strip()
    print(C.RST, end="")

    if not validate_ip(ip):
        err("Invalid IP address.")
        return

    print()
    warn(f"Performing reverse DNS for {ip} …")

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = None
    except Exception as e:
        err(f"Lookup error: {e}")
        return

    if hostname:
        ok(f"Hostname: {C.GRN}{hostname}{C.RST}")
    else:
        warn("No PTR record found for this IP.")

    # Extra: forward confirm
    if hostname:
        try:
            fwd = socket.gethostbyname(hostname)
            if fwd == ip:
                ok(f"Forward-confirmed: {C.GRN}{fwd} → {hostname}{C.RST}")
            else:
                warn(f"Forward mismatch: {fwd} ≠ {ip} (possible spoofing?)")
        except Exception:
            warn("Forward lookup failed.")

    sep(C.GRN)


# ──────────────────────────────────────────────────────────────────────────────
#  MODULE 8 — SUBNET CALCULATOR
# ──────────────────────────────────────────────────────────────────────────────
def subnet_calc():
    header("SUBNET / CIDR CALCULATOR", C.BLU)
    raw = input(f"\n  {C.WHT}Enter IP/CIDR (e.g. 192.168.1.0/24){C.WHT}: {C.BLU}").strip()
    print(C.RST, end="")

    if not raw:
        err("No input.")
        return

    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError as e:
        err(f"Invalid CIDR: {e}")
        return

    print()
    header("RESULT — SUBNET INFO", C.BLU)
    info("Network",       str(net),             C.WHT, C.GRN)
    info("CIDR",          f"/{net.prefixlen}",  C.WHT, C.GRN)
    info("Network Addr",  str(net.network_address), C.WHT, C.CYN)
    info("Broadcast",     str(net.broadcast_address), C.WHT, C.RED)
    info("Netmask",       str(net.netmask),     C.WHT, C.YEL)
    info("Hostmask",      str(net.hostmask),    C.WHT, C.YEL)
    info("Total Hosts",   net.num_addresses,    C.WHT, C.GRN)
    info("Usable Hosts",  max(net.num_addresses - 2, 0), C.WHT, C.GRN)
    info("IP Version",    f"IPv{net.version}",  C.WHT, C.MAG)
    info("Is Private",    net.is_private,       C.WHT, C.BLU)
    info("Is Global",     net.is_global,        C.WHT, C.BLU)
    info("Is Loopback",   net.is_loopback,      C.WHT, C.BLU)
    info("Is Multicast",  net.is_multicast,     C.WHT, C.BLU)

    # Show first/last usable
    hosts = list(net.hosts())
    if hosts:
        info("First Host",   str(hosts[0]),  C.WHT, C.GRN)
        info("Last Host",    str(hosts[-1]), C.WHT, C.GRN)

    sep(C.BLU)


# ──────────────────────────────────────────────────────────────────────────────
#  MODULE 9 — PORT SCANNER
# ──────────────────────────────────────────────────────────────────────────────
TOP_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def _scan_port(host, port, open_ports, lock):
    try:
        with socket.create_connection((host, port), timeout=1):
            with lock:
                open_ports.append(port)
    except Exception:
        pass


def port_scanner():
    header("PORT SCANNER — TOP COMMON PORTS", C.RED)
    warn("For authorized use only. Only scan systems you own or have permission to scan.")
    print()
    host = input(f"  {C.WHT}Enter host / IP{C.WHT}: {C.RED}").strip()
    print(C.RST, end="")

    if not host:
        err("No host provided.")
        return

    # Resolve hostname
    try:
        resolved = socket.gethostbyname(host)
        if resolved != host:
            ok(f"Resolved: {host} → {resolved}")
    except socket.gaierror:
        err("Could not resolve hostname.")
        return

    print()
    warn(f"Scanning {len(TOP_PORTS)} common ports on {resolved} …")
    sep(C.RED, "─")

    open_ports = []
    lock = threading.Lock()
    threads = []

    for port in TOP_PORTS:
        t = threading.Thread(
            target=_scan_port,
            args=(resolved, port, open_ports, lock),
            daemon=True
        )
        threads.append(t)

    for i in range(0, len(threads), MAX_THREADS):
        batch = threads[i:i + MAX_THREADS]
        for t in batch:
            t.start()
        for t in batch:
            t.join()

    open_ports.sort()

    print()
    if open_ports:
        header(f"OPEN PORTS — {len(open_ports)} found", C.RED)
        for p in open_ports:
            svc = TOP_PORTS.get(p, "Unknown")
            print(f"  {C.GRN}[OPEN]{C.RST}  {C.WHT}{p:<7}{C.RST} {C.YEL}{svc}{C.RST}")
    else:
        warn("No open ports found in common port range.")
        warn("Host may be firewalled or unreachable.")

    sep(C.RED)

    export = input(f"\n  {C.WHT}Export results? {C.GRN}[y/N]{C.RST}: ").strip().lower()
    if export == "y":
        data = {"host": host, "resolved": resolved, "open_ports": open_ports}
        for p in open_ports:
            data[str(p)] = TOP_PORTS.get(p, "Unknown")
        save_result("port_scan", data)


# ──────────────────────────────────────────────────────────────────────────────
#  MAIN LOOP
# ──────────────────────────────────────────────────────────────────────────────
HANDLERS = {
    1: ip_tracker,
    2: my_ip,
    3: phone_osint,
    4: username_recon,
    5: dns_lookup,
    6: whois_lookup,
    7: reverse_dns,
    8: subnet_calc,
    9: port_scanner,
}


def run_module(num: int):
    fn = HANDLERS.get(num)
    if fn:
        print()
        try:
            fn()
        except KeyboardInterrupt:
            print(f"\n{C.YEL}  Interrupted — returning to menu.{C.RST}")
        input(f"\n  {C.WHT}[ {C.GRN}ENTER{C.WHT} ] {C.GRN}Press enter to continue …{C.RST}")
    elif num == 0:
        print(f"\n{C.GRN}  Goodbye.{C.RST}\n")
        sys.exit(0)
    else:
        err("Invalid option.")
        time.sleep(1)


def main():
    while True:
        show_menu()
        try:
            choice = input(
                f"\n  {C.WHT}[ {C.GRN}?{C.WHT} ] {C.GRN}Select option{C.WHT}: {C.GRN}"
            ).strip()
            print(C.RST, end="")
            num = int(choice)
            run_module(num)
        except ValueError:
            err("Please enter a number.")
            time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{C.GRN}  Goodbye.{C.RST}\n")
            sys.exit(0)


if __name__ == "__main__":
    main()
