#!/usr/bin/env python3
"""
heimdall.py - Fast Web Enumeration & Crawler
------------------------------------------
Pre-fuzzing recon tool for CTF/pentest environments.
Crawls a target, fingerprints low-hanging fruit, and outputs
colorized stdout + structured JSON report.

Usage:
    python webspy.py --target http://target.htb --threads 10 --depth 5 --output report.json
    python webspy.py --target http://target.htb --proxy http://127.0.0.1:8080 --no-verify-ssl
    python webspy.py --target http://target.htb --dnsbrutehosts /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

Dependencies:
    pip install requests beautifulsoup4
"""

import re
import sys
import json
import time
import argparse
import logging
import threading
import socket
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

try:
    import requests
    from bs4 import BeautifulSoup
    requests.packages.urllib3.disable_warnings()
except ImportError:
    sys.exit("[!] pip install requests beautifulsoup4")

# ---------------------------------------------------------------------------
# ANSI Colors
# ---------------------------------------------------------------------------
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    GREY    = "\033[90m"
    WHITE   = "\033[97m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ██╗  ██╗███████╗██╗███╗   ███╗██████╗  █████╗ ██╗     ██╗     
  ██║  ██║██╔════╝██║████╗ ████║██╔══██╗██╔══██╗██║     ██║     
  ███████║█████╗  ██║██╔████╔██║██║  ██║███████║██║     ██║     
  ██╔══██║██╔══╝  ██║██║╚██╔╝██║██║  ██║██╔══██║██║     ██║     
  ██║  ██║███████╗██║██║ ╚═╝ ██║██████╔╝██║  ██║███████╗███████╗
  ╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
{C.RESET}{C.GREY}  Watchman of Bifröst | Web Enumeration & Crawler
  Nothing crosses unseen.{C.RESET}
""")

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
LOG_LOCK = threading.Lock()

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(level, msg, color=C.WHITE):
    with LOG_LOCK:
        level_colors = {
            "INFO":     C.CYAN,
            "FIND":     C.GREEN,
            "HIGH":     C.RED,
            "MED":      C.ORANGE,
            "LOW":      C.YELLOW,
            "WARN":     C.YELLOW,
            "ERR":      C.RED,
            "ENUM":     C.MAGENTA,
            "DNS":      C.BLUE,
            "DISCOVER": C.MAGENTA,
        }
        lc = level_colors.get(level, C.WHITE)
        print(f"{C.GREY}{ts()}{C.RESET} {lc}[{level}]{C.RESET} {color}{msg}{C.RESET}")

# ---------------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------------
EMAIL_RE      = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I)
COMMENT_RE    = re.compile(r"<!--(.*?)-->", re.DOTALL)
IP_RE         = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
VERSION_RE    = re.compile(r"(?:v|version)[:\s/]*([\d]+\.[\d]+[\.\d]*)", re.I)

# High-value path patterns
HIGH_VALUE_PATHS = [
    r"admin", r"administrator", r"wp-admin", r"wp-login", r"login",
    r"signin", r"sign-in", r"dashboard", r"portal", r"manage",
    r"management", r"console", r"cpanel", r"plesk", r"phpmyadmin",
    r"pma", r"adminer", r"shell", r"webshell", r"upload", r"uploads",
    r"backup", r"backups", r"config", r"configuration", r"setup",
    r"install", r"installer", r"\.git", r"\.env", r"\.htaccess",
    r"api/v", r"graphql", r"swagger", r"actuator", r"jenkins",
    r"jira", r"confluence", r"gitlab", r"bitbucket"
]
HIGH_VALUE_RE = re.compile("|".join(HIGH_VALUE_PATHS), re.I)

# LFI indicators
LFI_PARAMS    = re.compile(r"(?:file|path|page|include|dir|document|folder|root|"
                            r"pg|style|pdf|template|php_path|doc|load|read|lang|locale)=", re.I)
PHP_WRAPPER   = re.compile(r"php://|data://|expect://|zip://|phar://", re.I)

# Command injection indicators
CMD_PARAMS    = re.compile(r"(?:cmd|exec|command|execute|ping|query|jump|code|"
                            r"reg|do|func|arg|option|load|process|step|read|"
                            r"feature|exe|module|payload|run|print)=", re.I)

# XSS surface indicators
FEEDBACK_RE   = re.compile(r"(?:contact|feedback|comment|review|message|"
                            r"submit|reply|support|ticket|report|enquiry|inquiry)", re.I)

# CMS fingerprints
CMS_PATTERNS  = {
    "WordPress":  [r"wp-content", r"wp-includes", r"wp-json", r"xmlrpc\.php"],
    "Joomla":     [r"joomla", r"com_content", r"/components/com_"],
    "Drupal":     [r"drupal", r"sites/default", r"misc/drupal\.js"],
    "Magento":    [r"magento", r"mage/", r"skin/frontend"],
    "Laravel":    [r"laravel", r"_token", r"csrf-token.*laravel"],
    "Django":     [r"csrfmiddlewaretoken", r"django"],
    "Spring":     [r"spring", r"actuator", r"springframework"],
    "Struts":     [r"struts", r"\.action", r"\.do\?"],
}

# ---------------------------------------------------------------------------
# Session builder
# ---------------------------------------------------------------------------
def build_session(proxy_url, verify_ssl, user_agent, cookies=None):
    s = requests.Session()
    if proxy_url:
        s.proxies = {"http": proxy_url, "https": proxy_url}
    #s.verify = verify_ssl
    s.verify = False
    s.headers.update({"User-Agent": user_agent})
    if cookies:
        s.cookies.update(cookies)
    return s

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def normalize_url(url):
    p = urlparse(url)
    return p._replace(fragment="").geturl()

def same_host(url, allowed_host):
    return urlparse(url).netloc == allowed_host

def classify_asset(url):
    """Return asset type based on file extension or path patterns."""
    path = urlparse(url).path.lower()
    ext  = path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
    if ext in ("js", "mjs"):                        return "js"
    if ext in ("css",):                             return "css"
    if ext in ("html", "htm", "xhtml", "php",
               "asp", "aspx", "jsp", "cfm",
               "pl", "rb", "py"):                   return "page"
    if ext in ("pdf", "doc", "docx", "xls",
               "xlsx", "ppt", "pptx", "txt",
               "csv", "xml", "json", "yaml",
               "yml", "md", "log", "bak",
               "sql", "zip", "tar", "gz",
               "7z", "rar"):                        return "file"
    if ext in ("png", "jpg", "jpeg", "gif",
               "svg", "ico", "webp", "bmp"):        return "image"
    if ext in ("woff", "woff2", "ttf", "eot",
               "otf"):                              return "font"
    if ext in ("mp4", "mp3", "webm", "ogg",
               "wav", "avi", "mov"):                return "media"
    # No extension — likely a directory or clean route
    if not ext or path.endswith("/"):               return "directory"
    return "other"


def extract_assets(base_url, html, allowed_host):
    """
    Comprehensive passive asset extraction from HTML.
    Returns:
        crawl_queue : set of same-host URLs to follow (pages only)
        assets      : dict keyed by type -> list of absolute URLs
    """
    soup = BeautifulSoup(html, "html.parser")
    all_refs   = set()
    crawl_next = set()

    # Tag -> attribute mappings to scrape
    TAG_ATTRS = [
        ("a",       "href"),
        ("script",  "src"),
        ("link",    "href"),
        ("img",     "src"),
        ("img",     "data-src"),        # lazy-load
        ("source",  "src"),
        ("source",  "srcset"),
        ("iframe",  "src"),
        ("frame",   "src"),
        ("form",    "action"),
        ("button",  "formaction"),
        ("input",   "formaction"),
        ("video",   "src"),
        ("audio",   "src"),
        ("track",   "src"),
        ("embed",   "src"),
        ("object",  "data"),
        ("meta",    "content"),         # meta refresh redirects
    ]

    for tag_name, attr in TAG_ATTRS:
        for tag in soup.find_all(tag_name, **{attr: True}):
            raw = tag[attr].strip()
            if not raw or raw.startswith(("javascript:", "data:", "mailto:", "#")):
                continue
            # Handle srcset (space-separated url descriptor pairs)
            if attr == "srcset":
                for part in raw.split(","):
                    part = part.strip().split()[0]
                    if part:
                        absolute = urljoin(base_url, part)
                        all_refs.add(normalize_url(absolute))
                continue
            # meta refresh: content="0; url=..."
            if tag_name == "meta":
                url_match = re.search(r"url=([^\s;\"']+)", raw, re.I)
                if url_match:
                    raw = url_match.group(1)
                else:
                    continue
            absolute = urljoin(base_url, raw)
            parsed   = urlparse(absolute)
            if parsed.scheme not in ("http", "https"):
                continue
            all_refs.add(normalize_url(absolute))

    # Also scrape inline CSS for url() references
    for style_tag in soup.find_all("style"):
        for css_url in re.findall(r'url\(["\']?([^"\')\s]+)["\']?\)', style_tag.string or ""):
            if not css_url.startswith("data:"):
                absolute = urljoin(base_url, css_url)
                all_refs.add(normalize_url(absolute))

    # Scrape inline JS for string literals that look like paths
    PATH_IN_JS = re.compile(r'["\'](\/?[\w\-./]+\.(?:php|asp|aspx|jsp|html|htm|js|json|xml))["\']', re.I)
    for script_tag in soup.find_all("script"):
        if not script_tag.get("src") and script_tag.string:
            for match in PATH_IN_JS.findall(script_tag.string):
                absolute = urljoin(base_url, match)
                parsed   = urlparse(absolute)
                if parsed.scheme in ("http", "https"):
                    all_refs.add(normalize_url(absolute))

    # Classify and separate
    assets = defaultdict(list)
    for ref in all_refs:
        atype = classify_asset(ref)
        assets[atype].append(ref)
        # Only queue same-host pages/directories for crawling
        if same_host(ref, allowed_host) and atype in ("page", "directory", "other"):
            crawl_next.add(ref)

    # Always queue same-host JS for passive scanning (not crawl depth — just fetch once)
    for ref in assets.get("js", []):
        if same_host(ref, allowed_host):
            crawl_next.add(ref)

    return crawl_next, dict(assets)


def extract_links(base_url, html, allowed_host):
    """Thin wrapper kept for compatibility — returns crawlable links only."""
    crawl_next, _ = extract_assets(base_url, html, allowed_host)
    return crawl_next

def extract_emails(text):
    return sorted(set(EMAIL_RE.findall(text)))

def extract_comments(html):
    raw = COMMENT_RE.findall(html)
    cleaned = [c.strip() for c in raw if c.strip() and len(c.strip()) > 3]
    return cleaned

def extract_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            itype = inp.get("type", "text")
            if name:
                inputs.append({"name": name, "type": itype})
        forms.append({
            "action": urljoin(base_url, action) if action else base_url,
            "method": method,
            "inputs": inputs
        })
    return forms

def detect_cms(html, headers):
    detected = []
    combined = html + str(headers)
    for cms, patterns in CMS_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, combined, re.I):
                detected.append(cms)
                break
    return list(set(detected))

def check_high_value(url):
    path = urlparse(url).path
    return bool(HIGH_VALUE_RE.search(path))

def check_lfi_surface(url):
    qs = urlparse(url).query
    return bool(LFI_PARAMS.search(qs)) or bool(PHP_WRAPPER.search(url))

def check_cmd_surface(url):
    qs = urlparse(url).query
    return bool(CMD_PARAMS.search(qs))

def check_xss_surface(html, url):
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    has_feedback = bool(FEEDBACK_RE.search(urlparse(url).path))
    has_forms = len(forms) > 0
    has_input = bool(soup.find_all(["input", "textarea"]))
    return has_feedback or (has_forms and has_input)

def scrape_robots(session, base_url):
    urls = []
    try:
        r = session.get(f"{base_url}/robots.txt", timeout=10)
        if r.status_code == 200:
            log("ENUM", f"robots.txt found [{r.status_code}]", C.MAGENTA)
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        path = parts[1].strip()
                        if path and path != "/":
                            full = urljoin(base_url, path)
                            urls.append(full)
                            log("ENUM", f"  robots.txt ref: {full}", C.GREY)
    except Exception as e:
        log("WARN", f"robots.txt error: {e}")
    return urls

def scrape_sitemap(session, base_url):
    urls = []
    sitemaps = ["/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"]
    for path in sitemaps:
        try:
            r = session.get(f"{base_url}{path}", timeout=10)
            if r.status_code == 200 and ("xml" in r.headers.get("Content-Type", "") or "<url" in r.text):
                log("ENUM", f"{path} found [{r.status_code}]", C.MAGENTA)
                found = re.findall(r"<loc>(.*?)</loc>", r.text)
                for u in found:
                    u = u.strip()
                    if u:
                        urls.append(u)
                        log("ENUM", f"  sitemap ref: {u}", C.GREY)
                break
        except Exception as e:
            log("WARN", f"sitemap error: {e}")
    return urls

def scrape_hvts(session, base_url):
    urls = []
    for path in HIGH_VALUE_PATHS:
        try:
            r = session.get(f"{base_url}/{path}", timeout=10)
            if r.status_code == 200 and ("xml" in r.headers.get("Content-Type", "") or "<url" in r.text):
                log("ENUM", f"/{path} found [{r.status_code}]", C.MAGENTA)
                found = re.findall(r"<loc>(.*?)</loc>", r.text)
                for u in found:
                    u = u.strip()
                    if u:
                        urls.append(u)
                        log("ENUM", f"  hvt ref: {u}", C.GREY)
                break
        except Exception as e:
            log("WARN", f"hvt error: {e}")
    return urls


def ping_host(host):
    """Basic TCP ping to check host reachability on common ports."""
    results = {}
    ports = [80, 443, 8080, 8443, 22, 21, 3306, 5432]
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                results[port] = "open"
        except Exception:
            pass
    return results

# ---------------------------------------------------------------------------
# Nmap XML ingestion
# ---------------------------------------------------------------------------

# Ports/services we consider web targets
WEB_PORTS = {
    80:   "http",
    443:  "https",
    8080: "http",
    8443: "https",
    8000: "http",
    8008: "http",
    8888: "http",
    8880: "http",
    9090: "http",
    9443: "https",
    3000: "http",
    4443: "https",
    5000: "http",
    7443: "https",
}

WEB_SERVICE_NAMES = re.compile(
    r"http|https|web|www|ssl/http|http-proxy|http-alt|"
    r"tomcat|apache|nginx|iis|jetty|lighttpd|caddy|gunicorn",
    re.I
)

def parse_nmap_xml(xml_path):
    """
    Parse an nmap XML file and extract all web service targets.
    Returns a list of dicts:
      { "url": "http://x.x.x.x:80", "ip": "x.x.x.x",
        "port": 80, "scheme": "http",
        "hostname": "target.htb" or None,
        "service": "http", "product": "Apache httpd",
        "version": "2.4.51", "state": "open" }
    """
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        log("ERR", f"Failed to parse nmap XML: {e}")
        return []
    except FileNotFoundError:
        log("ERR", f"nmap XML not found: {xml_path}")
        return []

    root    = tree.getroot()
    targets = []

    for host in root.findall("host"):
        # Skip hosts that are not up
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Primary IP
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        if not ip:
            continue

        # Hostnames (PTR or user-supplied)
        hostnames = []
        hn_block = host.find("hostnames")
        if hn_block is not None:
            for hn in hn_block.findall("hostname"):
                name = hn.get("name", "").strip()
                if name:
                    hostnames.append(name)

        # Ports
        ports_block = host.find("ports")
        if ports_block is None:
            continue

        for port_el in ports_block.findall("port"):
            port_num = int(port_el.get("portid", 0))
            proto    = port_el.get("protocol", "tcp")
            if proto != "tcp":
                continue

            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            svc_name   = ""
            product    = ""
            version    = ""
            tunnel     = ""
            if service_el is not None:
                svc_name = service_el.get("name", "")
                product  = service_el.get("product", "")
                version  = service_el.get("version", "")
                tunnel   = service_el.get("tunnel", "")  # 'ssl'

            # Determine if this is a web service
            is_web_port    = port_num in WEB_PORTS
            is_web_service = bool(WEB_SERVICE_NAMES.search(svc_name)) or \
                             bool(WEB_SERVICE_NAMES.search(product))

            if not (is_web_port or is_web_service):
                continue

            # Determine scheme
            if tunnel == "ssl" or "https" in svc_name or port_num in (443, 8443, 4443, 9443, 7443):
                scheme = "https"
            elif port_num in WEB_PORTS:
                scheme = WEB_PORTS[port_num]
            else:
                scheme = "http"

            # Build URL — prefer first hostname if available
            host_str = hostnames[0] if hostnames else ip
            if (scheme == "http" and port_num == 80) or (scheme == "https" and port_num == 443):
                url = f"{scheme}://{host_str}"
            else:
                url = f"{scheme}://{host_str}:{port_num}"

            targets.append({
                "url":      url,
                "ip":       ip,
                "port":     port_num,
                "scheme":   scheme,
                "hostname": hostnames[0] if hostnames else None,
                "service":  svc_name,
                "product":  product,
                "version":  version,
                "state":    "open",
            })

            log("ENUM",
                f"  Web target: {url} | {product} {version} [{svc_name}]".strip(),
                C.MAGENTA)

    log("ENUM", f"Parsed {len(targets)} web target(s) from {xml_path}", C.MAGENTA)
    return targets


# ---------------------------------------------------------------------------
# DNS / VHost bruteforcer
# ---------------------------------------------------------------------------
def vhost_bruteforce(base_url, wordlist_path, session_template, threads=20):
    """
    Bruteforce virtual hostnames by fuzzing the Host header.

    Detection strategy (layered):
      1. Establish a REAL baseline (valid host, no redirects — avoids redirect loops)
      2. Establish a WILDCARD baseline using a random nonexistent subdomain
      3. For each candidate:
         - If response matches wildcard fingerprint → discard (false positive)
         - If Location header reflects the candidate hostname → confirmed vhost
         - If status/size genuinely differs from wildcard → flag as candidate
    """
    import random, string

    parsed    = urlparse(base_url)
    base_host = parsed.hostname
    scheme    = parsed.scheme
    port      = parsed.port

    target_base = f"{scheme}://{base_host}"
    if port:
        target_base = f"{scheme}://{base_host}:{port}"

    log("DNS", f"Starting vhost bruteforce against {base_host}", C.BLUE)

    def _get(fqdn, allow_redirects=False):
        headers = {
            "Host":       fqdn,
            "User-Agent": session_template.headers.get("User-Agent", ""),
        }
        return session_template.get(
            target_base, headers=headers,
            timeout=8, allow_redirects=allow_redirects
        )

    # ------------------------------------------------------------------
    # 1. Real baseline — no redirects to avoid infinite redirect traps
    # ------------------------------------------------------------------
    try:
        b = _get(base_host, allow_redirects=False)
        baseline_status   = b.status_code
        baseline_size     = len(b.text)
        baseline_location = b.headers.get("Location", "")
        log("DNS", f"Real baseline   : [{baseline_status}] size={baseline_size} "
                   f"location={baseline_location or 'none'}", C.GREY)
    except Exception as e:
        log("ERR", f"Real baseline request failed: {e}")
        return []

    # ------------------------------------------------------------------
    # 2. Wildcard baseline — random nonexistent subdomain
    # ------------------------------------------------------------------
    rand_sub  = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    rand_fqdn = f"{rand_sub}.{base_host}"
    try:
        w = _get(rand_fqdn)
        wildcard_status   = w.status_code
        wildcard_size     = len(w.text)
        wildcard_location = w.headers.get("Location", "")
        log("DNS", f"Wildcard baseline: [{wildcard_status}] size={wildcard_size} "
                   f"location={wildcard_location or 'none'}", C.GREY)
    except Exception as e:
        log("WARN", f"Wildcard baseline failed — assuming no wildcard DNS: {e}", C.GREY)
        wildcard_status   = None
        wildcard_size     = None
        wildcard_location = None

    # ------------------------------------------------------------------
    # Load wordlist
    # ------------------------------------------------------------------
    try:
        with open(wordlist_path, "r", errors="ignore") as f:
            words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        log("ERR", f"Wordlist not found: {wordlist_path}")
        return []

    log("DNS", f"Loaded {len(words)} words — scanning all entries", C.GREY)

    # ------------------------------------------------------------------
    # 3. Probe each candidate
    # ------------------------------------------------------------------
    found_vhosts  = []
    lock          = threading.Lock()
    probe_count   = 0
    wildcard_hits = 0
    pc_lock       = threading.Lock()

    def is_wildcard_match(r, fqdn):
        """Return True if this response looks like the wildcard fallback."""
        if wildcard_status is None:
            return False
        loc  = r.headers.get("Location", "")
        size = len(r.text)

        # Location points to same generic destination and doesn't echo candidate
        if (r.status_code == wildcard_status and
                loc == wildcard_location and
                fqdn not in loc):
            return True

        # Status + size within tight tolerance of wildcard
        if (r.status_code == wildcard_status and
                wildcard_size is not None and
                abs(size - wildcard_size) < 20):
            return True

        return False

    def location_reflects_host(r, fqdn):
        """
        True if Location contains the candidate hostname —
        indicates a real vhost-specific redirect vs generic fallback.
        """
        loc = r.headers.get("Location", "")
        return bool(loc) and fqdn in loc

    def check_vhost(word):
        nonlocal probe_count, wildcard_hits

        fqdn = f"{word}.{base_host}"
        try:
            r    = _get(fqdn)
            size = len(r.text)
            loc  = r.headers.get("Location", "")

            with pc_lock:
                probe_count += 1
                if is_wildcard_match(r, fqdn):
                    wildcard_hits += 1
                    return  # filtered — matches wildcard fingerprint

            # --- Positive identification ---
            confirmed = False
            reason    = ""

            if location_reflects_host(r, fqdn):
                # Strongest signal — Location echoes candidate hostname
                confirmed = True
                reason    = f"Location reflects host → {loc}"

            elif wildcard_status is not None:
                size_diff = abs(size - (wildcard_size or 0))
                if r.status_code != wildcard_status:
                    confirmed = True
                    reason    = f"Status differs from wildcard ({wildcard_status}→{r.status_code})"
                elif size_diff > 200 and loc != wildcard_location:
                    confirmed = True
                    reason    = f"Size diff={size_diff} + location changed"
            else:
                # No wildcard baseline — compare against real baseline
                size_diff = abs(size - baseline_size)
                if r.status_code != baseline_status or size_diff > 200:
                    confirmed = True
                    reason    = f"Differs from real baseline (status={r.status_code} size_diff={size_diff})"

            if confirmed:
                result = {
                    "vhost":    fqdn,
                    "status":   r.status_code,
                    "size":     size,
                    "location": loc,
                    "reason":   reason,
                }
                with lock:
                    found_vhosts.append(result)
                log("DNS", f"  FOUND {fqdn} [{r.status_code}] size={size} | {reason}", C.GREEN)

        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(check_vhost, words))

    log("DNS",
        f"vhost bruteforce complete. {len(found_vhosts)} confirmed vhost(s) found "
        f"({probe_count} probed, {wildcard_hits} wildcard matches filtered).",
        C.BLUE)
    return found_vhosts


# ---------------------------------------------------------------------------
# Core crawler
# ---------------------------------------------------------------------------
def crawl(target, session, delay_ms, max_depth, threads):
    parsed_root = urlparse(target)
    allowed_host = parsed_root.netloc
def extract_hostname_from_error(exc_str):
    """Pull hostnames out of connection error messages like NameResolutionError."""
    # Matches: Failed to resolve 'intra.redcross.htb'
    m = re.search(r"[Ff]ailed to resolve ['\"]([a-zA-Z0-9\-\.]+)['\"]", exc_str)
    if m:
        return m.group(1)
    # Matches: host='intra.redcross.htb'
    m = re.search(r"host=['\"]([a-zA-Z0-9\-\.]+)['\"]", exc_str)
    if m:
        return m.group(1)
    return None


def crawl(target, session, delay_ms, max_depth, threads):
    parsed_root  = urlparse(target)
    allowed_host = parsed_root.netloc
    base_url     = f"{parsed_root.scheme}://{parsed_root.netloc}"

    visited          = {}
    seen             = {normalize_url(target)}
    queue            = [(normalize_url(target), 0)]
    q_lock           = threading.Lock()
    v_lock           = threading.Lock()
    discovered_hosts = set()   # hostnames found via redirects or errors
    dh_lock          = threading.Lock()

    # Extract the bare hostname (no port) for scope comparisons
    target_hostname = parsed_root.hostname or ""

    def _in_scope(hostname):
        """
        True only if hostname is the target itself or a subdomain of it.
        Blocks CDNs, external libraries, and anything not under the target domain.

        Examples (target = codify.htb):
            codify.htb          → True
            intra.codify.htb    → True
            cdnjs.cloudflare.com → False
            github.com          → False

        Examples (target = codify, bare hostname):
            codify              → True
            anything else       → False
        """
        if not hostname:
            return False
        h = hostname.lower().rstrip(".")
        b = target_hostname.lower().rstrip(".")
        return h == b or h.endswith(f".{b}")

    def _register_host(hostname):
        """
        Record a newly discovered hostname — only if it's in scope (subdomain of target).
        External hostnames (CDNs, GitHub, jQuery, etc.) are silently discarded here.
        """
        if not hostname or hostname == allowed_host:
            return
        if not _in_scope(hostname):
            return  # out of scope — external CDN/domain, do not register
        with dh_lock:
            if hostname not in discovered_hosts:
                discovered_hosts.add(hostname)
                log("DISCOVER", f"  ★ New hostname: {hostname}", C.MAGENTA)

    # Pre-crawl enum — suppress errors quietly
    log("ENUM", "Checking robots.txt, sitemap.xml, and high-value targets...", C.MAGENTA)
    robot_urls   = scrape_robots(session, base_url)
    sitemap_urls = scrape_sitemap(session, base_url)
    hvt_urls = scrape_hvts(session, base_url)

    with q_lock:
        for u in robot_urls + sitemap_urls + hvt_urls:
            nu = normalize_url(u)
            if nu not in seen and same_host(nu, allowed_host):
                seen.add(nu)
                queue.append((nu, 1))

    def process_url(url, depth):
        try:
            resp = session.get(url, timeout=15, allow_redirects=True)
        except requests.RequestException as exc:
            exc_str = str(exc)
            # Quietly record the error — extract any hostname leak
            leaked = extract_hostname_from_error(exc_str)
            if leaked:
                _register_host(leaked)
            with v_lock:
                visited[url] = {"status": None, "depth": depth, "error": exc_str}
            # Only log at DEBUG level — not ERR — to avoid noise
            log("WARN", f"Unreachable: {url} (host may need /etc/hosts entry)", C.GREY)
            return []

        # Harvest hostnames from every hop in the redirect chain
        for r in resp.history:
            loc = r.headers.get("Location", "")
            if loc:
                redir_host = urlparse(urljoin(url, loc)).hostname
                if redir_host:
                    _register_host(redir_host)
        # Also check final URL in case of silent redirect
        final_host = urlparse(resp.url).hostname
        if final_host:
            _register_host(final_host)

        status  = resp.status_code
        ct      = resp.headers.get("Content-Type", "")
        is_html = "text/html" in ct or "text/plain" in ct
        is_js   = "javascript" in ct or url.lower().endswith((".js", ".mjs"))
        html    = resp.text if (is_html or is_js) else ""

        # --- Passive asset extraction ---
        assets           = {}
        crawl_next_links = set()
        if is_html:
            crawl_next_links, assets = extract_assets(url, html, allowed_host)
            # Harvest hostnames from all external asset refs too
            for ref_list in assets.values():
                for ref in ref_list:
                    h = urlparse(ref).hostname
                    if h and h != allowed_host:
                        _register_host(h)

        # --- Fingerprint ---
        emails      = extract_emails(html) if html else []
        comments    = extract_comments(html) if is_html else []
        forms       = extract_forms(html, url) if is_html else []
        cms         = detect_cms(html, resp.headers) if is_html else []
        is_highval  = check_high_value(url)
        lfi_surface = check_lfi_surface(url)
        cmd_surface = check_cmd_surface(url)
        xss_surface = check_xss_surface(html, url) if is_html else False
        server_hdr  = resp.headers.get("Server", "")
        powered_by  = resp.headers.get("X-Powered-By", "")
        versions    = VERSION_RE.findall(html + server_hdr + powered_by)

        if is_js and html:
            emails = sorted(set(emails + extract_emails(html)))

        page_result = {
            "status":       status,
            "depth":        depth,
            "content_type": ct,
            "emails":       emails,
            "comments":     comments[:10],
            "forms":        forms,
            "cms":          cms,
            "high_value":   is_highval,
            "lfi_surface":  lfi_surface,
            "cmd_surface":  cmd_surface,
            "xss_surface":  xss_surface,
            "server":       server_hdr,
            "x_powered_by": powered_by,
            "versions":     list(set(versions)),
            "assets": {
                "js":       sorted(assets.get("js",        [])),
                "css":      sorted(assets.get("css",       [])),
                "images":   sorted(assets.get("image",     [])),
                "fonts":    sorted(assets.get("font",      [])),
                "files":    sorted(assets.get("file",      [])),
                "media":    sorted(assets.get("media",     [])),
                "pages":    sorted(assets.get("page",      [])),
                "dirs":     sorted(assets.get("directory", [])),
                "other":    sorted(assets.get("other",     [])),
                "external": sorted([
                    r for typ in assets.values()
                    for r in typ
                    if not same_host(r, allowed_host)
                ]),
            },
        }

        with v_lock:
            visited[url] = page_result

        # --- Stdout ---
        status_color = C.GREEN if status == 200 else (C.YELLOW if status in (301, 302, 403) else C.RED)
        log("INFO", f"[{status_color}{status}{C.RESET}] {url}")

        if is_highval:
            log("HIGH",    f"  ★ HIGH-VALUE PATH: {url}", C.RED)
        if lfi_surface:
            log("HIGH",    f"  ⚑ Possible LFI surface: {url}", C.RED)
        if cmd_surface:
            log("MED",     f"  ⚑ Possible CMD injection surface: {url}", C.ORANGE)
        if xss_surface:
            log("MED",     f"  ⚑ Possible XSS surface (form/feedback): {url}", C.ORANGE)
        if emails:
            log("FIND",    f"  ✉ Emails: {emails}", C.GREEN)
        if cms:
            log("FIND",    f"  ◈ CMS detected: {cms}", C.CYAN)
        if comments:
            log("LOW",     f"  <!-- {len(comments)} HTML comment(s) found -->", C.YELLOW)
        if versions:
            log("LOW",     f"  ⓥ Version strings: {list(set(versions))}", C.YELLOW)
        if server_hdr or powered_by:
            log("LOW",     f"  ⓢ Server: {server_hdr} | X-Powered-By: {powered_by}", C.GREY)

        asset_counts = {k: len(v) for k, v in page_result["assets"].items() if v}
        if asset_counts:
            parts = [f"{v} {k}" for k, v in asset_counts.items()]
            log("INFO", f"  ⊕ Assets: {', '.join(parts)}", C.GREY)

        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

        new_links = []
        if depth < max_depth:
            for link in crawl_next_links:
                with q_lock:
                    if link not in seen:
                        seen.add(link)
                        new_links.append((link, depth + 1))
        return new_links

    # BFS via thread pool
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(process_url, url, depth): (url, depth)
                   for url, depth in queue}
        queue.clear()

        while futures:
            done = []
            for future in list(as_completed(futures)):
                new_links = future.result()
                done.append(future)
                for link, d in new_links:
                    f = executor.submit(process_url, link, d)
                    futures[f] = (link, d)
            for f in done:
                del futures[f]

    return visited, list(discovered_hosts)

# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------
def build_report(results, target, vhosts=None, discovered_hosts=None):
    pages_with_emails  = {u: d["emails"] for u, d in results.items() if d.get("emails")}
    high_value_pages   = [u for u, d in results.items() if d.get("high_value")]
    lfi_pages          = [u for u, d in results.items() if d.get("lfi_surface")]
    cmd_pages          = [u for u, d in results.items() if d.get("cmd_surface")]
    xss_pages          = [u for u, d in results.items() if d.get("xss_surface")]
    cms_detected       = list({c for d in results.values() for c in d.get("cms", [])})
    all_emails         = sorted({e for v in pages_with_emails.values() for e in v})
    all_comments       = {u: d["comments"] for u, d in results.items() if d.get("comments")}
    all_versions       = list({v for d in results.values() for v in d.get("versions", [])})

    asset_inventory = defaultdict(set)
    for d in results.values():
        for atype, urls in d.get("assets", {}).items():
            asset_inventory[atype].update(urls)
    asset_summary = {k: sorted(v) for k, v in asset_inventory.items() if v}

    return {
        "meta": {
            "target":              target,
            "generated":           datetime.now().isoformat(),
            "total_pages_crawled": len(results),
        },
        "summary": {
            "cms_detected":        cms_detected,
            "high_value_pages":    high_value_pages,
            "lfi_surfaces":        lfi_pages,
            "cmd_surfaces":        cmd_pages,
            "xss_surfaces":        xss_pages,
            "pages_with_emails":   len(pages_with_emails),
            "unique_emails":       all_emails,
            "pages_with_comments": len(all_comments),
            "version_strings":     all_versions,
            "vhosts_found":        vhosts or [],
            "discovered_hosts":    sorted(discovered_hosts or []),
            "asset_counts":        {k: len(v) for k, v in asset_summary.items()},
        },
        "findings": {
            "emails_by_page":   pages_with_emails,
            "comments_by_page": all_comments,
        },
        "asset_inventory": asset_summary,
        "pages":            results,
    }

def print_summary(report):
    s = report["summary"]
    m = report["meta"]
    a = report.get("asset_inventory", {})

    print(f"\n{C.BOLD}{C.CYAN}{'='*65}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  SCAN SUMMARY — {m['target']}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'='*65}{C.RESET}")
    print(f"  {C.GREY}Pages crawled   :{C.RESET} {m['total_pages_crawled']}")
    print(f"  {C.GREY}CMS detected    :{C.RESET} {C.CYAN}{s['cms_detected'] or 'None'}{C.RESET}")
    print(f"  {C.RED}High-value pages:{C.RESET} {len(s['high_value_pages'])}")
    print(f"  {C.RED}LFI surfaces    :{C.RESET} {len(s['lfi_surfaces'])}")
    print(f"  {C.ORANGE}CMD surfaces    :{C.RESET} {len(s['cmd_surfaces'])}")
    print(f"  {C.ORANGE}XSS surfaces    :{C.RESET} {len(s['xss_surfaces'])}")
    print(f"  {C.GREEN}Emails found    :{C.RESET} {len(s['unique_emails'])}")
    print(f"  {C.YELLOW}Pages w/comments:{C.RESET} {s['pages_with_comments']}")
    print(f"  {C.YELLOW}Version strings :{C.RESET} {s['version_strings'] or 'None'}")

    # Asset inventory block
    if s.get("asset_counts"):
        print(f"\n{C.BOLD}{C.CYAN}  ASSET INVENTORY{C.RESET}")
        print(f"  {C.CYAN}{'-'*40}{C.RESET}")
        type_colors = {
            "js":        C.YELLOW,
            "css":       C.BLUE,
            "pages":     C.WHITE,
            "dirs":      C.CYAN,
            "files":     C.ORANGE,
            "images":    C.GREY,
            "fonts":     C.GREY,
            "media":     C.GREY,
            "external":  C.MAGENTA,
            "other":     C.GREY,
        }
        for atype, count in sorted(s["asset_counts"].items()):
            color = type_colors.get(atype, C.WHITE)
            label = atype.upper().ljust(10)
            bar   = "█" * min(count, 40)
            print(f"  {color}{label}{C.RESET} {count:>4}  {color}{bar}{C.RESET}")

        # Highlight interesting file types found
        interesting_files = [
            f for f in a.get("files", [])
            if any(f.lower().endswith(ext) for ext in (
                ".bak", ".sql", ".env", ".log", ".xml",
                ".json", ".yaml", ".yml", ".config",
                ".zip", ".tar", ".gz", ".7z", ".rar"
            ))
        ]
        if interesting_files:
            print(f"\n  {C.RED}{C.BOLD}⚑ INTERESTING FILES:{C.RESET}")
            for f in interesting_files:
                print(f"    {C.RED}→ {f}{C.RESET}")

        # JS files — useful surface for your XSS work
        if a.get("js"):
            print(f"\n  {C.YELLOW}{C.BOLD}JS FILES ({len(a['js'])}):{C.RESET}")
            for f in a["js"]:
                print(f"    {C.YELLOW}→ {f}{C.RESET}")

        # External references
        if a.get("external"):
            print(f"\n  {C.MAGENTA}{C.BOLD}EXTERNAL REFS ({len(a['external'])}):{C.RESET}")
            for f in sorted(set(a["external"])):
                print(f"    {C.MAGENTA}→ {f}{C.RESET}")

    if s["high_value_pages"]:
        print(f"\n  {C.RED}{C.BOLD}★ HIGH-VALUE TARGETS:{C.RESET}")
        for u in s["high_value_pages"]:
            print(f"    {C.RED}→ {u}{C.RESET}")

    if s["lfi_surfaces"]:
        print(f"\n  {C.RED}{C.BOLD}⚑ LFI SURFACES:{C.RESET}")
        for u in s["lfi_surfaces"]:
            print(f"    {C.RED}→ {u}{C.RESET}")

    if s["cmd_surfaces"]:
        print(f"\n  {C.ORANGE}{C.BOLD}⚑ CMD INJECTION SURFACES:{C.RESET}")
        for u in s["cmd_surfaces"]:
            print(f"    {C.ORANGE}→ {u}{C.RESET}")

    if s["xss_surfaces"]:
        print(f"\n  {C.ORANGE}{C.BOLD}⚑ XSS SURFACES:{C.RESET}")
        for u in s["xss_surfaces"]:
            print(f"    {C.ORANGE}→ {u}{C.RESET}")

    if s["unique_emails"]:
        print(f"\n  {C.GREEN}{C.BOLD}✉ EMAILS:{C.RESET}")
        for e in s["unique_emails"]:
            print(f"    {C.GREEN}- {e}{C.RESET}")

    if s.get("discovered_hosts"):
        ip_hint = urlparse(m["target"]).hostname
        print(f"\n  {C.MAGENTA}{C.BOLD}★ DISCOVERED HOSTNAMES ({len(s['discovered_hosts'])}):{C.RESET}")
        print(f"  {C.GREY}  These were found via redirects or error messages during crawl.{C.RESET}")
        print(f"  {C.GREY}  Add to /etc/hosts and re-run to enumerate them:{C.RESET}")
        print()
        for h in s["discovered_hosts"]:
            print(f"    {C.MAGENTA}→ {h}{C.RESET}")
        print()
        print(f"  {C.GREY}  Suggested /etc/hosts entry:{C.RESET}")
        hosts_line = f"{ip_hint}    " + "    ".join(s["discovered_hosts"])
        print(f"  {C.CYAN}  {hosts_line}{C.RESET}")

    if s.get("vhosts_found"):
        print(f"\n  {C.BLUE}{C.BOLD}◈ VHOSTS FOUND:{C.RESET}")
        for v in s["vhosts_found"]:
            print(f"    {C.BLUE}→ {v['vhost']} [{v['status']}] size={v['size']}{C.RESET}")

    print(f"\n{C.BOLD}{C.CYAN}{'='*65}{C.RESET}\n")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="webspy - Fast Web Enum & Crawler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  Single target:  python webspy.py --target http://10.10.10.10\n"
            "  nmap ingest:    python webspy.py --nmap scan.xml --depth 3 --output report.json\n"
            "  With proxy:     python webspy.py --target http://target.htb --proxy http://127.0.0.1:8080 --no-verify-ssl\n"
            "  vhost fuzz:     python webspy.py --target http://10.10.10.10 --dnsbrutehosts /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt\n"
        )
    )
    # --target and --nmap are mutually exclusive; one is required
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--target",
                     metavar="URL",
                     help="Single target URL e.g. http://target.htb")
    tgt.add_argument("--nmap",
                     metavar="NMAP_XML",
                     help="nmap XML scan file — auto-extracts all open web services "
                          "and crawls them in sequence. (e.g. scan.xml)")

    p.add_argument("--proxy",           default=None,   help="Upstream proxy e.g. http://127.0.0.1:8080")
    p.add_argument("--delay",           type=int, default=0,  help="Delay between requests in ms (default: 0)")
    p.add_argument("--depth",           type=int, default=5,  help="Max crawl depth per target (default: 5)")
    p.add_argument("--threads",         type=int, default=10, help="Crawler thread count (default: 10)")
    p.add_argument("--output",          default="report.json", help="JSON output file (default: report.json)")
    p.add_argument("--no-verify-ssl",   action="store_true",   help="Disable SSL verification")
    p.add_argument("--user-agent",      default=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ), help="User-Agent string")
    p.add_argument("--cookies",         default=None,
                   help="Session cookies as comma-separated key=value pairs")
    p.add_argument("--ping",            action="store_true",
                   help="TCP port scan target host before crawling")
    # DNS vhost bruteforce — non-default, opt-in
    p.add_argument("--dnsbrutehosts",   default=None,
                   metavar="WORDLIST",
                   help="(Optional) Wordlist for vhost bruteforcing via Host header fuzzing. "
                        "e.g. /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    p.add_argument("--dns-threads",     type=int, default=20,
                   help="Thread count for vhost bruteforce (default: 20)")
    return p.parse_args()


def run_single(target, args, session, all_reports):
    """Crawl a single target and append its report to all_reports."""
    parsed = urlparse(target)
    host   = parsed.hostname

    log("INFO", f"{'='*55}", C.CYAN)
    log("INFO", f"Target: {target}", C.WHITE)
    log("INFO", f"Depth : {args.depth} | Threads: {args.threads} | Delay: {args.delay}ms", C.GREY)

    if args.ping:
        log("INFO", f"TCP ping: {host}", C.CYAN)
        open_ports = ping_host(host)
        if open_ports:
            log("FIND", f"Open ports on {host}: {open_ports}", C.GREEN)
        else:
            log("WARN", f"No common ports responded on {host}")

    log("INFO", "Starting crawl...", C.CYAN)
    results, discovered_hosts = crawl(
        target    = target,
        session   = session,
        delay_ms  = args.delay,
        max_depth = args.depth,
        threads   = args.threads
    )

    vhosts = []
    if args.dnsbrutehosts:
        log("DNS", f"vhost bruteforce: {args.dnsbrutehosts}", C.BLUE)
        vhosts = vhost_bruteforce(
            base_url         = target,
            wordlist_path    = args.dnsbrutehosts,
            session_template = session,
            threads          = args.dns_threads
        )

    report = build_report(results, target, vhosts, discovered_hosts)
    print_summary(report)
    all_reports[target] = report


def main():
    banner()
    args = parse_args()

    cookies = {}
    if args.cookies:
        for pair in args.cookies.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    session = build_session(
        proxy_url  = args.proxy,
        verify_ssl = not args.no_verify_ssl,
        user_agent = args.user_agent,
        cookies    = cookies
    )

    if args.proxy:
        log("INFO", f"Proxy    : {args.proxy}", C.GREY)

    all_reports    = {}
    all_discovered = set()

    # ----------------------------------------------------------------
    # Mode A: single --target
    # ----------------------------------------------------------------
    if args.target:
        run_single(args.target, args, session, all_reports)

    # ----------------------------------------------------------------
    # Mode B: --nmap XML ingest — dynamic queue with auto-pivot
    # ----------------------------------------------------------------
    else:
        log("ENUM", f"Parsing nmap XML: {args.nmap}", C.MAGENTA)
        nmap_targets = parse_nmap_xml(args.nmap)

        if not nmap_targets:
            log("WARN", "No web targets found in nmap XML. Exiting.")
            sys.exit(1)

        # Auto-disable SSL verification for nmap mode
        if not args.no_verify_ssl:
            log("WARN", "nmap mode: auto-disabling SSL verification (self-signed certs expected)", C.YELLOW)
            import urllib3
            urllib3.disable_warnings()
            session.verify = False

        # Derive the schemes present in nmap results — used when pivoting
        # to discovered hosts (inherit whatever the nmap scan found open)
        nmap_schemes = list({t["scheme"] for t in nmap_targets})
        nmap_ports   = {t["scheme"]: t["port"] for t in nmap_targets}
        nmap_ip      = nmap_targets[0]["ip"] if nmap_targets else "TARGET_IP"

        # Dynamic scan queue — seeded from nmap, grows as hosts are discovered
        scan_queue   = [t["url"] for t in nmap_targets]
        queued_urls  = set(scan_queue)   # dedup guard
        pivot_hosts  = set()             # discovered hosts we've already pivoted to
        nmap_meta    = {t["url"]: t for t in nmap_targets}

        def resolve_host(hostname):
            """
            Return True only if hostname resolves AND its IP matches the nmap target.

            This is the second scope gate. Without the IP check, publicly resolvable
            hosts like cdnjs.cloudflare.com pass getaddrinfo() and get queued.
            The IP match ensures we only pivot to hostnames pointing at our actual target.
            """
            try:
                results      = socket.getaddrinfo(hostname, None)
                resolved_ips = {r[4][0] for r in results}
                return nmap_ip in resolved_ips
            except socket.gaierror:
                return False

        def build_pivot_urls(hostname, schemes, ports):
            """Generate http/https URLs for a discovered hostname matching nmap port profile."""
            urls = []
            for scheme in schemes:
                port = ports.get(scheme)
                if port and not ((scheme == "http" and port == 80) or
                                 (scheme == "https" and port == 443)):
                    urls.append(f"{scheme}://{hostname}:{port}")
                else:
                    urls.append(f"{scheme}://{hostname}")
            return urls

        total_scanned = 0
        while scan_queue:
            url = scan_queue.pop(0)
            total_scanned += 1
            log("INFO", f"[{total_scanned}] {url}", C.WHITE)
            run_single(url, args, session, all_reports)

            # Attach nmap metadata if this was an original nmap target
            if url in nmap_meta:
                t = nmap_meta[url]
                all_reports[url]["nmap_info"] = {
                    "ip":      t["ip"],
                    "port":    t["port"],
                    "service": t["service"],
                    "product": t["product"],
                    "version": t["version"],
                }

            # Harvest discovered hosts from this scan
            report    = all_reports.get(url, {})
            new_hosts = report.get("summary", {}).get("discovered_hosts", [])

            for hostname in new_hosts:
                all_discovered.add(hostname)

                # Skip if already pivoted to this host
                if hostname in pivot_hosts:
                    continue

                # Check if it resolves — already in /etc/hosts
                if resolve_host(hostname):
                    pivot_hosts.add(hostname)
                    pivot_urls = build_pivot_urls(hostname, nmap_schemes, nmap_ports)

                    for pivot_url in pivot_urls:
                        if pivot_url not in queued_urls:
                            queued_urls.add(pivot_url)
                            scan_queue.append(pivot_url)
                            log("DISCOVER",
                                f"  ↳ Auto-pivoting to {pivot_url} (resolved in /etc/hosts)",
                                C.MAGENTA)
                else:
                    # Doesn't resolve yet — flag it but don't block
                    log("WARN",
                        f"  ↳ {hostname} discovered but not resolvable — add to /etc/hosts to auto-pivot",
                        C.YELLOW)

        # Final advisory — only show hosts that still need /etc/hosts entries
        unresolved = all_discovered - pivot_hosts
        if unresolved:
            print(f"\n{C.BOLD}{C.MAGENTA}{'='*65}{C.RESET}")
            print(f"{C.BOLD}{C.WHITE}  ★ UNRESOLVED HOSTS — ADD TO /etc/hosts{C.RESET}")
            print(f"{C.BOLD}{C.MAGENTA}{'='*65}{C.RESET}")
            print(f"  {C.GREY}These were discovered but could not be auto-pivoted{C.RESET}")
            print(f"  {C.GREY}because they don't resolve. Add the entry below and re-run:{C.RESET}\n")
            for h in sorted(unresolved):
                print(f"    {C.MAGENTA}→ {h}{C.RESET}")
            print(f"\n  {C.CYAN}Suggested /etc/hosts entry:{C.RESET}")
            hosts_line = f"  {nmap_ip}    " + "    ".join(sorted(unresolved))
            print(f"  {C.BOLD}{C.WHITE}{hosts_line}{C.RESET}")
            print(f"{C.BOLD}{C.MAGENTA}{'='*65}{C.RESET}\n")
        elif all_discovered:
            # All discovered hosts were pivoted — clean confirmation
            log("INFO",
                f"All {len(all_discovered)} discovered host(s) were resolved and scanned automatically.",
                C.GREEN)

    # ----------------------------------------------------------------
    # Write combined JSON output
    # ----------------------------------------------------------------
    final_output = {
        "generated": datetime.now().isoformat(),
        "source":    args.nmap if args.nmap else args.target,
        "targets":   all_reports,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2)

    log("INFO", f"Report saved → {args.output}", C.CYAN)
    log("INFO", f"Total targets crawled: {len(all_reports)}", C.WHITE)


if __name__ == "__main__":
    main()
