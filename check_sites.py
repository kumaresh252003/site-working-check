#!/usr/bin/env python3
"""
Website uptime + page checker.
- Auto-discovers every page (sitemap.xml, falls back to crawling internal links)
- Checks each page: HTTP status, timeouts, blank/white pages, PHP/WordPress errors
- Sends an email via SMTP when something is wrong
"""
import os
import re
import smtplib
import ssl
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.mime.text import MIMEText
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup

# ----------------------------- settings ------------------------------------
TIMEOUT = 20                 # seconds per request
RETRIES = 1                  # extra attempts before a page is marked failed
MIN_VISIBLE_TEXT = 80        # fewer visible characters than this = "white screen"
MAX_PAGES_PER_SITE = 300     # safety limit for crawling
WORKERS = 16
USER_AGENT = "Mozilla/5.0 (compatible; SiteMonitorBot/1.0; +https://github.com)"

ERROR_SIGNATURES = [
    "there has been a critical error on this website",
    "error establishing a database connection",
    "fatal error:",
    "parse error:",
    "warning: require(",
    "internal server error",
    "service unavailable",
    "bad gateway",
    "account suspended",
    "this site can’t be reached",
    "briefly unavailable for scheduled maintenance",
]

SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".pdf",
            ".css", ".js", ".zip", ".mp4", ".mp3", ".xml", ".woff", ".woff2")

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})


# ----------------------------- helpers -------------------------------------
def fetch(url):
    """GET with retries. Returns (response|None, error|None, seconds)."""
    last_err = None
    for attempt in range(RETRIES + 1):
        start = time.time()
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            return r, None, time.time() - start
        except requests.RequestException as e:
            last_err = f"{type(e).__name__}: {str(e)[:150]}"
            time.sleep(2)
    return None, last_err, 0


def normalize(url):
    url, _ = urldefrag(url.strip())
    return url.rstrip("/") if urlparse(url).path in ("", "/") else url


def same_host(a, b):
    strip = lambda h: h.lower().replace("www.", "")
    return strip(urlparse(a).netloc) == strip(urlparse(b).netloc)


def parse_sitemap(url, seen=None, depth=0):
    """Return all page URLs from a sitemap (follows sitemap indexes)."""
    seen = seen or set()
    if url in seen or depth > 3:
        return []
    seen.add(url)
    r, err, _ = fetch(url)
    if r is None or r.status_code != 200:
        return []
    locs = re.findall(r"<loc>\s*(?:<!\[CDATA\[)?\s*(.*?)\s*(?:\]\]>)?\s*</loc>", r.text, re.S)
    urls = []
    for loc in locs:
        loc = loc.strip()
        if loc.lower().endswith(".xml") or "sitemap" in urlparse(loc).path.lower() and loc.endswith(".xml"):
            urls += parse_sitemap(loc, seen, depth + 1)
        else:
            urls.append(loc)
    return urls


def discover_from_sitemap(base):
    candidates = [urljoin(base, p) for p in
                  ("/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml", "/sitemap-index.xml")]
    r, _, _ = fetch(urljoin(base, "/robots.txt"))
    if r is not None and r.status_code == 200:
        candidates = re.findall(r"(?im)^sitemap:\s*(\S+)", r.text) + candidates
    found, seen = [], set()
    for c in candidates:
        found += parse_sitemap(c, seen)
        if found:
            break
    return found


def crawl(base):
    """Fallback: follow internal links starting at the homepage."""
    queue, seen = deque([normalize(base)]), {normalize(base)}
    while queue and len(seen) < MAX_PAGES_PER_SITE:
        url = queue.popleft()
        r, _, _ = fetch(url)
        if r is None or "text/html" not in r.headers.get("Content-Type", ""):
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = normalize(urljoin(r.url, a["href"]))
            if (link.startswith("http") and same_host(link, base)
                    and not link.lower().endswith(SKIP_EXT) and link not in seen):
                seen.add(link)
                queue.append(link)
    return list(seen)


def discover_pages(site):
    pages = discover_from_sitemap(site)
    source = "sitemap"
    if not pages:
        pages, source = crawl(site), "crawl"
    pages = [normalize(p) for p in pages if same_host(p, site)
             and not p.lower().endswith(SKIP_EXT)]
    pages.append(normalize(site))               # always include homepage
    pages = sorted(set(pages))[:MAX_PAGES_PER_SITE]
    return pages, source


def load_manual_pages():
    """If pages.txt has URLs for a site, discovery is skipped (much faster)."""
    path = os.path.join(os.path.dirname(__file__), "pages.txt")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


# ----------------------------- page check ----------------------------------
def check_page(url):
    r, err, secs = fetch(url)
    if r is None:
        return {"url": url, "ok": False, "problem": f"No response ({err})"}
    if r.status_code >= 400:
        return {"url": url, "ok": False, "problem": f"HTTP {r.status_code}"}

    ctype = r.headers.get("Content-Type", "")
    if "text/html" not in ctype:
        return {"url": url, "ok": True, "problem": ""}

    html = r.text
    if len(html.strip()) < 300:
        return {"url": url, "ok": False,
                "problem": f"WHITE SCREEN - page body is almost empty ({len(html.strip())} bytes)"}

    low = html.lower()
    for sig in ERROR_SIGNATURES:
        if sig in low:
            return {"url": url, "ok": False, "problem": f"Error text on page: '{sig}'"}

    soup = BeautifulSoup(html, "html.parser")
    for t in soup(["script", "style", "noscript", "template"]):
        t.decompose()
    text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
    if len(text) < MIN_VISIBLE_TEXT:
        return {"url": url, "ok": False,
                "problem": f"WHITE SCREEN - only {len(text)} characters of visible text"}

    if secs > 15:
        return {"url": url, "ok": False, "problem": f"Very slow ({secs:.1f}s)"}
    return {"url": url, "ok": True, "problem": ""}


# ----------------------------- email ---------------------------------------
def send_email(subject, body):
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "465"))
    user, pwd = os.environ["SMTP_USER"], os.environ["SMTP_PASS"]
    to = [x.strip() for x in os.environ["MAIL_TO"].split(",") if x.strip()]

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"], msg["From"], msg["To"] = subject, user, ", ".join(to)
    with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context()) as s:
        s.login(user, pwd)
        s.sendmail(user, to, msg.as_string())


# ----------------------------- main ----------------------------------------
def main():
    sites_file = os.path.join(os.path.dirname(__file__), "sites.txt")
    with open(sites_file) as f:
        sites = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if "--discover" in sys.argv:
        # One-time helper: builds pages.txt so later runs skip slow discovery
        with open(os.path.join(os.path.dirname(__file__), "pages.txt"), "w") as out:
            for site in sites:
                pages, source = discover_pages(site)
                print(f"{site}: {len(pages)} pages via {source}")
                out.write(f"# {site}\n" + "\n".join(pages) + "\n\n")
        print("pages.txt written. Commit it to your repo.")
        return

    manual = load_manual_pages()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report, failures, total = [], 0, 0

    for site in sites:
        mine = [normalize(u) for u in manual if same_host(u, site)]
        if mine:
            pages, source = sorted(set(mine + [normalize(site)])), "pages.txt"
        else:
            pages, source = discover_pages(site)
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            results = list(ex.map(check_page, pages))
        bad = [r for r in results if not r["ok"]]
        total += len(results)
        failures += len(bad)
        status = "DOWN/ISSUES" if bad else "OK"
        print(f"[{status}] {site}: {len(results)} pages ({source}), {len(bad)} problems")
        report.append(f"{site}\n  Pages checked: {len(results)} (found via {source})  |  Problems: {len(bad)}")
        for r in bad:
            print(f"    - {r['url']} -> {r['problem']}")
            report.append(f"    X {r['url']}\n      {r['problem']}")
        report.append("")

    body = f"Website check at {now}\nTotal pages checked: {total}\nTotal problems: {failures}\n\n" + "\n".join(report)

    send_ok = os.getenv("SEND_OK_EMAIL", "false").lower() == "true"
    if failures:
        send_email(f"ALERT: {failures} website problem(s) found", body)
        print("Alert email sent.")
        sys.exit(1)          # marks the GitHub Actions run as failed too
    elif send_ok:
        send_email("All websites are working", body)
        print("OK email sent.")
    else:
        print("All good. No email sent.")


if __name__ == "__main__":
    main()
