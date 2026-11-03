#!/usr/bin/env python3
"""
Checks every URL listed in pages.txt (no crawling, no discovery).
Detects: HTTP errors, timeouts, white/blank pages, PHP/WordPress error pages.
Emails a report. Fast: pages are checked in parallel.
"""
import os
import re
import smtplib
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.mime.text import MIMEText
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup

# ----------------------------- settings ------------------------------------
TIMEOUT = 20               # seconds per request
RETRIES = 1                # extra attempt before marking a page failed
MIN_VISIBLE_TEXT = 80      # fewer visible characters than this = "white screen"
WORKERS = 30               # pages checked in parallel (lower it if your hosting struggles)
SLOW_SECONDS = 15
MAX_LISTED_PER_SITE = 100  # keeps the email readable if a lot of pages fail

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
    "briefly unavailable for scheduled maintenance",
]

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; SiteMonitorBot/1.0)"})
adapter = HTTPAdapter(pool_connections=WORKERS, pool_maxsize=WORKERS * 2)
session.mount("http://", adapter)
session.mount("https://", adapter)


def fetch(url, retries=RETRIES):
    last_err = None
    for _ in range(retries + 1):
        start = time.time()
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            return r, None, time.time() - start
        except requests.RequestException as e:
            last_err = f"{type(e).__name__}: {str(e)[:120]}"
            time.sleep(1)
    return None, last_err, 0


def check_page(url):
    r, err, secs = fetch(url)
    if r is None:
        return {"url": url, "ok": False, "problem": f"No response ({err})"}
    if r.status_code >= 400:
        return {"url": url, "ok": False, "problem": f"HTTP {r.status_code}"}
    if "text/html" not in r.headers.get("Content-Type", ""):
        return {"url": url, "ok": True, "problem": ""}

    html = r.text
    if len(html.strip()) < 300:
        return {"url": url, "ok": False,
                "problem": f"WHITE SCREEN - body almost empty ({len(html.strip())} bytes)"}

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
    if secs > SLOW_SECONDS:
        return {"url": url, "ok": False, "problem": f"Very slow ({secs:.1f}s)"}
    return {"url": url, "ok": True, "problem": ""}


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


def load_pages():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages.txt")
    with open(path, encoding="utf-8") as f:
        urls = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    seen, out = set(), []
    for u in urls:
        if u.startswith("http") and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def main():
    urls = load_pages()
    sites = {}
    for u in urls:
        p = urlparse(u)
        sites.setdefault(f"{p.scheme}://{p.netloc}", []).append(u)

    started = time.time()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # 1) Quick check: is each website reachable at all? (avoids waiting on thousands of timeouts)
    down = {}
    def probe(site):
        r, err, _ = fetch(site + "/", retries=2)
        return site, (err if r is None else None)
    with ThreadPoolExecutor(max_workers=len(sites) or 1) as ex:
        for site, err in ex.map(probe, sites):
            if err:
                down[site] = err

    # 2) Check all pages of the reachable sites in one big parallel pool
    todo = [u for site, pages in sites.items() if site not in down for u in pages]
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        results = list(ex.map(check_page, todo))
    by_url = {r["url"]: r for r in results}

    # 3) Build report
    report, problems = [], 0
    for site, pages in sites.items():
        if site in down:
            problems += 1
            print(f"[SITE DOWN] {site}: {down[site]}")
            report.append(f"{site}\n  SITE DOWN - cannot be reached ({down[site]})\n  {len(pages)} pages not checked\n")
            continue
        bad = [by_url[u] for u in pages if not by_url[u]["ok"]]
        problems += len(bad)
        print(f"[{'ISSUES' if bad else 'OK'}] {site}: {len(pages)} pages, {len(bad)} problems")
        report.append(f"{site}\n  Pages checked: {len(pages)}  |  Problems: {len(bad)}")
        for r in bad[:MAX_LISTED_PER_SITE]:
            print(f"    - {r['url']} -> {r['problem']}")
            report.append(f"    X {r['url']}\n      {r['problem']}")
        if len(bad) > MAX_LISTED_PER_SITE:
            report.append(f"    ... and {len(bad) - MAX_LISTED_PER_SITE} more (see GitHub Actions log)")
        report.append("")

    took = int(time.time() - started)
    body = (f"Website check at {now} (took {took}s)\n"
            f"Total pages: {len(urls)}\nTotal problems: {problems}\n\n" + "\n".join(report))

    if problems:
        send_email(f"ALERT: {problems} website problem(s) found", body)
        print("Alert email sent.")
        sys.exit(1)
    elif os.getenv("SEND_OK_EMAIL", "false").lower() == "true":
        send_email("All websites are working", body)
        print("OK email sent.")
    else:
        print("All good. No email sent.")


if __name__ == "__main__":
    main()
