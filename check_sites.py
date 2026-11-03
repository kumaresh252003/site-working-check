#!/usr/bin/env python3
"""
Checks every URL listed in pages.txt (no crawling, no discovery).
Detects: HTTP errors, timeouts, white/blank pages, PHP/WordPress error pages.
Emails a report. Fast: pages are checked in parallel.
"""
import os
import json
import re
import smtplib
import threading
from itertools import zip_longest
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
RETRIES = 2                # extra attempts before marking a page failed
MIN_VISIBLE_TEXT = 80      # fewer visible characters than this = "white screen"
WORKERS = 30               # total pages checked in parallel
PER_SITE = int(os.getenv("PER_SITE", "4"))               # max simultaneous requests to ONE website (prevents 503 overload/rate-limit)
RETRY_STATUS = (429, 502, 503, 504)
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
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-AU,en;q=0.9",
})
site_locks = {}
adapter = HTTPAdapter(pool_connections=WORKERS, pool_maxsize=WORKERS * 2)
session.mount("http://", adapter)
session.mount("https://", adapter)


def fetch(url, retries=RETRIES):
    last_err, r = None, None
    for attempt in range(retries + 1):
        start = time.time()
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code in RETRY_STATUS and attempt < retries:
                wait = r.headers.get("Retry-After", "")
                time.sleep(min(int(wait), 20) if wait.isdigit() else 4 * (attempt + 1))
                continue
            return r, None, time.time() - start
        except requests.RequestException as e:
            last_err = f"{type(e).__name__}: {str(e)[:120]}"
            time.sleep(2)
    return None, last_err, 0


def check_page(url):
    site = "{0.scheme}://{0.netloc}".format(urlparse(url))
    with site_locks[site]:
        return _check_page(url)


def _check_page(url):
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
    # usage: python check_sites.py pages.txt [domain.com.au]
    path = sys.argv[1] if len(sys.argv) > 1 else "pages.txt"
    domain = sys.argv[2].lower() if len(sys.argv) > 2 else None
    with open(path, encoding="utf-8") as f:
        urls = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    seen, out = set(), []
    for u in urls:
        if not u.startswith("http") or u in seen:
            continue
        host = urlparse(u).netloc.lower()
        if domain and host not in (domain, "www." + domain):
            continue
        seen.add(u)
        out.append(u)
    return out, domain


def save_report(site, pages, problems, details):
    """When REPORT_DIR is set, save results for the combined email instead of emailing."""
    out = os.environ["REPORT_DIR"]
    os.makedirs(out, exist_ok=True)
    name = (site or "all").replace("/", "_")
    with open(os.path.join(out, name + ".json"), "w", encoding="utf-8") as f:
        json.dump({"site": site, "pages": pages, "problems": problems, "details": details}, f)


def main():
    urls, domain = load_pages()
    if not urls:
        print(f"No URLs found for {domain or 'this list'} in the pages file - nothing to check.")
        if os.getenv("REPORT_DIR"):
            save_report(domain, 0, 0, f"{domain}\n  No pages listed in pages.txt - nothing checked\n")
        return
    sites = {}
    for u in urls:
        p = urlparse(u)
        sites.setdefault(f"{p.scheme}://{p.netloc}", []).append(u)

    for site in sites:
        site_locks[site] = threading.BoundedSemaphore(PER_SITE)
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
    lists = [pages for site, pages in sites.items() if site not in down]
    todo = [u for group in zip_longest(*lists) for u in group if u]   # interleave sites
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        results = list(ex.map(check_page, todo))
    by_url = {r["url"]: r for r in results}

    # 2b) Second chance: re-check server errors slowly after a pause.
    # Separates real broken pages from temporary errors caused by server load.
    flaky = set()
    failed = [r["url"] for r in results if not r["ok"]
              and (r["problem"].startswith("HTTP 5") or r["problem"].startswith("No response"))]
    if failed and len(failed) <= 300:
        print(f"Re-checking {len(failed)} failed pages after a short pause...")
        time.sleep(20)
        with ThreadPoolExecutor(max_workers=3) as ex:
            for r in ex.map(check_page, failed):
                if r["ok"]:
                    flaky.add(r["url"])
                else:
                    r["problem"] += " (failed again on re-check)"
                by_url[r["url"]] = r

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
        recovered = sum(1 for u in pages if u in flaky)
        if recovered:
            report.append(f"  ({recovered} page(s) gave a temporary server error but worked on re-check)")
        for r in bad[:MAX_LISTED_PER_SITE]:
            print(f"    - {r['url']} -> {r['problem']}")
            report.append(f"    X {r['url']}\n      {r['problem']}")
        if len(bad) > MAX_LISTED_PER_SITE:
            report.append(f"    ... and {len(bad) - MAX_LISTED_PER_SITE} more (see GitHub Actions log)")
        report.append("")

    names = ", ".join(urlparse(x).netloc for x in sites)
    took = int(time.time() - started)
    body = (f"Website check at {now} (took {took}s)\n"
            f"Total pages: {len(urls)}\nTotal problems: {problems}\n\n" + "\n".join(report))

    if os.getenv("REPORT_DIR"):
        save_report(domain, len(urls), problems, "\n".join(report))
        print("Report saved for the combined email.")
        sys.exit(1 if problems else 0)

    if problems:
        send_email(f"ALERT: {problems} problem(s) on {names}", body)
        print("Alert email sent.")
        sys.exit(1)
    elif os.getenv("SEND_OK_EMAIL", "false").lower() == "true":
        send_email(f"OK: {names} is working", body)
        print("OK email sent.")
    else:
        print("All good. No email sent.")


if __name__ == "__main__":
    main()
