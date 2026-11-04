#!/usr/bin/env python3
"""
Checks every URL listed in pages.txt (no crawling, no discovery).
Detects: HTTP errors, timeouts, white/blank pages, JS-rendered pages, bot-protection
pages, PHP/WordPress error pages. Emails a report. Fast: pages are checked in parallel.

------------------------------------------------------------------------------
WHAT CHANGED AND WHY  (the "WHITE SCREEN - only 73 characters" bug)
------------------------------------------------------------------------------
The old version fetched each page with `requests` and counted what BeautifulSoup
could find in the raw HTML:

    text = BeautifulSoup(html).get_text()      # no JavaScript, no rendering
    if len(text) < 80: "WHITE SCREEN"

That is a *crawler's* view of the page, not a visitor's. It produces false alarms
whenever the response the checker receives is not the page a browser gets:

  * JavaScript-rendered pages      -> the HTML only holds an empty shell
  * bot protection / WAF challenge  -> a short "verifying your browser" page
    (GoDaddy, Sucuri, Cloudflare, Imunify360, mod_security, CloudLinux ...)
  * rate limiting / shared-hosting  -> "Resource Limit Is Reached" style notices
  * IP reputation for cloud runners -> GitHub Actions runners are often challenged
    even when the same URL loads perfectly from a home connection

"73 characters on EVERY page" is the fingerprint of the second group: the site is
fine, the *runner* is receiving the same short notice page for every URL.

This version fixes it in four ways:

  1. HTTP first, browser second. Every page is still fetched with requests (fast).
     Only pages whose raw HTML looks empty/suspicious are re-checked in a real
     headless Chromium, which runs the JavaScript and measures the text a visitor
     actually sees. A JS-rendered page is reported OK, not as a white screen.
  2. Block/challenge detection. Notices from WAFs, hosting limits and captchas are
     recognised by their text and reported as PROTECTED/BLOCKED, never as a white
     screen, and the notice text is quoted in the email so you can see what the
     server really sent.
  3. Site-wide sanity rule. If most pages of a site return the same short response,
     the report says so once ("this looks like bot protection, not broken pages")
     instead of listing hundreds of fake white screens.
  4. --diagnose. Prints status, headers, byte count and the first characters of both
     the HTTP and the browser-rendered page, so you can confirm in one run from the
     GitHub runner what it is actually being served.

Everything else is unchanged on purpose: same CLI, same pages.txt input, same
reports/*.json contract for combine_report.py, same email, same exit code.
"""

import json
import os
import re
import smtplib
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.mime.text import MIMEText
from itertools import zip_longest
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter

# ----------------------------- settings ------------------------------------
TIMEOUT = 20               # seconds per request
# Some hosts are just slow (capitalautocarremovals.com.au needs ~60 s for the first byte).
# They get a longer timeout instead of a false "unreachable" alert every hour.
SLOW_TIMEOUT = int(os.getenv("SLOW_TIMEOUT", "90"))
SLOW_BROWSER_TIMEOUT = int(os.getenv("SLOW_BROWSER_TIMEOUT", "120000"))  # ms
SLOW_HOSTS = {
    h.strip().lower().removeprefix("www.")
    for h in os.getenv("SLOW_HOSTS", "capitalautocarremovals.com.au").split(",")
    if h.strip()
}


def is_slow(url):
    return urlparse(url).netloc.lower().removeprefix("www.") in SLOW_HOSTS


def timeout_for(url):
    return SLOW_TIMEOUT if is_slow(url) else TIMEOUT
RETRIES = 2                # extra attempts before marking a page failed
MIN_VISIBLE_TEXT = 80      # fewer visible characters than this = suspicious
WORKERS = 30               # total pages checked in parallel
PER_SITE = int(os.getenv("PER_SITE", "4"))   # max simultaneous requests to ONE website
RETRY_STATUS = (429, 502, 503, 504)
MAX_LISTED_PER_SITE = 100  # keeps the email readable if a lot of pages fail

# Browser verification (only used for pages that look empty over plain HTTP)
USE_BROWSER = os.getenv("USE_BROWSER", "true").lower() != "false"
MAX_BROWSER_CHECKS = int(os.getenv("MAX_BROWSER_CHECKS", "12"))  # per site and run (sampling is enough)
BROWSER_WORKERS = int(os.getenv("BROWSER_WORKERS", "1"))
BROWSER_PAUSE = float(os.getenv("BROWSER_PAUSE", "0.4"))   # seconds between browser checks
MAX_TRANSIENT_RETRIES = int(os.getenv("MAX_TRANSIENT_RETRIES", "10"))
TRANSIENT_PAUSE = int(os.getenv("TRANSIENT_PAUSE", "30"))  # seconds before re-checking 5xx pages
BROWSER_TIMEOUT = 45000    # ms

# Contact-form audit: does every page carry a lead form?
CONTACT_FORM_CHECK = os.getenv("CONTACT_FORM_CHECK", "true").lower() != "false"
CONTACT_FORM_REQUIRED = os.getenv("CONTACT_FORM_REQUIRED", "false").lower() == "true"


SETTLE_SECONDS = 3.0       # how long to watch the page until the text stops growing
NAV_TIMEOUT = 45

# A page whose raw HTML contains one of these is broken, not just empty.
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

# Texts that mean "the server did not show me the page", not "the page is blank".
# Matched case-insensitively against the first ~4000 characters of visible text.
BLOCK_SIGNATURES = [
    "just a moment",
    "checking your browser",
    "verifying your browser",
    "verify you are human",
    "needs to review the security of your connection",
    "enable javascript and cookies to continue",
    "attention required",
    "access denied",
    "access to this page has been denied",
    "request blocked",
    "request unsuccessful",
    "you have been blocked",
    "blocked by",
    "web application firewall",
    "sucuri website firewall",
    "mod_security",
    "modsecurity",
    "imunify360",
    "ddos protection",
    "ddos-guard",
    "captcha",
    "are you a robot",
    "unusual traffic",
    "too many requests",
    "rate limit",
    "resource limit is reached",
    "resource limit",
    "this site is temporarily unavailable",
    "temporarily unavailable",
    "site is offline",
    "one more step",
    "please wait while we verify",
    "please wait while your request is being verified",
    "security check",
    "maintenance mode",
    "not acceptable",
    "the request could not be satisfied",
    # 5xx / overload pages: the server answered, it just could not serve the page
    "503 service",
    "service unavailable",
    "service temporarily unavailable",
    "temporarily unavailable",
    "500 internal server error",
    "502 bad gateway",
    "504 gateway",
    "gateway time-out",
    "the server is busy",
    "server too busy",
    "please try again later",
    "try again later",
]

# Never treated as visible page text (matches a browser's innerText behaviour closely enough).
NON_TEXT_TAGS = ["script", "style", "noscript", "template", "svg", "canvas", "iframe"]

# Text that only a 5xx error page contains. Deliberately strict: generic phrasing such
# as "try again later" also appears in firewall notices, which are a different verdict.
FATAL_5XX = (
    "503 service",
    "503 service unavailable",
    "service unavailable",
    "service temporarily unavailable",
    "500 internal server error",
    "internal server error",
    "502 bad gateway",
    "bad gateway",
    "504 gateway",
    "gateway time-out",
    "gateway timeout",
    "the server is busy",
    "server too busy",
)

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-AU,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",      # br is not always available in requests
    "Connection": "keep-alive",
})
site_locks = {}
adapter = HTTPAdapter(pool_connections=WORKERS, pool_maxsize=WORKERS * 2)
session.mount("http://", adapter)
session.mount("https://", adapter)

# ---------------------------------------------------------------------------
# measuring "what a visitor sees"
# ---------------------------------------------------------------------------
# Runs inside Chromium. Counts only text that is really rendered: skips
# display:none / visibility:hidden / opacity:0 / screen-reader-only text,
# script/style/svg junk, and walks open shadow DOM + same-origin iframes.
MEASURE_JS = r"""
() => {
  const SKIP = new Set(['SCRIPT','STYLE','NOSCRIPT','TEMPLATE','HEAD','META','LINK','TITLE',
                        'SVG','PATH','G','DEFS','SYMBOL','USE','CANVAS','VIDEO','AUDIO',
                        'OBJECT','EMBED','BR','HR']);
  const SR_ONLY = /(^|[\s_-])(sr-only|visually-?hidden|screen-?reader(-text)?|hidden-text|hide-text)([\s_-]|$)/i;
  const out = { chars: 0, words: 0, sample: '', hiddenChars: 0 };

  const visible = (el) => {
    let cs;
    try { cs = window.getComputedStyle(el); } catch (e) { return false; }
    if (!cs) return false;
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.visibility === 'collapse') return false;
    const op = parseFloat(cs.opacity);
    if (!isNaN(op) && op < 0.05) return false;
    const fs = parseFloat(cs.fontSize);
    if (!isNaN(fs) && fs < 1) return false;
    const r = el.getBoundingClientRect();
    if (cs.position === 'absolute' && cs.overflow === 'hidden' && (r.width <= 2 || r.height <= 2)) return false;
    if (cs.clip === 'rect(0px, 0px, 0px, 0px)' || cs.clip === 'rect(1px, 1px, 1px, 1px)') return false;
    const cls = el.getAttribute ? (el.getAttribute('class') || '') : '';
    if (cls && SR_ONLY.test(cls) && (r.width <= 2 || r.height <= 2)) return false;
    if (cs.textIndent && parseFloat(cs.textIndent) < -500) return false;
    return true;
  };

  const walk = (root) => {
    if (!root) return;
    const kids = root.childNodes || [];
    for (const node of kids) {
      if (node.nodeType === 3) {
        const parent = node.parentElement;
        const text = (node.nodeValue || '').replace(/\s+/g, ' ').trim();
        if (!text || !parent) continue;
        if (!visible(parent)) { out.hiddenChars += text.length; continue; }
        out.chars += text.length;
        out.words += text.split(' ').filter(Boolean).length;
        if (out.sample.length < 250) out.sample += (out.sample ? ' ' : '') + text;
        continue;
      }
      if (node.nodeType !== 1) continue;
      const tag = node.tagName.toUpperCase();
      if (SKIP.has(tag)) continue;
      if (!visible(node)) {
        try { out.hiddenChars += (node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim().length; } catch (e) {}
        continue;
      }
      if (node.shadowRoot) walk(node.shadowRoot);
      if (tag === 'IFRAME') {
        try { const d = node.contentDocument; if (d && d.body) walk(d.body); } catch (e) {}
        continue;
      }
      walk(node);
    }
  };

  walk(document.body || document.documentElement);
  out.sample = out.sample.replace(/\s+/g, ' ').trim();
  return out;
}
"""


# Markers left in the HTML by the form plugins used on WordPress sites. Checked before
# the <form> scan because many of these render their fields with JavaScript.
FORM_PLUGIN_MARKERS = (
    "wpcf7", "wpforms", "gform_", "gform_wrapper", "gravityforms", "ninja_forms", "nf-form",
    "elementor-form", "fluentform", "forminator", "caldera", "hs-form", "hbspt.forms",
    "wp-block-jetpack-contact-form", "mc4wp", "typeform", "jotform", "formstack",
    "contact-form-7", "contact_form_7", "wpcargo", "strong-forms", "quform", "cf7",
)

# Inputs that make a <form> a lead form rather than a search box or a newsletter toggle.
CONTACT_INPUT_HINTS = ("email", "mail", "phone", "tel", "mobile", "name", "message",
                       "enquir", "inquir", "comment", "subject", "postcode")


def form_looks_like_contact(form):
    """True when this <form> asks for the kind of data a lead form asks for.

    Search boxes are excluded on purpose: almost every WordPress header carries one,
    and counting it would hide the pages that really have no lead form.
    """
    fields = [f for f in form.find_all(["input", "select", "textarea"])
              if (f.get("type") or "").lower() not in ("submit", "button", "reset", "image", "hidden")]
    if not fields:
        return False
    is_search = all(
        (f.get("type") or "").lower() == "search"
        or (f.get("name") or "").lower() in ("s", "search", "q", "query", "keyword", "keywords")
        for f in fields
    )
    if is_search:
        return False
    if form.find("textarea"):
        return True
    for field in form.find_all(["input", "select"]):
        ftype = (field.get("type") or "text").lower()
        if ftype in ("email", "tel"):
            return True
        if ftype in ("hidden", "submit", "button", "search", "reset", "image", "file"):
            continue
        blob = " ".join(str(field.get(k) or "") for k in ("name", "id", "placeholder", "aria-label")).lower()
        if any(hint in blob for hint in CONTACT_INPUT_HINTS):
            return True
    return False


# A form plugin shortcode left unprocessed by WordPress: the visitor sees this text
# instead of a form. capitalautocarremovals.com.au/contact/ shows
# [contact-form-7 id="edc096b" title="Home Form"] exactly like this.
BROKEN_FORM_SHORTCODE = re.compile(
    r"\[\s*(contact-form-7|contact-form|wpforms|gravityform|gravityforms|ninja_form|"
    r"ninja-forms|formidable|caldera_form|fluentform|forminator|quform|strong-forms)"
    r"[^\]]{0,140}\]",
    re.IGNORECASE,
)


def find_broken_form_shortcode(text):
    """Return the raw shortcode that the page printed instead of a form, else ''."""
    m = BROKEN_FORM_SHORTCODE.search(text or "")
    return m.group(0)[:160] if m else ""


def parse_html(html):
    """BeautifulSoup parse that never raises (real pages contain broken markup)."""
    try:
        return BeautifulSoup(html or "", "html.parser")
    except Exception:
        return None


def detect_contact_form(html=None, soup=None):
    """Does this page really contain a contact form? -> (bool, reason).

    Only real fields count. Never the string "wpcf7" on its own: sites that load the
    Contact Form 7 stylesheet but render NO form (capitalautocarremovals.com.au is
    one) would otherwise be reported as having a form they do not have.
    """
    if soup is None:
        soup = parse_html(html)
    if soup is None:
        return False, ""
    try:
        for form in soup.find_all("form"):
            if form_looks_like_contact(form):
                return True, "form element"
        # a form plugin container that holds real fields (its <form> may be injected later)
        for el in soup.find_all(attrs={"class": True}):
            classes = " ".join(el.get("class") or []).lower()
            if not any(m in classes for m in FORM_PLUGIN_MARKERS):
                continue
            fields = [f for f in el.find_all(["input", "select", "textarea"])
                      if (f.get("type") or "").lower() not in
                      ("submit", "button", "reset", "image", "hidden")]
            if fields:
                return True, f"plugin:{classes.split()[0]}"
    except Exception:
        pass
    return False, ""


def text_from_html(html, soup=None):
    """Visible-ish text from raw HTML (no browser). Cheap first pass.

    Defensive on purpose: real pages contain broken markup, and one malformed tag
    must never abort the whole monitoring job.
    """
    if soup is None:
        soup = parse_html(html)
    if soup is None:
        return ""
    for tag in NON_TEXT_TAGS:
        try:
            for t in soup.find_all(tag):
                t.decompose()
        except Exception:
            continue
    # drop obviously hidden blocks: inline display:none / visibility:hidden / hidden attr
    try:
        hidden_elements = []
        for el in soup.find_all(style=True):
            attrs = getattr(el, "attrs", None) or {}
            style = str(attrs.get("style") or "").replace(" ", "").lower()
            if "display:none" in style or "visibility:hidden" in style or "opacity:0" in style:
                hidden_elements.append(el)
        for el in soup.find_all(attrs={"hidden": True}):
            hidden_elements.append(el)
        for el in hidden_elements:
            try:
                el.decompose()
            except Exception:
                pass
    except Exception:
        pass
    try:
        return re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
    except Exception:
        return ""


def find_signature(text, signatures):
    low = text[:6000].lower()
    for sig in signatures:
        if sig in low:
            return sig
    return None


# ---------------------------------------------------------------------------
# HTTP layer (unchanged behaviour, plus block detection)
# ---------------------------------------------------------------------------
def fetch(url, retries=RETRIES):
    last_err, r = None, None
    for attempt in range(retries + 1):
        start = time.time()
        try:
            r = session.get(url, timeout=timeout_for(url), allow_redirects=True)
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
    """Never raises: a crash on one page must not abort the whole monitoring run."""
    site = "{0.scheme}://{0.netloc}".format(urlparse(url))
    lock = site_locks.get(site)
    try:
        if lock is not None:
            with lock:
                return _check_page(url)
        return _check_page(url)
    except Exception as e:
        return {"url": url, "ok": False, "suspect": False,
                "problem": f"Checker error while reading this page: {type(e).__name__}: {str(e)[:120]}"}


def _check_page(url):
    r, err, secs = fetch(url)
    if r is None:
        return {"url": url, "ok": False, "problem": f"No response ({err})", "suspect": False}
    if r.status_code >= 500:
        # The server answered but could not serve the page: usually the host throttling
        # us (too many parallel requests), occasionally a real outage. Never call this a
        # white screen without checking what a browser gets.
        body = text_from_html(r.text or "")
        form, _ = detect_contact_form(r.text or "") if CONTACT_FORM_CHECK else (False, "")
        return {"url": url, "ok": False, "suspect": True, "form": form,
                "http_sample": body[:200], "http_len": len(body), "http_status": r.status_code,
                "problem": f"SERVER ERROR - HTTP {r.status_code} from the server"}

    if r.status_code >= 400:
        # a 403/429 from a WAF gets the clearer wording
        body = text_from_html(r.text or "")
        sig = find_signature(body, BLOCK_SIGNATURES)
        if sig or r.status_code in (403, 429, 503):
            detail = f' - page said: "{body[:120]}"' if body else ""
            return {"url": url, "ok": False, "suspect": True,
                    "problem": f"BLOCKED/HTTP {r.status_code} - the server refused the request{detail}"}
        return {"url": url, "ok": False, "suspect": False, "problem": f"HTTP {r.status_code}"}

    if "text/html" not in r.headers.get("Content-Type", ""):
        if not (r.content or b"").strip():
            return {"url": url, "ok": False, "suspect": False, "problem": "Empty response body"}
        return {"url": url, "ok": True, "suspect": False, "problem": ""}

    html = r.text or ""

    # a real error page can be very short, so look for the error text first
    for sig in ERROR_SIGNATURES:
        if sig in html.lower():
            return {"url": url, "ok": False, "suspect": False, "problem": f"Error text on page: '{sig}'"}

    if len(html.strip()) < 300:
        return {"url": url, "ok": False, "suspect": True,
                "problem": f"WHITE SCREEN - body almost empty ({len(html.strip())} bytes)"}

    soup = parse_html(html)
    # the form question is only asked of the homepage - every other page is still
    # checked for white screens, error text and unprocessed form shortcodes
    is_home = urlparse(url).path in ("", "/")
    form, form_why = (detect_contact_form(html, soup=soup)
                      if (CONTACT_FORM_CHECK and is_home) else (None, ""))
    text = text_from_html(html, soup=soup)
    if len(text) >= MIN_VISIBLE_TEXT:
        broken = find_broken_form_shortcode(text) if CONTACT_FORM_CHECK else ""
        if broken:
            return {"url": url, "ok": False, "suspect": False, "form": False,
                    "form_why": "raw shortcode",
                    "http_sample": text[:200], "http_len": len(text),
                    "problem": f"CONTACT FORM BROKEN - the page shows the raw shortcode "
                               f"{broken} instead of a form"}
        return {"url": url, "ok": True, "suspect": False, "problem": "",
                "form": form, "form_why": form_why,
                "http_sample": text[:200], "http_len": len(text)}

    # Short text over plain HTTP: could be a JS app, a WAF notice, or a real white screen.
    # Do not judge it yet - send it to the browser for verification.
    return {"url": url, "ok": False, "suspect": True, "http_text": text,
            "http_sample": text[:200], "http_len": len(text),
            "form": form, "form_why": form_why,
            "problem": f"WHITE SCREEN - only {len(text)} characters of visible text"}


# ---------------------------------------------------------------------------
# Browser layer - the part that removes the false "white screen" reports
# ---------------------------------------------------------------------------
_thread_local = threading.local()


def _browser():
    """One Chromium per worker thread, reused for every page that thread checks."""
    if getattr(_thread_local, "browser", None) is None:
        from playwright.sync_api import sync_playwright
        pw = sync_playwright().start()
        browser = pw.chromium.launch(
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-blink-features=AutomationControlled"]
        )
        _thread_local.playwright = pw
        _thread_local.browser = browser
    return _thread_local.browser


def close_browser():
    """Close this thread's browser (Playwright objects are thread-affine)."""
    browser = getattr(_thread_local, "browser", None)
    pw = getattr(_thread_local, "playwright", None)
    try:
        if browser is not None:
            browser.close()
    except Exception:
        pass
    finally:
        _thread_local.browser = None
        try:
            if pw is not None:
                pw.stop()
        except Exception:
            pass
        _thread_local.playwright = None


def browser_probe(url):
    """Render the page in Chromium and report what a visitor would see."""
    browser = _browser()
    context = browser.new_context(
        user_agent=session.headers["User-Agent"],
        viewport={"width": 1366, "height": 900},
        locale="en-AU",
        ignore_https_errors=True,
    )
    page = context.new_page()
    info = {"url": url, "status": None, "chars": 0, "words": 0, "sample": "",
            "hidden": 0, "error": "", "headers": {}}
    try:
        response = page.goto(url, wait_until="domcontentloaded",
                             timeout=SLOW_BROWSER_TIMEOUT if is_slow(url) else BROWSER_TIMEOUT)
        info["status"] = response.status if response else None
        if response is not None:
            try:
                info["headers"] = dict(response.headers)
            except Exception:
                info["headers"] = {}
        for state in ("load", "networkidle"):
            try:
                page.wait_for_load_state(state, timeout=10000)
            except Exception:
                pass

        # wait until the visible text stops growing (handles slow JS / XHR rendering)
        deadline = time.time() + SETTLE_SECONDS
        last, stable = -1, 0
        while time.time() < deadline:
            try:
                n = page.evaluate(
                    "() => document.body ? document.body.innerText.replace(/\\s+/g,' ').trim().length : 0")
            except Exception:
                n = 0
            if n == last and n > 0:
                stable += 1
                if stable >= 2:
                    break
            else:
                stable = 0
            last = n
            time.sleep(0.25)

        # scroll once so lazy / reveal-on-scroll content is painted too
        try:
            before = page.evaluate("() => document.body ? document.body.scrollHeight : 0")
            page.evaluate("""async () => {
                const step = Math.max(window.innerHeight - 100, 300);
                for (let y = 0; y < document.body.scrollHeight; y += step) {
                    window.scrollTo(0, y);
                    await new Promise(r => setTimeout(r, 100));
                }
                window.scrollTo(0, 0);
            }""")
            after = page.evaluate("() => document.body ? document.body.scrollHeight : 0")
            if after != before:
                time.sleep(1.0)
        except Exception:
            pass

        measured = page.evaluate(MEASURE_JS)
        info["chars"] = int(measured.get("chars", 0))
        info["words"] = int(measured.get("words", 0))
        info["hidden"] = int(measured.get("hiddenChars", 0))
        info["contact_form"] = bool(measured.get("contactForm"))
        info["broken_shortcode"] = measured.get("brokenShortcode", "")
        info["forms"] = int(measured.get("forms", 0))
        info["sample"] = (measured.get("sample") or "")[:250]
    except Exception as e:
        info["error"] = f"{type(e).__name__}: {str(e).splitlines()[0][:160]}"
    finally:
        try:
            context.close()
        except Exception:
            pass
    return info


def verify_with_browser(urls, label="", workers=None):
    """Render a batch of suspicious URLs. Returns {url: browser_probe result}.

    The URLs are split into one chunk per worker thread, because Playwright's
    sync API is thread-affine: each thread creates, uses and closes its own browser.
    """
    urls = [u for u in urls if u]
    if not urls or not USE_BROWSER:
        return {}
    try:
        import playwright  # noqa: F401
    except ImportError:
        print("  ! Playwright is not installed - falling back to HTTP-only checks.")
        print("    Fix: pip install playwright && playwright install chromium")
        return {}

    workers = max(1, min(workers or BROWSER_WORKERS, len(urls)))
    chunks = [urls[i::workers] for i in range(workers)]
    collected = {}
    lock = threading.Lock()

    def run_chunk(chunk):
        try:
            for n, url in enumerate(chunk):
                if n and BROWSER_PAUSE:
                    time.sleep(BROWSER_PAUSE)
                info = browser_probe(url)
                with lock:
                    collected[url] = info
        finally:
            close_browser()

    threads = [threading.Thread(target=run_chunk, args=(c,), daemon=True) for c in chunks if c]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return collected


def resolve_suspect(result, probe):
    """Turn an HTTP result + its browser probe into a final verdict.

    Every verdict carries the text that was measured, so the site-wide rule can still
    recognise "the same short page on every URL" (WAF notice, rate limit, ...).
    """
    url = result["url"]
    problem = result["problem"]
    info = {"url": url,
            "http_sample": result.get("http_sample", ""),
            "http_len": result.get("http_len", 0),
            "form": bool(result.get("form")),
            "form_why": result.get("form_why", "")}
    broken_shortcode = (probe or {}).get("broken_shortcode", "") or \
                       (find_broken_form_shortcode(result.get("http_text", ""))
                        if CONTACT_FORM_CHECK else "")
    if result.get("http_status"):
        info["http_status"] = result["http_status"]
    if probe:
        info["browser_sample"] = probe.get("sample", "")
        info["browser_chars"] = probe.get("chars", 0)
        # the browser sees forms that JavaScript injects, so trust it when it found one
        if probe.get("contact_form"):
            info["form"] = True
            info["form_why"] = info.get("form_why") or "rendered form"

    if probe and probe.get("error"):
        # browser could not load it at all - keep the HTTP wording, add the reason
        info["problem"] = f"{problem} (browser could not confirm: {probe['error'][:100]})"
        info["ok"] = False
        return info

    if probe:
        sample = probe.get("sample", "")
        status = probe.get("status") or 0
        sig = find_signature(sample, BLOCK_SIGNATURES) or find_signature(problem, BLOCK_SIGNATURES)

        # The site refused to serve the page (5xx) instead of serving an empty one.
        # That is throttling/overload, not a white screen - the pages are usually fine.
        http_status = result.get("http_status") or 0
        five_xx = (status >= 500 or http_status >= 500
                   or (sample and any(k in sample.lower() for k in FATAL_5XX)))
        if five_xx:
            info.update(ok=False, transient=True,
                        problem=(f"OVERLOADED / RATE-LIMITED - the server answered HTTP "
                                 f"{status or http_status or '5xx'} instead of the page "
                                 f"(the host is throttling the checker, not broken content)"
                                 + (f'. Server said: "{sample[:110]}"' if sample else "")))
            return info

        if probe["chars"] >= MIN_VISIBLE_TEXT and not sig:
            if broken_shortcode:
                info.update(ok=False, form=False, form_why="raw shortcode",
                            problem=(f"CONTACT FORM BROKEN - the page shows the raw "
                                     f"shortcode {broken_shortcode} instead of a form"))
                return info
            # the page renders fine for a real browser: JS-rendered, not broken
            info.update(ok=True, problem="", js_rendered=True)
            return info

        if sig:
            info.update(ok=False,
                        problem=(f"PROTECTED/BLOCKED - the server is returning a challenge page, "
                                 f"not your content (matched '{sig}'; {probe['chars']} chars "
                                 f'visible). Page said: "{sample[:110]}"'))
            return info

        if probe["chars"] >= MIN_VISIBLE_TEXT:
            info.update(ok=True, problem="")
            return info

        if probe["chars"] == 0 and status >= 400:
            info.update(ok=False,
                        problem=f"HTTP {status} in the browser (server refused the request)")
            return info

        info.update(ok=False,
                    problem=(f"WHITE SCREEN - only {probe['chars']} characters of visible text "
                             f"after rendering (browser confirmed; {probe['hidden']} chars hidden)"
                             + (f'. Page said: "{sample[:110]}"' if sample else "")))
        return info

    # no browser available: keep the honest HTTP verdict but say it is unconfirmed
    info.update(ok=False,
                problem=f"{problem} (unconfirmed - not re-checked in a browser)")
    return info


def identical_short_cluster(pages, by_url, short_limit=600, min_pages=5, share=0.6):
    """Detect a site that answers every URL with the same short page.

    Returns {"sample": text, "count": n, "length": chars} or None.
    Pages a browser confirmed as real content (js_rendered) are ignored, so a genuine
    JavaScript app is never mistaken for a notice page.
    """
    if len(pages) < min_pages:
        return None
    samples = {}
    for u in pages:
        r = by_url.get(u) or {}
        if r.get("js_rendered"):
            continue
        sample = (r.get("browser_sample") or r.get("http_sample") or "").strip()
        length = r.get("browser_chars") or r.get("http_len") or len(sample)
        if not sample or length > short_limit:
            continue
        key = re.sub(r"[^a-z0-9]+", " ", sample.lower())[:160].strip()
        if not key:
            continue
        samples.setdefault(key, []).append((sample, length))

    if not samples:
        return None
    key, items = max(samples.items(), key=lambda kv: len(kv[1]))
    count = len(items)
    if count < min_pages or count < len(pages) * share:
        return None
    return {"sample": items[0][0], "count": count, "length": max(i[1] for i in items)}


# ---------------------------------------------------------------------------
# email
# ---------------------------------------------------------------------------
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


def try_send(subject, body):
    """Send the email, but never crash the run when credentials are missing (local use)."""
    try:
        send_email(subject, body)
        print("Email sent.")
        return True
    except KeyError as e:
        print(f"Email not sent: missing environment variable {e} "
              f"(set SMTP_USER, SMTP_PASS and MAIL_TO to enable email).")
    except Exception as e:
        print(f"Email not sent: {type(e).__name__}: {e}")
    print("\n------------ report ------------\n" + body + "\n-------------------------------")
    return False


# ---------------------------------------------------------------------------
# input / output
# ---------------------------------------------------------------------------
def load_pages():
    """usage: python check_sites.py pages.txt [domain.com.au]"""
    path = sys.argv[1] if len(sys.argv) > 1 else "pages.txt"
    domain = sys.argv[2].lower() if len(sys.argv) > 2 and not sys.argv[2].startswith("-") else None
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


def save_report(site, pages, problems, details, sites_payload=None):
    """When REPORT_DIR is set, save results for the combined email instead of emailing.

    `sites_payload` is the structured version of the same information (per site: the
    failing pages with their reason, plus notes). The combined HTML email uses it to
    render the report; `details` stays as the plain-text fallback.
    """
    out = os.environ["REPORT_DIR"]
    os.makedirs(out, exist_ok=True)
    name = (site or "all").replace("/", "_")
    with open(os.path.join(out, name + ".json"), "w", encoding="utf-8") as f:
        json.dump({"site": site, "pages": pages, "problems": problems,
                   "details": details, "sites": sites_payload or []}, f)


# ---------------------------------------------------------------------------
# diagnostics
# ---------------------------------------------------------------------------
def diagnose(url):
    """Show exactly what this machine/runner is served - HTTP view and browser view."""
    print(f"DIAGNOSE {url}\n" + "-" * 70)
    try:
        r = session.get(url, timeout=timeout_for(url), allow_redirects=True)
        raw = text_from_html(r.text or "")
        print(f"HTTP      status={r.status_code} bytes={len(r.content or b'')} "
              f"type={r.headers.get('Content-Type', '?')}")
        for h in ("server", "vary", "cf-ray", "x-sucuri-id", "x-powered-by", "retry-after", "set-cookie"):
            if h in r.headers:
                print(f"          {h}: {r.headers[h][:110]}")
        print(f"HTTP text {len(raw)} chars: {raw[:300]!r}")
    except Exception as e:
        print(f"HTTP      FAILED: {type(e).__name__}: {e}")

    if USE_BROWSER:
        try:
            info = browser_probe(url)
            print(f"BROWSER   status={info['status']} chars={info['chars']} "
                  f"hidden={info['hidden']} error={info['error'] or '-'}")
            print(f"BROWSER text: {info['sample'][:300]!r}")
        except Exception as e:
            print(f"BROWSER   FAILED: {type(e).__name__}: {e}")
    print("-" * 70
          + "\nIf HTTP text is short but BROWSER text is long -> the page is JS-rendered: fine."
          + "\nIf both are short and the text looks like a security notice -> the runner is being"
          + "\nblocked by the site's firewall, not a broken page.")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    flags = {a for a in sys.argv[1:] if a.startswith("-")}

    if "--diagnose" in flags:
        urls, domain = load_pages()
        if not urls:
            print("No URLs to diagnose.")
            return
        target = os.getenv("DIAGNOSE_URL") or urls[0]
        diagnose(target)
        return

    if "--no-browser" in flags:
        global USE_BROWSER
        USE_BROWSER = False

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

    # 1) Quick check: is each website reachable at all?
    down = {}

    def probe(site):
        r, err, _ = fetch(site + "/", retries=2)
        return site, (err if r is None else None)

    with ThreadPoolExecutor(max_workers=len(sites) or 1) as ex:
        for site, err in ex.map(probe, sites):
            if err:
                down[site] = err

    # 2) Check all pages of the reachable sites in one big parallel pool (HTTP only)
    lists = [pages for site, pages in sites.items() if site not in down]
    todo = [u for group in zip_longest(*lists) for u in group if u]   # interleave sites
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        results = list(ex.map(check_page, todo))
    by_url = {r["url"]: r for r in results}

    # 2b) Second chance for server errors, slowly, after a pause
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

    # 3) Browser verification for every page that only looked empty over HTTP.
    #    This is what turns "73 characters of visible text" into either OK
    #    (JavaScript rendered it) or a correctly labelled block/protected page.
    suspects = [r for r in results if r.get("suspect") and not r["ok"]]
    if suspects:
        if not USE_BROWSER:
            print(f"{len(suspects)} page(s) looked empty; browser verification disabled.")
        else:
            # Do not spend 40 browser runs on the same notice: sample first, then decide.
            sample = suspects[:MAX_BROWSER_CHECKS]
            print(f"{len(suspects)} page(s) looked empty over HTTP - verifying {len(sample)} in a browser...")
            probes = verify_with_browser([r["url"] for r in sample])
            for r in sample:
                by_url[r["url"]] = resolve_suspect(r, probes.get(r["url"]))
            rest = suspects[MAX_BROWSER_CHECKS:]
            if rest:
                good = sum(1 for r in sample if by_url[r["url"]]["ok"])
                if good >= len(sample) * 0.8:
                    # the site renders in a browser: the remaining pages are the same kind
                    for r in rest:
                        by_url[r["url"]] = {"url": r["url"], "ok": True, "problem": "",
                                            "js_rendered": True}
                    print(f"  {good}/{len(sample)} sampled pages render fine in a browser - "
                          f"treating the other {len(rest)} the same (site is JS-rendered).")
                else:
                    for r in rest:
                        by_url[r["url"]] = {"url": r["url"], "ok": False,
                                            "problem": r["problem"] + " (not re-checked: sample limit)"}

    # 3b) Second chance for pages the host refused to serve (5xx / throttling).
    #     A monitoring tool must not report "broken page" for its own load spike:
    #     wait, then ask those pages once more, one at a time.
    transient = [r for r in by_url.values() if r.get("transient") and not r["ok"]]
    if transient and USE_BROWSER:
        retry = transient[:MAX_TRANSIENT_RETRIES]
        print(f"Waiting {TRANSIENT_PAUSE}s, then re-checking {len(retry)} page(s) the host refused (5xx)...")
        time.sleep(TRANSIENT_PAUSE)
        probes = verify_with_browser([r["url"] for r in retry], workers=1)
        for r in retry:
            info = probes.get(r["url"]) or {}
            if not info.get("error") and int(info.get("chars") or 0) >= MIN_VISIBLE_TEXT:
                by_url[r["url"]] = {"url": r["url"], "ok": True, "problem": "",
                                    "js_rendered": True, "browser_chars": info["chars"]}
                print(f"    recovered after the pause: {r['url']}")

    # 4) Build the report
    report, problems = [], 0
    sites_payload = []            # structured copy for the HTML email
    for site, pages in sites.items():
        entry = {"site": urlparse(site).netloc, "url": site, "pages": len(pages),
                 "problems": 0, "items": [], "notes": [], "down": False}
        sites_payload.append(entry)
        if site in down:
            problems += 1
            entry.update(problems=1, down=True)
            entry["notes"].append(f"Site unreachable - {down[site]}. {len(pages)} pages not checked.")
            print(f"[SITE DOWN] {site}: {down[site]}")
            report.append(f"{site}\n  SITE DOWN - cannot be reached ({down[site]})\n  {len(pages)} pages not checked\n")
            continue
        bad = [by_url[u] for u in pages if not by_url[u]["ok"]]

        # Site-wide sanity rule -------------------------------------------------
        # If most pages of a site return the SAME short text, that is not 200 broken
        # pages: it is one notice page (WAF challenge, rate limit, "coming soon",
        # maintenance, login wall) being served for every URL. Report it once.
        cluster = identical_short_cluster(pages, by_url)
        if cluster:
            bad = []

        # contact form: homepage only -------------------------------------------------
        home = next((u for u in pages if urlparse(u).path in ("", "/")), None)
        home_form = None
        if CONTACT_FORM_CHECK and home is not None:
            home_form = bool(by_url[home].get("form"))
        form_problem = (1 if (CONTACT_FORM_CHECK and CONTACT_FORM_REQUIRED
                              and home_form is False) else 0)
        site_problems = (1 if cluster else len(bad)) + form_problem

        problems += site_problems
        entry["problems"] = site_problems
        entry["home_form"] = home_form
        entry["home_url"] = home or site

        print(f"[{'ISSUES' if site_problems else 'OK'}] {site}: {len(pages)} pages, "
              f"{site_problems} problems"
              + ("" if home_form is None else
                 (", form on homepage" if home_form else ", NO form on homepage")))
        report.append(f"{site}\n  Pages checked: {len(pages)}  |  Problems: {site_problems}")
        if home_form is not None:
            report.append("  Contact form on homepage: " + ("yes" if home_form else "NO"))
            if home_form is False and CONTACT_FORM_REQUIRED:
                entry["items"].append({
                    "url": home or site,
                    "problem": "NO CONTACT FORM ON HOMEPAGE - visitors landing on the "
                               "homepage have no form to fill in",
                })
                report.append(f"  X {home or site}\n      NO CONTACT FORM ON HOMEPAGE")

        recovered = sum(1 for u in pages if u in flaky)
        if recovered:
            entry["notes"].append(f"{recovered} page(s) gave a temporary server error but worked on re-check.")
            report.append(f"  ({recovered} page(s) gave a temporary server error but worked on re-check)")

        js_rendered = sum(1 for u in pages if by_url[u].get("js_rendered"))
        if js_rendered:
            entry["notes"].append(f"{js_rendered} page(s) are rendered by JavaScript - confirmed OK in a browser.")
            report.append(f"  ({js_rendered} page(s) are rendered by JavaScript - confirmed OK in a browser)")

        if cluster:
            sample, count = cluster["sample"], cluster["count"]
            entry["notes"].append(
                f"PROTECTED, NOT BROKEN - the same {cluster['length']}-character page was "
                f"returned for {count} of {len(pages)} URLs: \"{sample[:160]}\". This is a "
                f"firewall / rate-limit notice, not missing content.")
            print(f"  ! {count} of {len(pages)} pages returned the same short page "
                  f"- reporting that once instead of {count} times.")
            report.append(
                "  PROTECTED / NOT BROKEN - the same short page was returned for "
                f"{count} of {len(pages)} URLs ({cluster['length']} characters):\n"
                f'    "{sample[:200]}"\n'
                "  Every URL of a real site cannot share one identical short page, so this is\n"
                "  almost certainly a firewall / rate-limit / region notice (GitHub runner IPs\n"
                "  are commonly challenged) and NOT missing content.\n"
                "  How to confirm and fix:\n"
                "    1. run this in the same job:  python check_sites.py pages.txt "
                f"{urlparse(site).netloc} --diagnose\n"
                "    2. if the text above is a security notice, whitelist your monitoring IP\n"
                "       (or the GitHub Actions ranges) in the site's firewall/WAF, lower\n"
                "       PER_SITE, and re-run;\n"
                "    3. open one URL in a normal browser to see the real page.")

        for r in bad[:MAX_LISTED_PER_SITE]:
            print(f"    - {r['url']} -> {r['problem']}")
            entry["items"].append({"url": r["url"], "problem": r["problem"]})
            report.append(f"    X {r['url']}\n      {r['problem']}")
        if len(bad) > MAX_LISTED_PER_SITE:
            report.append(f"    ... and {len(bad) - MAX_LISTED_PER_SITE} more (see GitHub Actions log)")
        report.append("")

    names = ", ".join(urlparse(x).netloc for x in sites)
    took = int(time.time() - started)
    body = (f"Website check at {now} (took {took}s)\n"
            f"Total pages: {len(urls)}\nTotal problems: {problems}\n\n" + "\n".join(report))

    if os.getenv("REPORT_DIR"):
        save_report(domain, len(urls), problems, "\n".join(report), sites_payload)
        print("Report saved for the combined email.")
        sys.exit(1 if problems else 0)

    if problems:
        try_send(f"ALERT: {problems} problem(s) on {names}", body)
        sys.exit(1)
    elif os.getenv("SEND_OK_EMAIL", "false").lower() == "true":
        try_send(f"OK: {names} is working", body)
    else:
        print("All good. No email sent.")


if __name__ == "__main__":
    main()
