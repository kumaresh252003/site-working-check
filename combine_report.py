#!/usr/bin/env python3
"""Reads the per-site results saved by each check job and sends ONE combined email.

The email is sent as HTML (with a plain-text fallback for old clients): a status
header, three summary tiles, one row per site, and a card for every failing page.

DUPLICATE-EMAIL GUARD
---------------------
You trigger this workflow from cron-job.org. If anything makes it start twice in the
same hour - a retry from the cron service, a double trigger, a manual re-run - two
runs would each send an email. Before sending, this script asks GitHub whether an
earlier run in the same hour already completed its "send combined email" job. If one
did, this run prints that and exits without emailing, so you get exactly one email per
hour. It fails safe: if GitHub cannot be asked, the email is sent rather than skipped.

    DEDUPE_HOUR=false   turn the guard off
    --force             send anyway (workflow input: force_email)
    --test              send one test email and exit (workflow input: test_email)
"""
import glob
import html
import json
import os
import re
import smtplib
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

EMAIL_JOB_NAME = "send combined email"      # must match the job name in the workflow

# ---------------------------------------------------------------------------
# palette
# ---------------------------------------------------------------------------
INK = "#0f172a"
INK_SOFT = "#334155"
MUTED = "#64748b"
LINE = "#e4e9f0"
PAGE_BG = "#eef1f6"

RED, RED_BG, RED_SOFT = "#dc2626", "#fef2f2", "#fecaca"
GREEN, GREEN_BG, GREEN_SOFT = "#059669", "#ecfdf5", "#a7f3d0"
AMBER, AMBER_BG, AMBER_SOFT = "#b45309", "#fffbeb", "#fde68a"
GREY_BG = "#f8fafc"


def esc(value):
    return html.escape(str(value), quote=True)


def shorten(text, limit=300):
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def status_mark(site):
    """✅ when the site is fine, ❌ when it has problems or is unreachable."""
    return "❌" if (site.get("problems") or site.get("down")) else "✅"


def error_lines(ctx):
    """Plain-text style list of everything that went wrong, site by site."""
    lines = []
    for s in ctx["sites"]:
        name = s.get("site") or ""
        if s.get("down"):
            lines.append((name, (s.get("notes") or ["Site unreachable"])[0]))
        for note in s.get("notes") or []:
            lines.append((name, note))
        for item in s.get("items") or []:
            lines.append((item.get("url", ""), item.get("problem", "")))
    return lines


def render_html(ctx):
    rows = "".join(
        f'<tr>'
        f'<td style="padding:11px 12px;border-bottom:1px solid #e5e5e5;font-size:14px;'
        f'color:#000;word-break:break-all;">{esc(s.get("site", ""))}</td>'
        f'<td align="right" style="padding:11px 12px;border-bottom:1px solid #e5e5e5;'
        f'font-size:16px;white-space:nowrap;">{status_mark(s)}</td>'
        f"</tr>"
        for s in ctx["sites"]
    )

    errors = error_lines(ctx)
    if errors:
        blocks = "".join(
            f'<div style="margin:0 0 14px;">'
            f'<div style="font-size:13px;color:#000;word-break:break-all;">{esc(where)}</div>'
            f'<div style="font-size:13px;line-height:1.6;color:#555;word-break:break-word;">'
            f'{esc(shorten(what, 300))}</div>'
            f"</div>"
            for where, what in errors
        )
        errors_html = (
            f'<div style="margin-top:26px;">'
            f'<div style="font-size:12px;font-weight:700;letter-spacing:1.4px;'
            f'text-transform:uppercase;color:#000;padding-bottom:8px;'
            f'border-bottom:1px solid #000;">Errors</div>'
            f'<div style="padding-top:14px;">{blocks}</div>'
            f"</div>"
        )
    else:
        errors_html = (
            '<div style="margin-top:26px;font-size:13px;color:#555;">'
            "No errors. Every page returned content.</div>"
        )

    # contact form on the homepage (only when the checks reported it)
    form_sites = [x for x in ctx["sites"] if x.get("home_form") is not None]
    forms_html = ""
    if form_sites:
        have = [x for x in form_sites if x.get("home_form")]
        missing = [x for x in form_sites if not x.get("home_form")]
        form_rows = [f'<div style="font-size:13px;color:#000;">'
                f'{len(have)} of {len(form_sites)} homepages have a contact form</div>']
        for x in missing:
            form_rows.append(
                f'<div style="margin:8px 0 0;font-size:13px;color:#000;">'
                f'{esc(x.get("site", ""))} &mdash; no contact form on the homepage</div>'
                f'<div style="margin:2px 0 0 14px;font-size:12px;color:#555;'
                f'word-break:break-all;">{esc(x.get("home_url", ""))}</div>'
            )
        forms_html = (
            '<div style="margin-top:26px;">'
            '<div style="font-size:12px;font-weight:700;letter-spacing:1.4px;'
            'text-transform:uppercase;color:#000;padding-bottom:8px;'
            'border-bottom:1px solid #000;">Contact form on homepage</div>'
            f'<div style="padding-top:14px;">{"".join(form_rows)}</div>'
            "</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(ctx['subject'])}</title>
</head>
<body style="margin:0;padding:0;background:#ffffff;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"
       style="width:100%;background:#ffffff;">
 <tr><td align="center" style="padding:24px 16px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
         style="width:100%;max-width:600px;border-collapse:collapse;
                font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">

   <tr><td style="padding-bottom:4px;">
     <div style="font-size:17px;font-weight:700;color:#000;letter-spacing:-.2px;">Website Monitor</div>
     <div style="font-size:12px;color:#555;margin-top:3px;">{esc(ctx['when'])}</div>
   </td></tr>

   <tr><td style="padding:10px 0 18px;">
     <div style="font-size:13px;color:#000;">
       {esc(ctx['sites_count'])} websites &middot; {ctx['pages']:,} pages checked &middot;
       {ctx['problems']} problem{'s' if ctx['problems'] != 1 else ''}
     </div>
   </td></tr>

   <tr><td>
     <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
            style="width:100%;border-collapse:collapse;border:1px solid #000;">
       <tr>
         <td style="padding:9px 12px;font-size:11px;font-weight:700;letter-spacing:1.2px;
                    text-transform:uppercase;color:#000;border-bottom:1px solid #000;">Website</td>
         <td align="right" style="padding:9px 12px;font-size:11px;font-weight:700;
                    letter-spacing:1.2px;text-transform:uppercase;color:#000;
                    border-bottom:1px solid #000;">Status</td>
       </tr>
       {rows}
     </table>
   </td></tr>

   <tr><td>{errors_html}</td></tr>
   <tr><td>{forms_html}</td></tr>

   <tr><td style="padding-top:26px;">
     <div style="border-top:1px solid #e5e5e5;padding-top:12px;font-size:11px;
                 line-height:1.7;color:#777;">
       site-working-check &middot; one email per hour
       {ctx['run_link']}
     </div>
   </td></tr>

  </table>
 </td></tr>
</table>
</body></html>"""


def render_text(ctx):
    lines = [ctx["subject"], "",
             f"{ctx['when']}",
             f"{ctx['sites_count']} websites, {ctx['pages']:,} pages checked, "
             f"{ctx['problems']} problem(s)", "",
             "WEBSITE                                  STATUS"]
    for s in ctx["sites"]:
        name = s.get("site", "")
        mark = status_mark(s)
        lines.append(f"{name:<40} {mark}")
    lines.append("")
    errors = error_lines(ctx)
    if errors:
        lines.append("ERRORS")
        for where, what in errors:
            lines.append(f"  {where}")
            lines.append(f"    {shorten(what, 300)}")
    else:
        lines.append("No errors. Every page returned content.")
    form_sites = [x for x in ctx["sites"] if x.get("home_form") is not None]
    if form_sites:
        have = [x for x in form_sites if x.get("home_form")]
        missing = [x for x in form_sites if not x.get("home_form")]
        lines += ["", "CONTACT FORM ON HOMEPAGE",
                  f"  {len(have)} of {len(form_sites)} homepages have a contact form"]
        for x in missing:
            lines.append(f"  {x.get('site','')} - no contact form on the homepage "
                         f"({x.get('home_url','')})")
    lines += ["", "-- ", "site-working-check" + (f" | {ctx['run_url']}" if ctx.get("run_url") else "")]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------
def parse_details(details):
    """Fallback for reports written by an older check_sites.py (no structured data)."""
    items = []
    current = None
    for raw in (details or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if stripped.startswith("X ") and "http" in stripped:
            parts = stripped[2:].split()
            url = next((p for p in parts if p.startswith("http")), stripped[2:])
            current = {"url": url, "problem": ""}
            items.append(current)
        elif current is not None and stripped and not stripped.startswith("X "):
            current["problem"] = (current["problem"] + " " + stripped).strip()
    return items


def build_context(reports, expected):
    sites = []
    for name in expected:
        r = reports.get(name)
        if r is None:
            sites.append({"site": name, "pages": 0, "problems": 1, "down": True,
                          "items": [], "notes": ["No report was produced - the check job "
                                                 "for this site crashed or timed out. See the "
                                                 "GitHub Actions log."]})
            continue
        payload = r.get("sites") or []
        if payload:
            for s in payload:
                sites.append({
                    "site": s.get("site") or s.get("url") or name,
                    "pages": s.get("pages", 0),
                    "problems": s.get("problems", 0),
                    "down": s.get("down", False),
                    "items": s.get("items") or [],
                    "notes": s.get("notes") or [],
                    "home_form": s.get("home_form"),
                    "home_url": s.get("home_url", ""),
                })
        else:                       # older report format
            p = r.get("problems", 0)
            sites.append({"site": name, "pages": r.get("pages", 0), "problems": p,
                          "down": False, "notes": [],
                          "items": parse_details(r.get("details", "")) if p else []})

    pages = sum(s["pages"] for s in sites)
    problems = sum(s["problems"] for s in sites)
    now = datetime.now(timezone.utc)
    ctx = {
        "sites": sites,
        "sites_count": len(sites),
        "pages": pages,
        "problems": problems,
        "sites_down": sum(1 for s in sites if s["down"]),
        "bad_sites": sum(1 for s in sites if s["problems"] or s["down"]),
        "when": now.strftime("%d %b %Y · %H:%M UTC"),
        "when_short": now.strftime("%d %b %H:%M UTC"),
        "run_url": (f"{os.getenv('GITHUB_SERVER_URL', 'https://github.com')}/"
                    f"{os.getenv('GITHUB_REPOSITORY', '')}/actions/runs/"
                    f"{os.getenv('GITHUB_RUN_ID', '')}"
                    if os.getenv("GITHUB_RUN_ID") else ""),
    }
    if ctx["run_url"]:
        ctx["run_link"] = (f'&nbsp;&middot;&nbsp;<a href="{esc(ctx["run_url"])}" '
                           f'style="color:{MUTED};">view run</a>')
    else:
        ctx["run_link"] = ""

    # subject
    stamp = ctx["when_short"]
    if ctx["sites_down"]:
        subject = f"❌ {ctx['sites_down']} site(s) unreachable · {stamp}"
    elif problems:
        bad = [s for s in sites if s["problems"]]
        if len(bad) == 1:
            subject = (f"❌ {problems} problem{'s' if problems != 1 else ''} on "
                       f"{bad[0]['site']} · {stamp}")
        else:
            subject = f"❌ {problems} problems on {len(bad)} websites · {stamp}"
    else:
        subject = f"✅ All {ctx['sites_count']} websites OK · {stamp}"
    ctx["subject"] = subject
    return ctx


# ---------------------------------------------------------------------------
# sending
# ---------------------------------------------------------------------------
def mask(address):
    """kumaresh252003@gmail.com -> kum********3@gmail.com (visible in a public repo)."""
    address = (address or "").strip()
    if "@" not in address:
        return address or "(empty)"
    local, _, domain = address.partition("@")
    if len(local) <= 6:
        return f"{local[:2]}***@{domain}"
    return f"{local[:3]}***{local[-3:]}@{domain}"


def write_step_summary(markdown):
    """Write to the GitHub job summary: visible on the run page, no log digging."""
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if path:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(markdown.rstrip() + "\n")
        except Exception:
            pass


def send_email(subject, text_body, html_body=None):
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "465"))
    user, pwd = os.environ["SMTP_USER"], os.environ["SMTP_PASS"]
    to = [x.strip() for x in os.environ["MAIL_TO"].split(",") if x.strip()]
    if not to:
        raise ValueError("MAIL_TO is empty - nothing to send to")

    if html_body:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))
    else:
        msg = MIMEText(text_body, "plain", "utf-8")

    msg["Subject"] = subject
    msg["From"] = user                     # plain address: looks like a normal mail, not bulk
    msg["To"] = ", ".join(to)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=(user.split("@")[-1] or "localhost"))
    msg["Auto-Submitted"] = "auto-generated"

    with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context()) as s:
        s.login(user, pwd)
        s.sendmail(user, to, msg.as_string())


# ---------------------------------------------------------------------------
# duplicate-run detection
# ---------------------------------------------------------------------------
def _api(path):
    base = os.getenv("GITHUB_API_URL", "https://api.github.com")
    token = os.environ["GITHUB_TOKEN"]
    req = urllib.request.Request(
        base + path,
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "site-working-check"},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def email_already_sent_this_hour():
    """True when an earlier run in the same clock hour already delivered the email."""
    repo = os.getenv("GITHUB_REPOSITORY")
    run_id = os.getenv("GITHUB_RUN_ID")
    if not (repo and run_id and os.getenv("GITHUB_TOKEN")):
        return False, "not running on GitHub Actions - dedupe skipped"

    try:
        my_run_id = int(run_id)
        started = datetime.now(timezone.utc)
        try:
            mine = _api(f"/repos/{repo}/actions/runs/{my_run_id}")
            if mine.get("created_at"):
                started = datetime.strptime(mine["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc)
        except Exception:
            pass
        hour_start = started.replace(minute=0, second=0, microsecond=0)
        since = hour_start.strftime("%Y-%m-%dT%H:%M:%SZ")
        runs = _api(f"/repos/{repo}/actions/runs?created=%3E%3D{since}&per_page=100").get(
            "workflow_runs", [])

        earlier = []
        for r in runs:
            rid = int(r.get("id", 0))
            created = r.get("created_at") or ""
            if rid >= my_run_id:
                continue
            if not created or created < since:
                continue
            earlier.append(r)
        earlier.sort(key=lambda r: int(r.get("id", 0)))

        for r in earlier:
            if r.get("status") != "completed":
                continue
            jobs = _api(f"/repos/{repo}/actions/runs/{r['id']}/jobs?per_page=100").get("jobs", [])
            for job in jobs:
                if job.get("name") == EMAIL_JOB_NAME and job.get("conclusion") == "success":
                    return True, (f"run {r['id']} ({r.get('created_at', '?')}) already sent "
                                  f"the email for this hour")
    except Exception as e:
        return False, (f"could not check for duplicates ({type(e).__name__}: {str(e)[:100]})"
                       " - sending anyway")

    if not earlier:
        return False, "first run of this hour"
    return False, f"no earlier run of this hour ({hour_start:%H}:00 UTC) sent an email"


# ---------------------------------------------------------------------------
def main():
    force = "--force" in sys.argv

    # --test: prove SMTP works, without waiting for an hourly run.
    if "--test" in sys.argv:
        to = os.getenv("MAIL_TO", "(MAIL_TO not set)")
        ctx = {"subject": "✅ Test email · Website Monitor",
               "sites": [{"site": "example.com", "pages": 12, "problems": 0,
                          "items": [], "notes": ["This is a test. No real check was run."]}],
               "sites_count": 1, "pages": 12, "problems": 0, "sites_down": 0, "bad_sites": 0,
               "when": datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC"),
               "when_short": datetime.now(timezone.utc).strftime("%d %b %H:%M UTC"),
               "run_url": "", "run_link": ""}
        try:
            send_email(ctx["subject"],
                       "Test email from Website Monitor.\n\nIf you received this, SMTP_USER, "
                       "SMTP_PASS and MAIL_TO are correct and the hourly reports will arrive too.",
                       render_html(ctx) if os.getenv("EMAIL_FORMAT", "html").lower() != "text"
                       else None)
            print(f"Test email sent from {os.getenv('SMTP_USER', '?')} to {to}")
            write_step_summary(f"## Test email: sent\nTo `{mask(os.getenv('MAIL_TO', ''))}` via "
                               f"{os.getenv('SMTP_HOST', 'smtp.gmail.com')}.\n\n"
                               "If it is not in your inbox, look in **Spam** - and check that "
                               "the `MAIL_TO` secret is exactly the address you are reading.")
        except KeyError as e:
            print(f"Test FAILED: environment variable {e} is missing in this job.")
            print("Add it under Settings -> Secrets and variables -> Actions.")
        except Exception as e:
            print(f"Test FAILED: {type(e).__name__}: {e}")
            print("Common causes: wrong app password, Gmail 2FA off, MAIL_TO empty, "
                  "SMTP port blocked.")
        return

    reports = {}
    for path in glob.glob("reports/*.json"):
        with open(path, encoding="utf-8") as f:
            r = json.load(f)
        reports[r["site"]] = r

    expected = [x.strip() for x in os.getenv("EXPECTED", "").split(",") if x.strip()]
    if not expected:
        expected = sorted(reports)

    ctx = build_context(reports, expected)

    if ctx["problems"]:
        pass
    elif os.getenv("SEND_OK_EMAIL", "false").lower() != "true":
        print("All good. No email sent (SEND_OK_EMAIL is not true).")
        write_step_summary("## Email: not sent\nNo problems found and `SEND_OK_EMAIL` is not true.")
        return

    # --- duplicate guard ---------------------------------------------------
    if not force and os.getenv("DEDUPE_HOUR", "true").lower() != "false":
        already, reason = email_already_sent_this_hour()
        if already:
            print(f"Duplicate email prevented: {reason}.")
            print("This run did not send anything. Re-run with --force to override.")
            write_step_summary(f"## Email: skipped (duplicate)\n{reason}\n\n"
                               "Set `DEDUPE_HOUR: \"false\"` or run with `force_email = true` "
                               "to send anyway.")
            return
        print(f"Dedupe check: {reason}.")

    text_body = render_text(ctx)
    use_html = os.getenv("EMAIL_FORMAT", "html").lower() != "text"
    html_body = render_html(ctx) if use_html else None

    recipient = os.getenv("MAIL_TO", "(MAIL_TO not set)")
    try:
        send_email(ctx["subject"], text_body, html_body)
        print(f"Email sent: {ctx['subject']}")
        print(f"  from {os.getenv('SMTP_USER', '?')} to {recipient}")
        write_step_summary(f"## Email: sent\n**{esc(ctx['subject'])}**\n\n"
                           f"Sent to `{mask(os.getenv('MAIL_TO', ''))}` via "
                           f"{os.getenv('SMTP_HOST', 'smtp.gmail.com')}.\n\n"
                           "If you cannot find it: check **Spam**, and check the `MAIL_TO` "
                           "secret above is exactly your address.")
    except KeyError as e:
        print(f"Email not sent: missing environment variable {e} "
              f"(set SMTP_USER, SMTP_PASS and MAIL_TO).")
        print("\n------------ report ------------\n" + text_body + "\n-------------------------------")
        write_step_summary(f"## Email: FAILED\nMissing secret `{e}`. Add it under "
                           "**Settings -> Secrets and variables -> Actions**.")
        sys.exit(1)
    except Exception as e:
        print(f"Email not sent: {type(e).__name__}: {str(e)[:200]}")
        print("\n------------ report ------------\n" + text_body + "\n-------------------------------")
        hint = ""
        msg = str(e).lower()
        if "authentication" in msg or "535" in msg or "credentials" in msg:
            hint = ("Gmail rejected the login: `SMTP_PASS` must be a 16-character **App "
                    "Password** (Google Account -> Security -> 2-Step Verification -> App "
                    "passwords), not your normal password.")
        elif "quota" in msg or "limit" in msg:
            hint = "Gmail sending limit reached for today."
        elif "timed out" in msg or "timeout" in msg or "disconnected" in msg:
            hint = "The SMTP connection was blocked or timed out (port 465)."
        write_step_summary(f"## Email: FAILED\n`{type(e).__name__}: {str(e)[:200]}`\n\n{hint}")
        sys.exit(1)


if __name__ == "__main__":
    main()
