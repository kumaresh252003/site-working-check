#!/usr/bin/env python3
"""Reads the per-site results saved by each check job and sends ONE combined email.

DUPLICATE-EMAIL GUARD
---------------------
You trigger this workflow from cron-job.org. If anything makes it start twice in the
same hour - a retry from the cron service, a double trigger, a manual re-run after a
failure, two cron entries - two runs would each send an email.

Before sending, this script asks GitHub whether an EARLIER run in the same hour
already completed its "send combined email" job successfully. If one did, this run
prints that and exits without emailing. So you get exactly one email per hour, always
from the first run of that hour.

It fails safe: if the GitHub API cannot be asked (no token, rate limit, network), the
email is sent rather than silently skipped.

Environment (all provided by GitHub Actions automatically):
    GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_API_URL
Set DEDUPE_HOUR=false to turn the guard off; pass --force to send anyway.
"""
import glob
import json
import os
import smtplib
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.mime.text import MIMEText

EMAIL_JOB_NAME = "send combined email"      # must match the job name in the workflow
# Runs are grouped by the clock hour they started in (UTC). A run repeated inside the
# same hour is a duplicate; a run in a new hour is a new report - even if the previous
# one started only 59 minutes ago. That avoids skipping a legitimate hourly email.


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


# ---------------------------------------------------------------------------
# duplicate-run detection
# ---------------------------------------------------------------------------
def _api(path):
    """GET a GitHub API path, return parsed JSON. Raises on failure."""
    base = os.getenv("GITHUB_API_URL", "https://api.github.com")
    token = os.environ["GITHUB_TOKEN"]
    req = urllib.request.Request(
        base + path,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "site-working-check",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def email_already_sent_this_hour():
    """True when an earlier run in the last hour already delivered the email.

    Returns (bool, reason_string).
    """
    repo = os.getenv("GITHUB_REPOSITORY")
    run_id = os.getenv("GITHUB_RUN_ID")
    if not (repo and run_id and os.getenv("GITHUB_TOKEN")):
        return False, "not running on GitHub Actions - dedupe skipped"

    try:
        my_run_id = int(run_id)

        # Which hour does MY run belong to? Use the run's own start time, not "now",
        # so a long check that finishes in the next hour is still grouped correctly.
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

        # Only runs that started inside MY hour, and only older ones. Verified locally
        # as well as with the API filter: never rely on a server-side filter alone for
        # a decision that decides whether an alert email is sent.
        earlier = []
        for r in runs:
            rid = int(r.get("id", 0))
            created = r.get("created_at") or ""
            if rid >= my_run_id:
                continue
            if not created or created < since:      # ISO-8601 Z timestamps sort as strings
                continue
            earlier.append(r)
        earlier.sort(key=lambda r: int(r.get("id", 0)))

        for r in earlier:
            if r.get("status") != "completed":
                # still running: it may send the email itself, we cannot know yet.
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

    # --test: prove that SMTP_USER / SMTP_PASS / MAIL_TO work, without waiting for an
    # hourly run. Used by the "test_email" input of the workflow.
    if "--test" in sys.argv:
        to = os.getenv("MAIL_TO", "(MAIL_TO not set)")
        try:
            send_email("TEST: website monitor email",
                       "Test email from the website monitor.\n\n"
                       "If you received this, SMTP_USER, SMTP_PASS and MAIL_TO are correct "
                       "and the hourly reports will arrive too.")
            print(f"Test email sent from {os.getenv('SMTP_USER', '?')} to {to}")
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
    sites = expected or sorted(reports)

    total_pages = total_problems = 0
    summary, details = [], []
    for site in sites:
        r = reports.get(site)
        if r is None:
            total_problems += 1
            summary.append(f"  [!!]  {site}: NO REPORT (the check job crashed - see GitHub Actions log)")
            continue
        total_pages += r["pages"]
        total_problems += r["problems"]
        flag = "OK" if r["problems"] == 0 else "!!"
        summary.append(f"  [{flag}]  {site}: {r['pages']} pages, {r['problems']} problem(s)")
        if r["problems"]:
            details.append(r["details"])

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = (f"Website check at {now}\n"
            f"Total pages: {total_pages}   Total problems: {total_problems}\n\n"
            "SUMMARY\n" + "\n".join(summary) + "\n")
    if details:
        body += "\nDETAILS\n\n" + "\n".join(details)

    if total_problems:
        subject = f"ALERT: {total_problems} problem(s) across your websites"
    else:
        subject = "OK: all websites are working"
        if os.getenv("SEND_OK_EMAIL", "false").lower() != "true":
            print("All good. No email sent (SEND_OK_EMAIL is not true).")
            return

    # --- duplicate guard ---------------------------------------------------
    if not force and os.getenv("DEDUPE_HOUR", "true").lower() != "false":
        already, reason = email_already_sent_this_hour()
        if already:
            print(f"Duplicate email prevented: {reason}.")
            print("This run did not send anything. Re-run with --force to override.")
            return
        print(f"Dedupe check: {reason}.")
    # -----------------------------------------------------------------------

    try:
        send_email(subject, body)
        print(f"Email sent: {subject}")
    except KeyError as e:
        print(f"Email not sent: missing environment variable {e} "
              f"(set SMTP_USER, SMTP_PASS and MAIL_TO).")
        print("\n------------ report ------------\n" + body + "\n-------------------------------")
    except Exception as e:
        print(f"Email not sent: {type(e).__name__}: {str(e)[:200]}")
        print("\n------------ report ------------\n" + body + "\n-------------------------------")


if __name__ == "__main__":
    main()
