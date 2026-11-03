#!/usr/bin/env python3
"""Reads the per-site results saved by each check job and sends ONE combined email."""
import glob
import json
import os
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.text import MIMEText


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


def main():
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
        send_email(f"ALERT: {total_problems} problem(s) across your websites", body)
        print("Combined alert email sent.")
    elif os.getenv("SEND_OK_EMAIL", "false").lower() == "true":
        send_email("OK: all websites are working", body)
        print("Combined OK email sent.")
    else:
        print("All good. No email sent.")


if __name__ == "__main__":
    main()
