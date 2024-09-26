import os
import time
import logging
import smtplib
import threading

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from bs4 import BeautifulSoup

from framework import config


log = logging.getLogger(__name__)


def send_email_reports():
    """
    Email results of test run

    """
    time.sleep(20)
    mailids = config.ENV_DATA.get("email")
    recipients = []
    [recipients.append(mailid) for mailid in mailids.split(",")]
    sender = "ocs-ci@redhat.com"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "noobaa standalone results"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)

    html = config.ENV_DATA["html_path"]
    with open(os.path.expanduser(html)) as fd:
        html_data = fd.read()
    soup = BeautifulSoup(html_data, "html.parser")
    part1 = MIMEText(soup, "html")
    msg.attach(part1)
    try:
        s = smtplib.SMTP(config.REPORTING["email"]["smtp_server"])
        s.sendmail(sender, recipients, msg.as_string())
        s.quit()
        log.info(f"Results have been emailed to {recipients}")
    except Exception:
        log.exception("Sending email with results failed!")


def pytest_sessionfinish(session, exitstatus):
    """
    save session's report files and send email report
    """
    if config.ENV_DATA.get("email"):
        thread = threading.Thread(target=send_email_reports)
        thread.start()
    a = 1
