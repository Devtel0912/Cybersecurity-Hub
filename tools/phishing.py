# tools/phishing.py
import re
from urllib.parse import urlparse
import ipaddress

Suspicious_Words = ['login','signin','secure','account','update','confirm','verify','paypal','bank']

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except:
        return False

def score_url(raw_url):
    """
    Mimics the previous API, returns:
        (score:int, details:str)
    """
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', raw_url):
        raw_url = 'http://' + raw_url
    try:
        p = urlparse(raw_url)
    except:
        return 0, "Invalid URL"

    host = p.hostname or ''
    path = p.path or ''
    query = p.query or ''
    href = p.geturl()

    score = 0
    details = []

    if p.username or p.password:
        details.append("Credentials in URL")
        score += 2
    if '@' in href:
        details.append("@ in URL")
        score += 1
    if is_ip(host):
        details.append("IP address used")
        score += 2
    if len(href) > 75:
        details.append("Long URL")
        score += 1
    if host.count('.') > 3:
        details.append("Many subdomains")
        score += 1
    if '-' in host:
        details.append("Hyphen in domain")
        score += 1
    if p.scheme == 'http':
        details.append("Not HTTPS")
        score += 1
    for w in Suspicious_Words:
        if w in path.lower() or w in query.lower():
            details.append(f"Suspicious word: {w}")
            score += 1

    score = min(score, 100)
    if not details:
        details.append("No obvious phishing signs detected")

    return score, ", ".join(details)
