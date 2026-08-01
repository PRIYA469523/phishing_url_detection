"""
Phishing URL Feature Extractor
--------------------------------
This script checks a given URL against 30 "clues" (features) used in the
UCI Phishing Websites Dataset to help decide if a URL looks like phishing
or looks safe.

For every feature:
    -1 = suspicious / phishing sign
     0 = in-between / unknown
     1 = safe / legitimate sign

NOTE: Some features (marked "HARD") need internet lookups (WHOIS, DNS, SSL,
traffic rank). Those are implemented where possible, and marked clearly
where a free/reliable data source is no longer available (e.g. Alexa rank
was shut down in 2022), so they return 0 (unknown) as a safe placeholder.
"""

import re
import socket
import ssl
from urllib.parse import urlparse

# Optional libraries - install with:
# pip install python-whois dnspython requests
try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns = None


# ---------------------------------------------------------------------
# 1. URL-BASED FEATURES (easy - just look at the URL text)
# ---------------------------------------------------------------------

def having_IP_Address(url):
    """Checks if the URL uses a raw IP address instead of a domain name."""
    ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
    return -1 if re.search(ip_pattern, url) else 1


def URL_Length(url):
    """Long URLs are often used to hide suspicious parts."""
    length = len(url)
    if length < 54:
        return 1
    elif length <= 75:
        return 0
    else:
        return -1


def Shortining_Service(url):
    """Checks if a known URL-shortening service was used."""
    shorteners = r"bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|is\.gd|buff\.ly"
    return -1 if re.search(shorteners, url) else 1


def having_At_Symbol(url):
    """Browsers ignore everything before '@', attackers abuse this."""
    return -1 if "@" in url else 1


def double_slash_redirecting(url):
    """Checks if '//' appears later in the path (not just after http:)."""
    last_slash_pos = url.rfind("//")
    return -1 if last_slash_pos > 7 else 1


def Prefix_Suffix(url):
    """Legit domains rarely use hyphens in the domain name."""
    domain = urlparse(url).netloc
    return -1 if "-" in domain else 1


def having_Sub_Domain(url):
    """Too many sub-domains/dots can disguise the real site."""
    domain = urlparse(url).netloc
    dot_count = domain.count(".")
    if dot_count <= 1:
        return 1
    elif dot_count == 2:
        return 0
    else:
        return -1


def HTTPS_token(url):
    """Checks if 'https' is inserted into the domain text itself (trick)."""
    domain = urlparse(url).netloc
    return -1 if "https" in domain.lower() else 1


def port(url):
    """Checks if the URL uses a non-standard port."""
    parsed = urlparse(url)
    if parsed.port and parsed.port not in (80, 443):
        return -1
    return 1


# ---------------------------------------------------------------------
# 2. MEDIUM FEATURES (need a network lookup: SSL, WHOIS, DNS)
# ---------------------------------------------------------------------

def SSLfinal_State(url):
    """Checks if the site has a valid HTTPS/SSL certificate."""
    try:
        domain = urlparse(url).netloc
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
        return 1  # valid cert found
    except Exception:
        return -1  # no valid HTTPS connection


def DNSRecord(url):
    """Checks whether the domain has a valid DNS record."""
    if dns is None:
        return 0  # library not installed
    try:
        domain = urlparse(url).netloc
        dns.resolver.resolve(domain, "A")
        return 1
    except Exception:
        return -1


def age_of_domain(url):
    """Checks how old the domain is (older = more trustworthy)."""
    if whois is None:
        return 0
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return -1
        from datetime import datetime
        age_days = (datetime.now() - creation_date).days
        return 1 if age_days > 180 else -1  # older than ~6 months = safer
    except Exception:
        return 0  # lookup failed, mark unknown


def Domain_registeration_length(url):
    """Checks how long until the domain registration expires."""
    if whois is None:
        return 0
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if expiration_date is None:
            return -1
        from datetime import datetime
        days_left = (expiration_date - datetime.now()).days
        return 1 if days_left > 365 else -1  # registered for over a year = safer
    except Exception:
        return 0


# ---------------------------------------------------------------------
# 3. HARD FEATURES (need external services no longer freely available,
#    e.g. Alexa rank was shut down in 2022). Return 0 = "unknown" for now.
#    These can be revisited later with a paid API or alternative source.
# ---------------------------------------------------------------------

def web_traffic(url):
    """Traffic/popularity rank - needs a paid API now (Alexa is defunct)."""
    return 0


def Page_Rank(url):
    """Google PageRank score - no longer publicly available."""
    return 0


def Google_Index(url):
    """Whether the page is indexed by Google - needs Search API access."""
    return 0


def Statistical_report(url):
    """Checks against phishing blacklists like PhishTank."""
    return 0  # placeholder - can be connected to PhishTank API later


# ---------------------------------------------------------------------
# MAIN FUNCTION - runs all the "easy" and "medium" detectives together
# ---------------------------------------------------------------------

def extract_features(url):
    soup, _ = get_soup(url)
    features = {
        "having_IP_Address": having_IP_Address(url),
        "URL_Length": URL_Length(url),
        "Shortining_Service": Shortining_Service(url),
        "having_At_Symbol": having_At_Symbol(url),
        "double_slash_redirecting": double_slash_redirecting(url),
        "Prefix_Suffix": Prefix_Suffix(url),
        "having_Sub_Domain": having_Sub_Domain(url),
        "HTTPS_token": HTTPS_token(url),
        "port": port(url),
        "SSLfinal_State": SSLfinal_State(url),
        "DNSRecord": DNSRecord(url),
        "age_of_domain": age_of_domain(url),
        "Domain_registeration_length": Domain_registeration_length(url),
        "web_traffic": web_traffic(url),
        "Page_Rank": Page_Rank(url),
        "Google_Index": Google_Index(url),
        "Statistical_report": Statistical_report(url),
        "Favicon": Favicon(url, soup),
        "Request_URL": Request_URL(url, soup),
        "URL_of_Anchor": URL_of_Anchor(url, soup),
        "Links_in_tags": Links_in_tags(url, soup),
        "SFH": SFH(url, soup),
        "Submitting_to_email": Submitting_to_email(url, soup),
        "Abnormal_URL": Abnormal_URL(url),
        "Redirect": Redirect(url),
        "on_mouseover": on_mouseover(url, soup),
        "RightClick": RightClick(url, soup),
        "popUpWidnow": popUpWidnow(url, soup),
        "Iframe": Iframe(url, soup),
        "Links_pointing_to_page": Links_pointing_to_page(url, soup),
    }
    return features

# ---------------------------------------------------------------------
# TEST IT YOURSELF - run this file directly to see it in action
# ---------------------------------------------------------------------

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login",
        "http://paypal-secure-login.fake-bank.com/@verify",
    ]

    for test_url in test_urls:
        print(f"\nChecking: {test_url}")
        result = extract_features(test_url)
        for feature_name, value in result.items():
            print(f"  {feature_name}: {value}")
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def get_soup(url):
    """Fetches page HTML once, reused by all HTML-based checks below."""
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        return BeautifulSoup(response.text, 'html.parser'), response
    except Exception:
        return None, None

def Favicon(url, soup=None):
    try:
        if soup is None:
            soup, _ = get_soup(url)
        if soup is None:
            return -1
        icon = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
        if icon and icon.get('href'):
            domain = urlparse(url).netloc
            icon_domain = urlparse(icon['href']).netloc
            if icon_domain and domain not in icon_domain:
                return -1
        return 1
    except Exception:
        return 0

def Request_URL(url, soup=None):
    try:
        if soup is None:
            soup, _ = get_soup(url)
        if soup is None:
            return -1
        domain = urlparse(url).netloc
        tags = soup.find_all(['img', 'video', 'audio'])
        total, external = 0, 0
        for tag in tags:
            src = tag.get('src')
            if src:
                total += 1
                if domain not in urlparse(src).netloc and urlparse(src).netloc != '':
                    external += 1
        if total == 0:
            return 1
        ratio = external / total
        return 1 if ratio < 0.3 else (0 if ratio < 0.6 else -1)
    except Exception:
        return 0

def URL_of_Anchor(url, soup=None):
    try:
        if soup is None:
            soup, _ = get_soup(url)
        if soup is None:
            return -1
        domain = urlparse(url).netloc
        anchors = soup.find_all('a', href=True)
        total, suspicious = 0, 0
        for a in anchors:
            href = a['href']
            total += 1
            if href.startswith('#') or href.lower().startswith('javascript:') or href == '':
                suspicious += 1
            elif domain not in urlparse(href).netloc and urlparse(href).netloc != '':
                suspicious += 1
        if total == 0:
            return 1
        ratio = suspicious / total
        return 1 if ratio < 0.3 else (0 if ratio < 0.6 else -1)
    except Exception:
        return 0

def Links_in_tags(url, soup=None):
    try:
        if soup is None:
            soup, _ = get_soup(url)
        if soup is None:
            return -1
        domain = urlparse(url).netloc
        tags = soup.find_all(['meta', 'script', 'link'])
        total, external = 0, 0
        for tag in tags:
            src = tag.get('src') or tag.get('href')
            if src:
                total += 1
                if domain not in urlparse(src).netloc and urlparse(src).netloc != '':
                    external += 1
        if total == 0:
            return 1
        ratio = external / total
        return 1 if ratio < 0.3 else (0 if ratio < 0.6 else -1)
    except Exception:
        return 0

def SFH(url, soup=None):
    try:
        if soup is None:
            soup, _ = get_soup(url)
        if soup is None:
            return -1
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if action == '' or action.lower() == 'about:blank':
                return -1
            domain = urlparse(url).netloc
            if domain not in urlparse(action).netloc and urlparse(action).netloc != '':
                return 0
        return 1
    except Exception:
        return 0

def Submitting_to_email(url, soup=None):
    try:
        if soup is None:
            soup, _ = get_soup(url)
        if soup is None:
            return -1
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if 'mailto:' in action.lower():
                return -1
        return 1
    except Exception:
        return 0

def Abnormal_URL(url):
    try:
        domain = urlparse(url).netloc
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        return 1 if domain in response.url else -1
    except Exception:
        return 0

def Redirect(url):
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        redirect_count = len(response.history)
        return 1 if redirect_count <= 1 else (0 if redirect_count <= 3 else -1)
    except Exception:
        return 0

def on_mouseover(url, soup=None):
    try:
        if soup is None:
            soup, _ = get_soup(url)
        if soup is None:
            return -1
        html = str(soup)
        return -1 if 'onmouseover' in html.lower() and 'window.status' in html.lower() else 1
    except Exception:
        return 0

def RightClick(url, soup=None):
    try:
        if soup is None:
            soup, _ = get_soup(url)
        if soup is None:
            return -1
        html = str(soup)
        return -1 if 'event.button==2' in html.lower() or 'contextmenu' in html.lower() else 1
    except Exception:
        return 0

def popUpWidnow(url, soup=None):
    try:
        if soup is None:
            soup, _ = get_soup(url)
        if soup is None:
            return -1
        html = str(soup)
        return -1 if 'alert(' in html.lower() or 'prompt(' in html.lower() else 1
    except Exception:
        return 0

def Iframe(url, soup=None):
    try:
        if soup is None:
            soup, _ = get_soup(url)
        if soup is None:
            return -1
        iframes = soup.find_all('iframe')
        return -1 if len(iframes) > 0 else 1
    except Exception:
        return 0

def Links_pointing_to_page(url, soup=None):
    try:
        if soup is None:
            soup, _ = get_soup(url)
        if soup is None:
            return 0
        links = soup.find_all('a', href=True)
        count = len(links)
        return 1 if count > 2 else (0 if count > 0 else -1)
    except Exception:
        return 0