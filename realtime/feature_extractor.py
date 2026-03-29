import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "paypal", "signin", "confirm"
]

def extract_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return parsed.netloc.lower()

def extract_url_features(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    features = {}
    features["url_length"] = len(url)
    features["has_ip"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", domain) else 0
    features["has_https"] = 1  # browsers auto-upgrade
    features["num_subdomains"] = domain.count(".") - 1
    features["num_special_chars"] = sum(not c.isalnum() for c in url)
    features["has_suspicious_words"] = int(
        any(word in url.lower() for word in SUSPICIOUS_WORDS)
    )
    features["domain_length"] = len(domain)
    features["path_length"] = len(parsed.path)

    return features
