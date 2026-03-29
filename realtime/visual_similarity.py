import difflib

# Official brand domains (VERY IMPORTANT)
BRAND_DOMAINS = {
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com"],
    "apple": ["apple.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com"],
    "linkedin": ["linkedin.com"],
    "netflix": ["netflix.com"],
    "openai": ["openai.com"],
    "github": ["github.com"],
    "wikipedia": ["wikipedia.org"],
    "whatsapp": ["whatsapp.com"],
    "zoom": ["zoom.us"],
    "cloudflare": ["cloudflare.com"],
    "adobe": ["adobe.com"],
    "oracle": ["oracle.com"],
    "ibm": ["ibm.com"],
    "salesforce": ["salesforce.com"],
    "reddit": ["reddit.com"],
}

HOMOGLYPHS = {
    "rn": "m",
    "0": "o",
    "1": "l",
    "I": "l",
    "|": "l",
    "5": "s",
    "$": "s",
    "@": "a",
    "3": "e",
    "8": "b",
    "9": "g",
}

def normalize_domain(domain: str) -> str:
    normalized = domain.lower()
    for k, v in HOMOGLYPHS.items():
        normalized = normalized.replace(k, v)
    return normalized

def is_legitimate_brand_domain(domain: str, brand: str) -> bool:
    for legit in BRAND_DOMAINS.get(brand, []):
        if domain.endswith(legit):
            return True
    return False

def check_visual_similarity(domain: str, threshold: float = 0.8):
    normalized = normalize_domain(domain)

    for brand in BRAND_DOMAINS.keys():
        similarity = difflib.SequenceMatcher(None, normalized, brand).ratio()

        if similarity >= threshold:
            # 🚫 Do NOT flag if it's the official domain
            if is_legitimate_brand_domain(domain, brand):
                return False, None, 0.0

            return True, brand, round(similarity, 2)

    return False, None, 0.0
