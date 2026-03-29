"""Debug the actual decision engine"""
from realtime.feature_extractor import extract_url_features
from realtime.decision_engine import extract_domain, decide_phishing, BRANDS
from difflib import SequenceMatcher

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

url = "rnicrosoft.com"
print(f"Testing URL: {url}")

# Check domain extraction
domain = extract_domain(url)
print(f"Extracted domain: '{domain}'")

# Check which brand would match
print(f"\nBrand matching:")
for brand in BRANDS:
    sim = similarity(domain, brand)
    contains = brand in domain.lower()
    if sim > 0.6 or contains:
        print(f"  {brand}: similarity={sim:.2%}, contains={contains}")

# Check actual detection
result = decide_phishing(url)
print(f"\nActual result:")
print(f"  Label: {result['label']}")
print(f"  Risk Score: {result['risk_score']}")
print(f"  Reasons: {result['reasons']}")
