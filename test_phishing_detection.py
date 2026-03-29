"""Quick test of phishing detection fixing"""
from realtime.decision_engine import decide_phishing

test_urls = [
    "rnicrosoft.com",      # Look-alike typo
    "micr0soft.com",       # Look-alike with number
    "g00gle.com",          # Google lookalike
    "https://www.microsoft.com",  # Legitimate
    "https://www.google.com",     # Legitimate
]

print("Testing Phishing Detection:")
print("=" * 80)

for url in test_urls:
    result = decide_phishing(url)
    print(f"\nURL: {url}")
    print(f"  Result: {result['label']}")
    print(f"  Risk Score: {result['risk_score']}/100")
    print(f"  Confidence: {result['confidence']}%")
    print(f"  ML Prediction: {result['ml_prediction']}")
    print(f"  Reasons: {', '.join(result['reasons']) if result['reasons'] else 'None'}")
