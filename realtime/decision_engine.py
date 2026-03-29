from urllib.parse import urlparse
from difflib import SequenceMatcher
from pathlib import Path
import joblib
import numpy as np
import socket   

from realtime.feature_extractor import extract_url_features
from realtime.reputation import check_domain_reputation
from realtime.whois_check import get_domain_age


# Load ML model and scaler
BASE_DIR = Path(__file__).resolve().parent.parent
model = joblib.load(BASE_DIR / "models" / "phishing_model.pkl")
try:
    scaler = joblib.load(BASE_DIR / "models" / "scaler.pkl")
except:
    scaler = None  # Fallback if scaler not available


TRUSTED_DOMAINS = {
    "google.com", "www.google.com",
    "youtube.com", "www.youtube.com",
    "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com",
    "twitter.com", "www.twitter.com",
    "linkedin.com", "www.linkedin.com",
    "amazon.com", "www.amazon.com",
    "apple.com", "www.apple.com",
    "microsoft.com", "www.microsoft.com",
    "netflix.com", "www.netflix.com",
    "openai.com", "www.openai.com",
    "github.com", "www.github.com",
    "paypal.com", "www.paypal.com",
    "wikipedia.org", "www.wikipedia.org",
    "whatsapp.com", "www.whatsapp.com",
    "zoom.us", "www.zoom.us",
    "cloudflare.com", "www.cloudflare.com",
    "adobe.com", "www.adobe.com",
    "oracle.com", "www.oracle.com",
    "ibm.com", "www.ibm.com",
    "salesforce.com", "www.salesforce.com",
    "reddit.com", "www.reddit.com",
    "spotify.com", "www.spotify.com",
    "dropbox.com", "www.dropbox.com",
    "tcs.com","www.tcs.com",
    "slack.com", "www.slack.com",
    "shopify.com", "www.shopify.com",
}


BRANDS = [
    "google", "youtube", "facebook", "instagram", "twitter",
    "linkedin", "amazon", "apple", "microsoft", "netflix",
    "openai", "github", "paypal", "wikipedia", "whatsapp",
    "zoom", "cloudflare", "adobe", "oracle", "ibm",
    "salesforce", "reddit", "spotify", "dropbox",
    "slack", "shopify"
]


def extract_domain(url):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    return parsed.netloc.lower()


def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()


def normalize_domain(domain):
    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "8": "b",
        "9": "g",
        "4": "a",
        "6": "b",
        "7": "t",
        "2": "z",
        "@": "a"
    }

    for k, v in replacements.items():
        domain = domain.replace(k, v)

    return domain


# =========================
# GET IP ADDRESS (ADDED)
# =========================

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unknown"


# =========================
# MACHINE LEARNING PREDICTION
# =========================

def ml_predict(features):

    feature_vector = [0] * 30

    feature_vector[0] = int(features.get("has_ip", 0))
    feature_vector[1] = int(features.get("url_length", 0) > 75)
    feature_vector[2] = int(features.get("num_special_chars", 0) > 3)
    feature_vector[3] = int(features.get("num_subdomains", 0) > 2)
    feature_vector[4] = int(not features.get("has_https", True))

    X = np.array(feature_vector).reshape(1, -1)

    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0]

    confidence = round(max(probability) * 100, 2)

    if prediction == 0:
        label = "PHISHING"
    else:
        label = "LEGITIMATE"

    return label, confidence


# =========================
# MAIN ENGINE
# =========================

def decide_phishing(url):

    # Clean the URL first (remove extra spaces)
    url = url.strip()
    
    reasons = []
    rule_score = 0

    domain = extract_domain(url)

    ip = get_ip(domain)           
    age = get_domain_age(domain) 


    # Trusted domain
    if domain in TRUSTED_DOMAINS:

        return {
            "url": url,
            "is_phishing": False,
            "label": "LEGITIMATE",
            "risk_score": 0,
            "confidence": 100,
            "rule_score": 0,
            "ml_prediction": "LEGITIMATE",
            "ml_confidence": 100,
            "reasons": ["Trusted global domain"],
            "ip": ip,        
            "age": age      
        }

    features = extract_url_features(url)

    # Rule checks

    if not features.get("has_https", True):
        rule_score += 10
        reasons.append("No HTTPS")

    if features.get("num_special_chars", 0) > 3:
        rule_score += 15
        reasons.append("Excessive special characters")

    reputation = check_domain_reputation(domain)

    if reputation.get("suspicious", False):
        rule_score += 10
        reasons.append("Low domain reputation")

    # Check domain age - 0 means unknown/unavailable (suspicious)
    if age is None or age == 0 or age < 180:
        rule_score += 15
        if age == 0 or age is None:
            reasons.append("Domain age unknown or unavailable")
        else:
            reasons.append("Very new domain")

    # Look alike detection - improved logic for typos and substitutions
    # Extract domain name without TLD for better matching
    domain_name_only = domain.split('.')[0]  # Get part before .com/.net/etc
    normalized = normalize_domain(domain_name_only)
    
    lookalike_found = False
    for brand in BRANDS:
        # Check similarity directly (catches typos like rnicrosoft vs microsoft)
        sim = similarity(normalized, brand)
        
        # More aggressive: catch typos (65%+ similarity on domain name)
        if sim >= 0.65:
            rule_score += 35
            reasons.append(f"Look-alike domain detected (impersonates {brand})")
            lookalike_found = True
            break

    # ML prediction
    ml_label, ml_confidence = ml_predict(features)

    # Final decision
    if rule_score >= 50 or ml_label == "PHISHING":
        label = "PHISHING"
        # Calculate confidence: if rule-based detected, high confidence
        if rule_score >= 50:
            confidence = min(95, ml_confidence + 10)
        else:
            confidence = ml_confidence
    else:
        label = "LEGITIMATE"
        confidence = 100 - min(ml_confidence * 0.3, 30)  # Lower confidence = suspicious

    # Calculate overall risk score (0-100)
    risk_score = round(min(rule_score * 1.5 + (100 - ml_confidence) * 0.3, 100), 2)

    return {
        "url": url,
        "is_phishing": label == "PHISHING",
        "label": label,
        "risk_score": risk_score,
        "confidence": round(confidence, 2),
        "rule_score": rule_score,
        "ml_prediction": ml_label,
        "ml_confidence": ml_confidence,
        "reasons": reasons,
        "ip": ip,      
        "age": age     
    }
