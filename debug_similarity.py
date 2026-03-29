"""Debug look-alike detection"""
from difflib import SequenceMatcher

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

# Test similarity
domain_to_check = "rnicrosoft"
brand = "microsoft"

sim = similarity(domain_to_check, brand)
brand_in_domain = brand in domain_to_check

print(f"Domain: {domain_to_check}")
print(f"Brand: {brand}")
print(f"Similarity: {sim:.2%}")
print(f"Brand in domain: {brand_in_domain}")
print(f"Would trigger: {(sim >= 0.7 or brand_in_domain) and domain_to_check != brand}")
