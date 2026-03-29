KNOWN_BRANDS = [
    "google", "microsoft", "paypal", "facebook",
    "amazon", "apple", "instagram"
]

def check_domain_reputation(domain: str) -> dict:
    brand_hit = None
    for brand in KNOWN_BRANDS:
        if brand in domain:
            brand_hit = brand
            break

    return {
        "suspicious": brand_hit is not None,
        "brand": brand_hit
    }
