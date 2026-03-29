import whois
from datetime import datetime

def get_domain_age(domain: str) -> int:
    """Get domain age in days. Returns 0 if age cannot be determined (suspicious)."""
    try:
        # Extract domain without www
        clean_domain = domain.replace("www.", "").split("/")[0]
        
        data = whois.whois(clean_domain)
        creation = data.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            age = (datetime.now() - creation).days
            return max(0, age)  # Return 0 if somehow negative
            
    except Exception as e:
        # Return 0 for unknown domains (treated as suspicious/new)
        pass

    return 0  # Default: treat as very new domain (suspicious)
