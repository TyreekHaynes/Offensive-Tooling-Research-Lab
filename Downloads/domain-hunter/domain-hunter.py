import socket
import sys
import requests
import whois
from datetime import datetime

# Configuration & Wordlists for Variations
PREFIXES = ["get", "try", "use", "go", "my", "join", "the", "meet"]
SUFFIXES = ["app", "hq", "hub", "lab", "io", "net", "pro", "co"]
TLDS = [".com", ".net", ".io", ".co"]

def generate_domain_ideas(keyword):
    """Generates a list of targeted domain variations based on a seed keyword."""
    clean_kw = keyword.lower().strip().replace(" ", "")
    domains = set()
    
    for tld in TLDS:
        domains.add(f"{clean_kw}{tld}")
        
    for prefix in PREFIXES:
        for tld in TLDS:
            domains.add(f"{prefix}{clean_kw}{tld}")
            
    for suffix in SUFFIXES:
        for tld in TLDS:
            domains.add(f"{clean_kw}{suffix}{tld}")
            
    return list(domains)
    
def perform_recon(domain):
    """
    Performs DNS resolution, WHOIS lookup, and HTTP probing for comprehensive recon.
    """
    result = {
        "domain": domain,
        "status": "AVAILABLE",
        "creation_date": None,
        "http_status": None
    }
    
    # 1. DNS Check
    try:
        socket.gethostbyname(domain)
        result["status"] = "TAKEN"
    except socket.gaierror:
        return result

    # 2. WHOIS Lookup for registered domains
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        result["creation_date"] = creation
    except Exception:
        result["creation_date"] = "Unknown"

    # 3. HTTP/HTTPS Probing to check live web servers
    for scheme in ["https://", "http://"]:
        try:
            resp = requests.get(scheme + domain, timeout=3, allow_redirects=True)
            result["http_status"] = resp.status_code
            break
        except requests.RequestException:
            result["http_status"] = "No Web Server / Timed Out"

    return result

def hunt_domains(keyword):
    print(f"\n[*] Starting domain recon for: '{keyword}'...")
    candidates = generate_domain_ideas(keyword)
    print(f"[*] Generated {len(candidates)} variations. Executing DNS, WHOIS, and HTTP probes...\n")
    
    results = {"AVAILABLE": [], "TAKEN": []}
    
    for domain in sorted(candidates):
        data = perform_recon(domain)
        if data["status"] == "AVAILABLE":
            print(f"  [+] {domain} --> AVAILABLE / UNREGISTERED")
            results["AVAILABLE"].append(domain)
        else:
            print(f"  [-] {domain} --> TAKEN | Created: {data['creation_date']} | HTTP: {data['http_status']}")
            results["TAKEN"].append(data)
            
    print("\n" + "="*60)
    print(f" RECON COMPLETE: Found {len(results['AVAILABLE'])} open targets.")
    print("="*60)
    
    return results

if __name__ == "__main__":
    target_keyword = "target"
    if len(sys.argv) > 1:
        target_keyword = sys.argv[1]
        
    hunt_domains(target_keyword)
