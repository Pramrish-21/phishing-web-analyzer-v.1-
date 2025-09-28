
import urllib.parse
import ipaddress
import re
from typing import Dict, Any

# Define a baseline threshold for scoring. Higher scores indicate more potential risk.
RISK_THRESHOLD = 3

def is_ip_address(hostname: str) -> bool:
    """
    Checks if the hostname part of a URL is an IP address.
    Phishing sites sometimes use raw IP addresses to host pages.
    """
    # Remove port if present (e.g., 192.168.1.1:8080)
    if ':' in hostname:
        hostname = hostname.split(':')[0]
    
    # Check for IPv4
    try:
        ipaddress.IPv4Address(hostname)
        return True
    except ipaddress.AddressValueError:
        pass
    
    # Check for IPv6
    try:
        ipaddress.IPv6Address(hostname)
        return True
    except ipaddress.AddressValueError:
        return False

def check_url_for_phishing_indicators(url: str) -> Dict[str, Any]:
    """
    Analyzes a URL for common technical indicators associated with phishing attempts.

    Args:
        url: The URL string to analyze.

    Returns:
        A dictionary containing the analysis results, score, and verdict.
    """
    
    # --- 1. Initialize Results and Score ---
    analysis = {
        'url': url,
        'risk_score': 0,
        'verdict': 'LOW RISK',
        'indicators': []
    }
    
    # Basic check for empty or non-URL-like input
    if not url or not url.strip().startswith(('http://', 'https://')):
        analysis['verdict'] = 'INVALID INPUT'
        analysis['indicators'].append({'flag': 'SYNTAX_ERROR', 'description': 'Input must be a valid URL starting with http:// or https://'})
        return analysis

    try:
        # --- 2. Parse the URL ---
        parsed_url = urllib.parse.urlparse(url)
        scheme = parsed_url.scheme
        netloc = parsed_url.netloc # Hostname and port (e.g., www.google.com:443)
        path = parsed_url.path
        
        hostname = netloc.split(':')[0]

        # --- 3. Check for HTTPS (Security) ---
        if scheme != 'https':
            analysis['risk_score'] += 2
            analysis['indicators'].append({
                'flag': 'NO_HTTPS',
                'description': f'Uses insecure "{scheme}" scheme instead of HTTPS.',
                'impact': 2
            })

        # --- 4. Check for IP Address in Hostname ---
        if is_ip_address(hostname):
            analysis['risk_score'] += 3
            analysis['indicators'].append({
                'flag': 'IP_ADDRESS_HOST',
                'description': f'The hostname is a raw IP address ({hostname}), common in temporary phishing links.',
                'impact': 3
            })
            
        # --- 5. Check for Excessive Subdomains (Heuristic) ---
        # A legitimate domain typically has 2 or 3 parts (e.g., 'www.google.com' -> 3 parts)
        # Excessive subdomains (e.g., login.security.update.amazon.com) are often used to hide the true domain.
        domain_parts = hostname.split('.')
        # Count parts after removing 'www', 'm', etc. and checking for TLD
        effective_parts = [p for p in domain_parts if p and p.lower() not in ['www', 'm']]
        if len(effective_parts) > 3: 
            analysis['risk_score'] += 2
            analysis['indicators'].append({
                'flag': 'EXCESSIVE_SUBDOMAINS',
                'description': f'Too many effective domain parts ({len(effective_parts)}). Hostname complexity is a common obfuscation tactic.',
                'impact': 2
            })
            
        # --- 6. Check for Misleading Characters (e.g., @ symbol) ---
        # Attackers use the '@' symbol in the URL to confuse the user about the actual host.
        # e.g., https://safe.com@attacker.com/login (The true host is attacker.com)
        if '@' in netloc:
            # The '@' is a massive red flag because it changes the effective domain being visited
            analysis['risk_score'] += 4
            analysis['indicators'].append({
                'flag': 'MISLEADING_AT_SYMBOL',
                'description': 'The "@" symbol is present, which is used to mask the true domain name (the host is after the @).',
                'impact': 4
            })
            
        # --- 7. Check for Long Path or Query (Obfuscation) ---
        if len(path) > 70 or len(parsed_url.query) > 70:
            analysis['risk_score'] += 1
            analysis['indicators'].append({
                'flag': 'LONG_PATH_OR_QUERY',
                'description': 'The URL path or query string is unusually long (>70 chars), potentially used for obfuscation.',
                'impact': 1
            })
            
        # --- 8. Check for common phishing keywords in the hostname ---
        suspicious_keywords = ['login-', '-secure', 'paypal-verify', 'amazon-support', 'microsoft-live', 'webmail-update']
        if any(keyword in hostname for keyword in suspicious_keywords):
             analysis['risk_score'] += 3
             analysis['indicators'].append({
                'flag': 'SUSPICIOUS_KEYWORDS',
                'description': 'The hostname contains high-risk keywords (e.g., "login-", "paypal-verify") often used in fake domains.',
                'impact': 3
            })

    except Exception as e:
        analysis['verdict'] = 'ERROR'
        analysis['indicators'].append({'flag': 'PROCESSING_ERROR', 'description': f'Failed to parse or process URL: {e}'})
        return analysis


    # --- 9. Final Verdict ---
    if analysis['risk_score'] >= RISK_THRESHOLD:
        analysis['verdict'] = 'HIGH RISK (Potential Phishing Indicators Found)'
    
    return analysis

def display_results(results: Dict[str, Any]):
    """Prints the analysis results in a clean, readable format."""
    
    print("\n" + "=" * 50)
    print(f"  URL ANALYSIS REPORT  ")
    print(f"  URL: {results['url']}")
    print("=" * 50)
    
    verdict_color = '\033[91m' if results['verdict'].startswith('HIGH RISK') else '\033[92m' if results['verdict'].startswith('LOW RISK') else '\033[93m'
    
    print(f"Final Verdict: {verdict_color}\033[1m{results['verdict']}\033[0m")
    print(f"Total Risk Score: {results['risk_score']} (Threshold: {RISK_THRESHOLD})")
    print("-" * 50)
    
    if results['indicators']:
        print("\033[4mFound Indicators:\033[0m")
        for indicator in results['indicators']:
            print(f"  [FLAG: {indicator['flag']}] (Impact: +{indicator['impact']})")
            print(f"  Description: {indicator['description']}")
            print("-" * 20)
    else:
        print("No specific technical phishing indicators were detected.")
        
    print("-" * 50)

# --- Main Execution Loop ---
if __name__ == "__main__":
    
    print("\n" + "#" * 50)
    print("# Python Phishing Indicator Checker (Educational) #")
    print("#" * 50 + "\n")
    print("Enter 'exit' or 'quit' at any time to stop the scanner.")
    
    while True:
        try:
            user_input = input("\nEnter a URL to scan (e.g., https://www.google.com): ").strip()
            
            if user_input.lower() in ['exit', 'quit']:
                print("\nExiting the scanner. Stay safe!\n")
                break
                
            if not user_input:
                continue

            analysis_result = check_url_for_phishing_indicators(user_input)
            display_results(analysis_result)

        except KeyboardInterrupt:
            print("\nExiting the scanner. Stay safe!\n")
            break
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}")
            
    print("\nDisclaimer: This tool is for educational purposes and checks basic structural features. It is not a guaranteed anti-phishing solution.")
