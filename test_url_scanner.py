"""
Comprehensive URL Scanner Test Suite
Tests all URL categories against the trained ML model
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.predictor import get_predictor
from ml.feature_engineering.url_features import URLFeatureExtractor

def print_result(url, result, category):
    """Print formatted test result"""
    print(f"\n{'='*70}")
    print(f"Category: {category}")
    print(f"URL: {url}")
    print(f"{'='*70}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Trust Score: {100 - result['score']}")
    print(f"Phishing Probability: {result['phishing_probability']:.2%}")
    print(f"\nExplanation:")
    print(f"  {result['explanation']}")
    
    if result.get('indicators'):
        print(f"\nIndicators:")
        for indicator in result['indicators']:
            icon = '✓' if indicator['type'] == 'positive' else '⚠' if indicator['type'] == 'warning' else '❌'
            print(f"  {icon} {indicator['message']}")
    
    print(f"\nFeatures:")
    if 'features' in result and result['features']:
        features = result['features']
        print(f"  URL Length: {features.get('url_length', 'N/A')}")
        print(f"  Domain Length: {features.get('domain_length', 'N/A')}")
        print(f"  Has HTTPS: {'Yes' if features.get('has_https') else 'No'}")
        print(f"  Suspicious Keywords: {features.get('suspicious_keywords_count', 0)}")
        print(f"  Subdomain Count: {features.get('subdomain_count', 0)}")
        print(f"  Has IP Address: {'Yes' if features.get('has_ip_address') else 'No'}")

def run_tests():
    """Run all URL test categories"""
    predictor = get_predictor()
    
    print("\n" + "="*70)
    print("PHISHSHIELD URL SCANNER - COMPREHENSIVE TEST SUITE")
    print("="*70)
    
    # 1. Safe URLs (Legitimate Websites)
    print("\n" + "="*70)
    print("1️⃣  SAFE URLs (LEGITIMATE WEBSITES)")
    print("="*70)
    
    safe_urls = [
        "https://google.com",
        "https://github.com",
        "https://amazon.com",
        "https://wikipedia.org",
        "https://microsoft.com",
        "https://stackoverflow.com",
        "https://openai.com",
        "https://linkedin.com"
    ]
    
    for url in safe_urls:
        result = predictor.predict_url(url)
        print_result(url, result, "Safe URL")
    
    # 2. Suspicious URLs (Medium Risk)
    print("\n" + "="*70)
    print("2️⃣  SUSPICIOUS URLs (MEDIUM RISK)")
    print("="*70)
    
    suspicious_urls = [
        "http://login-account-update.com",
        "http://secure-check-verification.net",
        "http://verify-account-update.org",
        "http://bank-login-check-security.com",
        "http://account-confirmation-service.info"
    ]
    
    for url in suspicious_urls:
        result = predictor.predict_url(url)
        print_result(url, result, "Suspicious URL")
    
    # 3. Phishing-Style URLs (High Risk)
    print("\n" + "="*70)
    print("3️⃣  PHISHING-STYLE URLs (HIGH RISK)")
    print("="*70)
    
    phishing_urls = [
        "http://paypal-security-update-login.com",
        "http://amazon-payment-verification.xyz",
        "http://google-account-recovery-login.net",
        "http://facebook-login-security-check.com",
        "http://apple-id-confirmation-update.info"
    ]
    
    for url in phishing_urls:
        result = predictor.predict_url(url)
        print_result(url, result, "Phishing URL")
    
    # 4. URLs with Suspicious Characters
    print("\n" + "="*70)
    print("4️⃣  URLs WITH SUSPICIOUS CHARACTERS")
    print("="*70)
    
    suspicious_char_urls = [
        "http://paypal@secure-login.com",
        "http://login-paypal.secure-check.com",
        "http://bank-login-security-update-confirm.net",
        "http://secure.verify.account.update.com"
    ]
    
    for url in suspicious_char_urls:
        result = predictor.predict_url(url)
        print_result(url, result, "Suspicious Characters")
    
    # 5. IP Address URLs
    print("\n" + "="*70)
    print("5️⃣  IP ADDRESS URLs")
    print("="*70)
    
    ip_urls = [
        "http://192.168.1.10/login",
        "http://185.234.219.12/verify",
        "http://103.21.244.10/bank"
    ]
    
    for url in ip_urls:
        result = predictor.predict_url(url)
        print_result(url, result, "IP Address URL")
    
    # 6. Very Long URLs
    print("\n" + "="*70)
    print("6️⃣  VERY LONG URLs")
    print("="*70)
    
    long_urls = [
        "http://paypal-security-update-login-confirm-account-verify-now.com/login/account/update",
        "http://amazon-account-verify-security-update-confirmation-required-login-secure.com/check"
    ]
    
    for url in long_urls:
        result = predictor.predict_url(url)
        print_result(url, result, "Very Long URL")
    
    # 7. URLs with Fake Subdomains
    print("\n" + "="*70)
    print("7️⃣  URLs WITH FAKE SUBDOMAINS")
    print("="*70)
    
    fake_subdomain_urls = [
        "http://paypal.com.login.verify-account-update.com",
        "http://amazon.com.verify-account.secure-update.info",
        "http://google.com.account-recovery.verify-login.net"
    ]
    
    for url in fake_subdomain_urls:
        result = predictor.predict_url(url)
        print_result(url, result, "Fake Subdomain")
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    all_test_urls = {
        "Safe URLs": safe_urls,
        "Suspicious URLs": suspicious_urls,
        "Phishing URLs": phishing_urls,
        "Suspicious Character URLs": suspicious_char_urls,
        "IP Address URLs": ip_urls,
        "Long URLs": long_urls,
        "Fake Subdomain URLs": fake_subdomain_urls
    }
    
    print("\nCategory Results Summary:")
    print("-" * 50)
    
    for category, urls in all_test_urls.items():
        trust_scores = []
        risk_levels = []
        for url in urls:
            result = predictor.predict_url(url)
            trust_scores.append(result.get('trust_score', 100 - result['score']))
            risk_levels.append(result['risk_level'])
        
        avg_trust_score = sum(trust_scores) / len(trust_scores)
        risk_distribution = {
            'Safe': risk_levels.count('Safe'),
            'Suspicious': risk_levels.count('Suspicious'),
            'Dangerous': risk_levels.count('Dangerous')
        }
        
        print(f"\n{category}:")
        print(f"  Average Trust Score: {avg_trust_score:.1f}/100")
        print(f"  Risk Distribution: Safe={risk_distribution['Safe']}, Suspicious={risk_distribution['Suspicious']}, Dangerous={risk_distribution['Dangerous']}")

if __name__ == "__main__":
    run_tests()
