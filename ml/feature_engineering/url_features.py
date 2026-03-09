"""
URL Feature Extraction Module
Extracts features from URLs for phishing detection
"""

import re
import math
import sys
import os
from urllib.parse import urlparse

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# Import trusted domains loader
try:
    from detection_engine.trusted_domains_loader import TrustedDomainsLoader
    _trusted_loader = TrustedDomainsLoader()
    TRUSTED_DOMAINS = _trusted_loader.get_all_domains()
except Exception:
    # Fallback if loader fails
    TRUSTED_DOMAINS = [
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
        'wikipedia.org', 'twitter.com', 'instagram.com', 'linkedin.com',
        'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com',
        'paypal.com', 'ebay.com', 'netflix.com', 'spotify.com',
        'chatgpt.com', 'openai.com', 'chat.openai.com', 'reddit.com',
        'discord.com', 'zoom.us', 'slack.com'
    ]


class URLFeatureExtractor:
    """Extract features from a URL for phishing detection"""
    
    SUSPICIOUS_KEYWORDS = [
        'secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin',
        'banking', 'confirm', 'paypal', 'verif', 'admin', 'update',
        'security', 'verify', 'wallet', 'alert', 'protection', 'limited',
        'suspend', 'unusual', 'activity', 'access', 'confirm', 'identity',
        'verification', 'customer', 'service', 'resolution', 'center',
        'restore', 'unlock', 'reactivate', 'validate', 'authentication'
    ]
    
    SHORTENING_SERVICES = [
        'bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
        'is.gd', 'shorte.st', 'adf.ly', 'bit.do', 'short.link',
        'rb.gy', 'shorturl.at', 'rebrand.ly', 'cutt.ly'
    ]
    
    @staticmethod
    def is_trusted_domain(domain):
        """Check if domain is in trusted list"""
        domain_lower = domain.lower()
        for trusted in TRUSTED_DOMAINS:
            if domain_lower == trusted or domain_lower.endswith('.' + trusted):
                return True
        return False
    
    @staticmethod
    def extract_features(url):
        """
        Extract all features from a URL
        
        Args:
            url: String URL to analyze
            
        Returns:
            dict: Dictionary of extracted features
        """
        if not url:
            return URLFeatureExtractor._default_features()
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
        except Exception:
            return URLFeatureExtractor._default_features()
        
        # Check if domain is trusted - if so, return safe features
        if URLFeatureExtractor.is_trusted_domain(domain):
            return URLFeatureExtractor._trusted_domain_features()
        
        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'path_length': len(path),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_underscores': url.count('_'),
            'num_slashes': url.count('/'),
            'num_digits': sum(c.isdigit() for c in url),
            'has_at_symbol': 1 if '@' in url else 0,
            'has_double_slash': 1 if '//' in url[7:] else 0,
            'has_ip_address': 1 if URLFeatureExtractor._has_ip(domain) else 0,
            'has_https': 1 if url.startswith('https://') else 0,
            'domain_entropy': URLFeatureExtractor._calculate_entropy(domain),
            'suspicious_keywords_count': sum(1 for kw in URLFeatureExtractor.SUSPICIOUS_KEYWORDS if kw in url.lower()),
            'is_shortened': 1 if any(svc in domain for svc in URLFeatureExtractor.SHORTENING_SERVICES) else 0,
            'has_suspicious_tld': 1 if URLFeatureExtractor._has_suspicious_tld(domain) else 0,
            'subdomain_count': len(domain.split('.')) - 2 if domain.count('.') > 1 else 0,
            'has_port': 1 if URLFeatureExtractor._get_port(parsed) else 0,
            'query_length': len(query),
            'has_hex_chars': 1 if '%' in url else 0,
        }
        
        return features
    
    @staticmethod
    def _trusted_domain_features():
        """Return safe feature values for trusted domains"""
        return {
            'url_length': 20,
            'domain_length': 15,
            'path_length': 5,
            'num_dots': 1,
            'num_hyphens': 0,
            'num_underscores': 0,
            'num_slashes': 1,
            'num_digits': 0,
            'has_at_symbol': 0,
            'has_double_slash': 0,
            'has_ip_address': 0,
            'has_https': 1,
            'domain_entropy': 3.0,
            'suspicious_keywords_count': 0,
            'is_shortened': 0,
            'has_suspicious_tld': 0,
            'subdomain_count': 0,
            'has_port': 0,
            'query_length': 0,
            'has_hex_chars': 0,
        }
    
    @staticmethod
    def _default_features():
        """Return default feature values for invalid URLs"""
        return {
            'url_length': 0,
            'domain_length': 0,
            'path_length': 0,
            'num_dots': 0,
            'num_hyphens': 0,
            'num_underscores': 0,
            'num_slashes': 0,
            'num_digits': 0,
            'has_at_symbol': 0,
            'has_double_slash': 0,
            'has_ip_address': 0,
            'has_https': 0,
            'domain_entropy': 0,
            'suspicious_keywords_count': 0,
            'is_shortened': 0,
            'has_suspicious_tld': 0,
            'subdomain_count': 0,
            'has_port': 0,
            'query_length': 0,
            'has_hex_chars': 0,
        }
    
    @staticmethod
    def _has_ip(domain):
        """Check if domain is an IP address"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    @staticmethod
    def _calculate_entropy(string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = -sum([p * math.log(p) / math.log(2) for p in prob])
        return entropy
    
    @staticmethod
    def _get_port(parsed):
        """Safely get port from parsed URL"""
        try:
            port = parsed.port
            return port is not None and port not in [80, 443]
        except ValueError:
            return False
    
    @staticmethod
    def _has_suspicious_tld(domain):
        """Check if domain uses suspicious TLD"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.work', '.date', '.racing', '.loan', '.download']
        return any(domain.endswith(tld) for tld in suspicious_tlds)
    
    @classmethod
    def get_feature_vector(cls, url):
        """
        Get feature values as a list for model input
        
        Args:
            url: String URL to analyze
            
        Returns:
            list: List of feature values in consistent order
        """
        features = cls.extract_features(url)
        # Return features in consistent order
        feature_order = [
            'url_length', 'domain_length', 'path_length', 'num_dots',
            'num_hyphens', 'num_underscores', 'num_slashes', 'num_digits',
            'has_at_symbol', 'has_double_slash', 'has_ip_address', 'has_https',
            'domain_entropy', 'suspicious_keywords_count', 'is_shortened',
            'has_suspicious_tld', 'subdomain_count', 'has_port',
            'query_length', 'has_hex_chars'
        ]
        return [features[f] for f in feature_order]
    
    @classmethod
    def get_feature_names(cls):
        """Get list of feature names in consistent order"""
        return [
            'url_length', 'domain_length', 'path_length', 'num_dots',
            'num_hyphens', 'num_underscores', 'num_slashes', 'num_digits',
            'has_at_symbol', 'has_double_slash', 'has_ip_address', 'has_https',
            'domain_entropy', 'suspicious_keywords_count', 'is_shortened',
            'has_suspicious_tld', 'subdomain_count', 'has_port',
            'query_length', 'has_hex_chars'
        ]
