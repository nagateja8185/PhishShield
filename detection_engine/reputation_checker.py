"""
Reputation Checker Module
Checks domain reputation against threat intelligence sources
"""

import hashlib
import requests
from urllib.parse import urlparse
import sys
import os

# Import trusted domains loader from same directory
from detection_engine.trusted_domains_loader import TrustedDomainsLoader

# Initialize trusted domains loader
_trusted_loader = TrustedDomainsLoader()


class ReputationChecker:
    """Check domain reputation from various sources"""
    
    def __init__(self):
        # Known suspicious patterns
        self.suspicious_patterns = [
            'login', 'signin', 'verify', 'secure', 'account', 'update',
            'confirm', 'banking', 'password', 'credential', 'wallet',
            'security', 'authenticate', 'validation'
        ]
        
        # Use trusted domains loader
        self.trusted_domains_loader = _trusted_loader
        
        # Suspicious TLDs often used for scams
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains
            '.top', '.xyz', '.work', '.date', '.racing',
            '.loan', '.download', '.click', '.link'
        ]
    
    def check(self, url):
        """
        Check reputation signals for a URL
        
        Args:
            url: URL to check
            
        Returns:
            dict: Reputation check results
        """
        result = {
            'domain': None,
            'is_trusted_domain': False,
            'suspicious_keywords': [],
            'suspicious_tld': False,
            'url_length': 0,
            'subdomain_count': 0,
            'has_ip_address': False,
            'has_at_symbol': False,
            'has_double_slash': False,
            'entropy_score': 0,
            'reputation_score': 50,  # Neutral starting point
            'sources_checked': [],
            'error': None
        }
        
        try:
            # Parse URL
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc or parsed.path
            if ':' in domain:
                domain = domain.split(':')[0]
            
            result['domain'] = domain
            
            # Check if trusted domain
            result['is_trusted_domain'] = self._is_trusted_domain(domain)
            
            # Check suspicious keywords
            result['suspicious_keywords'] = self._check_suspicious_keywords(url)
            
            # Check TLD
            result['suspicious_tld'] = any(domain.endswith(tld) for tld in self.suspicious_tlds)
            
            # URL structure analysis
            result['url_length'] = len(url)
            result['subdomain_count'] = domain.count('.') - 1 if domain.count('.') > 1 else 0
            result['has_ip_address'] = self._is_ip_address(domain)
            result['has_at_symbol'] = '@' in url
            result['has_double_slash'] = '//' in url[7:]  # After protocol
            
            # Calculate entropy (randomness in domain)
            result['entropy_score'] = self._calculate_entropy(domain)
            
            # Calculate reputation score
            result['reputation_score'] = self._calculate_reputation_score(result)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _is_trusted_domain(self, domain):
        """Check if domain is in trusted list"""
        return self.trusted_domains_loader.is_trusted(domain)
    
    def _check_suspicious_keywords(self, url):
        """Check for suspicious keywords in URL"""
        url_lower = url.lower()
        found = []
        for keyword in self.suspicious_patterns:
            if keyword in url_lower:
                found.append(keyword)
        return found
    
    def _is_ip_address(self, domain):
        """Check if domain is an IP address"""
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    def _calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        import math
        if not string:
            return 0
        
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = -sum([p * math.log(p) / math.log(2) for p in prob if p > 0])
        return entropy
    
    def _calculate_reputation_score(self, data):
        """Calculate reputation score based on signals"""
        score = 50  # Start neutral
        
        # Trusted domain bonus
        if data['is_trusted_domain']:
            score += 40
        
        # Suspicious keywords penalty
        keyword_count = len(data['suspicious_keywords'])
        if keyword_count > 0:
            score -= min(keyword_count * 5, 20)
        
        # Suspicious TLD penalty
        if data['suspicious_tld']:
            score -= 15
        
        # URL length penalty (very long URLs are suspicious)
        if data['url_length'] > 100:
            score -= 10
        if data['url_length'] > 150:
            score -= 10
        
        # IP address penalty
        if data['has_ip_address']:
            score -= 20
        
        # @ symbol penalty (phishing technique)
        if data['has_at_symbol']:
            score -= 15
        
        # Double slash penalty
        if data['has_double_slash']:
            score -= 10
        
        # High entropy penalty (random-looking domain)
        if data['entropy_score'] > 4:
            score -= 10
        
        # Clamp score to 0-100
        return max(0, min(100, score))
    
    def get_risk_signals(self, reputation_data):
        """
        Extract risk signals from reputation data
        
        Returns:
            list: Risk signals with type and message
        """
        signals = []
        
        # Trusted domain
        if reputation_data.get('is_trusted_domain'):
            signals.append({
                'type': 'positive',
                'category': 'reputation',
                'message': 'Domain is a well-known, trusted website',
                'impact': 25
            })
        
        # Suspicious keywords
        keywords = reputation_data.get('suspicious_keywords', [])
        if keywords:
            signals.append({
                'type': 'warning',
                'category': 'url_pattern',
                'message': f"Suspicious keywords detected: {', '.join(keywords[:3])}",
                'impact': -min(len(keywords) * 5, 20)
            })
        
        # Suspicious TLD
        if reputation_data.get('suspicious_tld'):
            signals.append({
                'type': 'warning',
                'category': 'domain',
                'message': 'Domain uses a suspicious top-level domain',
                'impact': -15
            })
        
        # IP address
        if reputation_data.get('has_ip_address'):
            signals.append({
                'type': 'danger',
                'category': 'url_pattern',
                'message': 'URL uses an IP address instead of a domain name',
                'impact': -20
            })
        
        # @ symbol
        if reputation_data.get('has_at_symbol'):
            signals.append({
                'type': 'danger',
                'category': 'url_pattern',
                'message': 'URL contains @ symbol (credential stealing technique)',
                'impact': -15
            })
        
        # URL length
        url_length = reputation_data.get('url_length', 0)
        if url_length > 150:
            signals.append({
                'type': 'warning',
                'category': 'url_pattern',
                'message': f'Very long URL ({url_length} characters) - may be hiding malicious domain',
                'impact': -10
            })
        elif url_length > 100:
            signals.append({
                'type': 'caution',
                'category': 'url_pattern',
                'message': f'Long URL ({url_length} characters)',
                'impact': -5
            })
        
        # Double slash
        if reputation_data.get('has_double_slash'):
            signals.append({
                'type': 'warning',
                'category': 'url_pattern',
                'message': 'URL contains double slash after protocol (redirection technique)',
                'impact': -10
            })
        
        # High entropy
        entropy = reputation_data.get('entropy_score', 0)
        if entropy > 4.5:
            signals.append({
                'type': 'warning',
                'category': 'url_pattern',
                'message': 'Domain name appears randomly generated',
                'impact': -10
            })
        
        return signals
