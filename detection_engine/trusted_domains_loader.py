"""
Trusted Domains Loader
Loads and provides access to the trusted domains dataset
"""

import os
import csv
from urllib.parse import urlparse


class TrustedDomainsLoader:
    """Load and manage trusted domains from CSV dataset"""
    
    _instance = None
    _domains = None
    _domain_set = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TrustedDomainsLoader, cls).__new__(cls)
            cls._instance._load_domains()
        return cls._instance
    
    def _load_domains(self):
        """Load trusted domains from CSV file"""
        self._domains = []
        self._domain_set = set()
        
        csv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'trusted_domains.csv')
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain = row['domain'].strip().lower()
                    self._domains.append({
                        'domain': domain,
                        'category': row.get('category', 'general'),
                        'description': row.get('description', '')
                    })
                    self._domain_set.add(domain)
                    # Also add www variant
                    if not domain.startswith('www.'):
                        self._domain_set.add('www.' + domain)
        except FileNotFoundError:
            print(f"Warning: Trusted domains file not found at {csv_path}")
        except Exception as e:
            print(f"Error loading trusted domains: {e}")
    
    def is_trusted(self, url_or_domain):
        """
        Check if a URL or domain is trusted
        
        Args:
            url_or_domain: URL or domain name to check
            
        Returns:
            bool: True if domain is trusted
        """
        if not url_or_domain:
            return False
        
        # Extract domain from URL
        domain = self._extract_domain(url_or_domain)
        if not domain:
            return False
        
        # Check exact match
        if domain in self._domain_set:
            return True
        
        # Check if domain ends with trusted domain
        for trusted in self._domain_set:
            if domain.endswith('.' + trusted) or trusted.endswith('.' + domain):
                return True
        
        return False
    
    def get_domain_info(self, url_or_domain):
        """
        Get information about a trusted domain
        
        Args:
            url_or_domain: URL or domain name
            
        Returns:
            dict or None: Domain information if trusted, None otherwise
        """
        domain = self._extract_domain(url_or_domain)
        if not domain:
            return None
        
        for info in self._domains:
            if info['domain'] == domain or domain.endswith('.' + info['domain']):
                return info
        
        return None
    
    def _extract_domain(self, url_or_domain):
        """Extract domain from URL or return domain as-is"""
        if not url_or_domain:
            return None
        
        url_or_domain = url_or_domain.strip().lower()
        
        # If it looks like a URL, parse it
        if url_or_domain.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(url_or_domain)
                domain = parsed.netloc
            except Exception:
                return None
        else:
            domain = url_or_domain
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain
    
    def get_all_domains(self):
        """Get list of all trusted domains"""
        return [d['domain'] for d in self._domains]
    
    def get_domains_by_category(self, category):
        """Get domains filtered by category"""
        return [d for d in self._domains if d['category'] == category]
    
    def get_categories(self):
        """Get list of all categories"""
        return sorted(set(d['category'] for d in self._domains))
    
    def count(self):
        """Get total number of trusted domains"""
        return len(self._domains)


# Global instance for easy access
trusted_domains_loader = TrustedDomainsLoader()


def is_trusted_domain(url_or_domain):
    """
    Convenience function to check if a domain is trusted
    
    Args:
        url_or_domain: URL or domain to check
        
    Returns:
        bool: True if trusted
    """
    return trusted_domains_loader.is_trusted(url_or_domain)


def get_trusted_domain_info(url_or_domain):
    """
    Convenience function to get domain info
    
    Args:
        url_or_domain: URL or domain
        
    Returns:
        dict or None: Domain information
    """
    return trusted_domains_loader.get_domain_info(url_or_domain)
