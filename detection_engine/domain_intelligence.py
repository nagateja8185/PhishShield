"""
Domain Intelligence Module
Analyzes domain WHOIS data, age, registrar, and hosting information
"""

import socket
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse
import whois


class DomainIntelligence:
    """Analyze domain intelligence signals for trust scoring"""
    
    def __init__(self):
        self.suspicious_registrars = [
            'namecheap',  # Often used for quick scam setups
            'abuse@',     # Generic abuse contacts
        ]
        self.trusted_registrars = [
            'markmonitor',
            'cscglobal',
            'corporatedomains',
        ]
    
    def analyze(self, url):
        """
        Analyze domain intelligence for a URL
        
        Args:
            url: URL to analyze
            
        Returns:
            dict: Domain intelligence data
        """
        result = {
            'domain': None,
            'ip_address': None,
            'domain_age_days': None,
            'domain_age_category': 'unknown',
            'registrar': None,
            'registrant_country': None,
            'whois_hidden': False,
            'nameservers': [],
            'mx_records': [],
            'hosting_country': None,
            'creation_date': None,
            'expiration_date': None,
            'is_expired': False,
            'error': None
        }
        
        try:
            # Parse domain from URL
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc or parsed.path
            if ':' in domain:
                domain = domain.split(':')[0]
            result['domain'] = domain
            
            # Get IP address
            try:
                result['ip_address'] = socket.gethostbyname(domain)
            except socket.gaierror:
                result['error'] = 'Could not resolve domain'
                return result
            
            # Get DNS records
            result['nameservers'] = self._get_nameservers(domain)
            result['mx_records'] = self._get_mx_records(domain)
            
            # Get WHOIS data
            whois_data = self._get_whois_data(domain)
            result.update(whois_data)
            
            # Determine domain age category
            if result['domain_age_days'] is not None:
                result['domain_age_category'] = self._categorize_domain_age(
                    result['domain_age_days']
                )
            
            # Check if WHOIS is hidden
            result['whois_hidden'] = self._check_whois_hidden(whois_data)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _get_nameservers(self, domain):
        """Get nameservers for domain"""
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            return [str(ns).rstrip('.') for ns in ns_records]
        except Exception:
            return []
    
    def _get_mx_records(self, domain):
        """Get MX records for domain"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return [str(mx.exchange).rstrip('.') for mx in mx_records]
        except Exception:
            return []
    
    def _get_whois_data(self, domain):
        """Get WHOIS data for domain"""
        result = {
            'registrar': None,
            'registrant_country': None,
            'creation_date': None,
            'expiration_date': None,
            'domain_age_days': None,
            'is_expired': False
        }
        
        try:
            w = whois.whois(domain)
            
            # Get registrar
            if w.registrar:
                result['registrar'] = str(w.registrar).lower()
            
            # Get country
            if w.registrant_country:
                result['registrant_country'] = str(w.registrant_country)
            elif w.country:
                result['registrant_country'] = str(w.country)
            
            # Get dates
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            
            # Handle list of dates (take first)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            if creation_date:
                result['creation_date'] = creation_date.isoformat() if hasattr(creation_date, 'isoformat') else str(creation_date)
                # Calculate age
                if isinstance(creation_date, datetime):
                    age = (datetime.now() - creation_date).days
                    result['domain_age_days'] = age
            
            if expiration_date:
                result['expiration_date'] = expiration_date.isoformat() if hasattr(expiration_date, 'isoformat') else str(expiration_date)
                # Check if expired
                if isinstance(expiration_date, datetime):
                    result['is_expired'] = expiration_date < datetime.now()
            
        except Exception as e:
            # WHOIS failed - common for some TLDs
            pass
        
        return result
    
    def _categorize_domain_age(self, age_days):
        """Categorize domain age into risk levels"""
        if age_days < 30:
            return 'very_new'  # High risk
        elif age_days < 90:
            return 'new'  # Medium-high risk
        elif age_days < 180:
            return 'young'  # Medium risk
        elif age_days < 365:
            return 'moderate'  # Low-medium risk
        else:
            return 'established'  # Low risk
    
    def _check_whois_hidden(self, whois_data):
        """Check if WHOIS information is hidden/privacy protected"""
        # Common indicators of privacy protection
        privacy_keywords = [
            'privacy', 'whoisguard', 'protected', 'redacted',
            'not disclosed', 'hidden', 'proxy'
        ]
        
        registrar = whois_data.get('registrar', '') or ''
        
        for keyword in privacy_keywords:
            if keyword in registrar.lower():
                return True
        
        # If no registrant info available, likely hidden
        if not whois_data.get('registrant_country'):
            return True
        
        return False
    
    def get_risk_signals(self, domain_data):
        """
        Extract risk signals from domain intelligence
        
        Returns:
            list: Risk signals with type and message
        """
        signals = []
        
        # Domain age risks
        age_category = domain_data.get('domain_age_category')
        age_days = domain_data.get('domain_age_days')
        
        if age_category == 'very_new':
            signals.append({
                'type': 'danger',
                'category': 'domain_age',
                'message': f'Domain is only {age_days} days old (very new)',
                'impact': -25
            })
        elif age_category == 'new':
            signals.append({
                'type': 'warning',
                'category': 'domain_age',
                'message': f'Domain is {age_days} days old (recently created)',
                'impact': -15
            })
        elif age_category == 'young':
            signals.append({
                'type': 'caution',
                'category': 'domain_age',
                'message': f'Domain is {age_days} days old (less than 6 months)',
                'impact': -10
            })
        elif age_category == 'established':
            signals.append({
                'type': 'positive',
                'category': 'domain_age',
                'message': f'Domain is {age_days} days old (well established)',
                'impact': 15
            })
        
        # WHOIS privacy
        if domain_data.get('whois_hidden'):
            signals.append({
                'type': 'caution',
                'category': 'whois',
                'message': 'Domain owner information is hidden (privacy protection)',
                'impact': -5
            })
        else:
            signals.append({
                'type': 'positive',
                'category': 'whois',
                'message': 'Domain ownership information is publicly visible',
                'impact': 5
            })
        
        # Expiration check
        if domain_data.get('is_expired'):
            signals.append({
                'type': 'danger',
                'category': 'expiration',
                'message': 'Domain has expired',
                'impact': -30
            })
        
        # MX records (legitimate businesses usually have email)
        if domain_data.get('mx_records'):
            signals.append({
                'type': 'positive',
                'category': 'email',
                'message': 'Domain has configured email servers',
                'impact': 5
            })
        
        return signals
