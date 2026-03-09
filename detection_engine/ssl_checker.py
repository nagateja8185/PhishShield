"""
SSL Certificate Checker Module
Validates SSL certificates and HTTPS configuration
"""

import ssl
import socket
import certifi
from urllib.parse import urlparse
from datetime import datetime


class SSLChecker:
    """Check SSL certificate validity and security"""
    
    def __init__(self):
        self.context = ssl.create_default_context(cafile=certifi.where())
    
    def check(self, url):
        """
        Check SSL certificate for a URL
        
        Args:
            url: URL to check
            
        Returns:
            dict: SSL check results
        """
        result = {
            'has_https': False,
            'certificate_valid': False,
            'issuer': None,
            'subject': None,
            'not_before': None,
            'not_after': None,
            'days_until_expiry': None,
            'is_expired': False,
            'ssl_version': None,
            'cipher_suite': None,
            'cert_fingerprint': None,
            'san_domains': [],
            'error': None
        }
        
        try:
            # Parse URL
            parsed = urlparse(url if url.startswith('http') else f'https://{url}')
            
            if parsed.scheme == 'https':
                result['has_https'] = True
            else:
                # Try HTTPS anyway
                result['has_https'] = self._test_https(parsed.netloc or parsed.path)
                if not result['has_https']:
                    result['error'] = 'HTTPS not available'
                    return result
            
            domain = parsed.netloc or parsed.path
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Get certificate info
            cert_info = self._get_certificate_info(domain)
            result.update(cert_info)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _test_https(self, domain):
        """Test if HTTPS is available"""
        try:
            if ':' in domain:
                domain = domain.split(':')[0]
            
            with socket.create_connection((domain, 443), timeout=5):
                return True
        except Exception:
            return False
    
    def _get_certificate_info(self, domain):
        """Get detailed certificate information"""
        result = {
            'certificate_valid': False,
            'issuer': None,
            'subject': None,
            'not_before': None,
            'not_after': None,
            'days_until_expiry': None,
            'is_expired': False,
            'ssl_version': None,
            'cipher_suite': None,
            'cert_fingerprint': None,
            'san_domains': []
        }
        
        try:
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with self.context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    result['certificate_valid'] = True
                    result['ssl_version'] = version
                    result['cipher_suite'] = cipher[0] if cipher else None
                    
                    # Parse certificate data
                    if cert:
                        # Issuer
                        issuer = cert.get('issuer')
                        if issuer:
                            result['issuer'] = self._parse_cert_name(issuer)
                        
                        # Subject
                        subject = cert.get('subject')
                        if subject:
                            result['subject'] = self._parse_cert_name(subject)
                        
                        # Dates
                        not_before = cert.get('notBefore')
                        not_after = cert.get('notAfter')
                        
                        if not_before:
                            result['not_before'] = not_before
                        if not_after:
                            result['not_after'] = not_after
                            # Calculate days until expiry
                            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_left = (expiry - datetime.utcnow()).days
                            result['days_until_expiry'] = days_left
                            result['is_expired'] = days_left < 0
                        
                        # Subject Alternative Names
                        san = cert.get('subjectAltName', [])
                        result['san_domains'] = [name[1] for name in san if name[0] == 'DNS']
                        
                        # Fingerprint (we'll use a placeholder as we need binary cert)
                        result['cert_fingerprint'] = 'available'
        
        except ssl.SSLError as e:
            result['error'] = f'SSL Error: {str(e)}'
        except socket.timeout:
            result['error'] = 'Connection timeout'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _parse_cert_name(self, name_tuple):
        """Parse certificate name tuple into readable string"""
        parts = []
        for item in name_tuple:
            if isinstance(item, tuple):
                parts.append(f"{item[0]}={item[1]}")
            elif isinstance(item, list) and len(item) == 2:
                parts.append(f"{item[0]}={item[1]}")
        return ', '.join(parts) if parts else str(name_tuple)
    
    def get_risk_signals(self, ssl_data):
        """
        Extract risk signals from SSL data
        
        Returns:
            list: Risk signals with type and message
        """
        signals = []
        
        # HTTPS check
        if ssl_data.get('has_https'):
            signals.append({
                'type': 'positive',
                'category': 'ssl',
                'message': 'HTTPS is enabled',
                'impact': 10
            })
            
            # Certificate validity
            if ssl_data.get('certificate_valid'):
                signals.append({
                    'type': 'positive',
                    'category': 'ssl',
                    'message': 'SSL certificate is valid',
                    'impact': 10
                })
                
                # Expiry check
                days_left = ssl_data.get('days_until_expiry')
                if days_left is not None:
                    if days_left < 0:
                        signals.append({
                            'type': 'danger',
                            'category': 'ssl',
                            'message': f'SSL certificate expired {abs(days_left)} days ago',
                            'impact': -20
                        })
                    elif days_left < 7:
                        signals.append({
                            'type': 'warning',
                            'category': 'ssl',
                            'message': f'SSL certificate expires in {days_left} days',
                            'impact': -5
                        })
                    elif days_left < 30:
                        signals.append({
                            'type': 'caution',
                            'category': 'ssl',
                            'message': f'SSL certificate expires in {days_left} days',
                            'impact': -2
                        })
                    else:
                        signals.append({
                            'type': 'positive',
                            'category': 'ssl',
                            'message': f'SSL certificate valid for {days_left} more days',
                            'impact': 5
                        })
                
                # SSL version check
                version = ssl_data.get('ssl_version')
                if version:
                    if version in ['TLSv1.3']:
                        signals.append({
                            'type': 'positive',
                            'category': 'ssl',
                            'message': f'Using modern {version} encryption',
                            'impact': 5
                        })
                    elif version in ['TLSv1.2']:
                        signals.append({
                            'type': 'positive',
                            'category': 'ssl',
                            'message': f'Using {version} encryption',
                            'impact': 3
                        })
                    elif version in ['TLSv1.1', 'TLSv1', 'SSLv3', 'SSLv2']:
                        signals.append({
                            'type': 'warning',
                            'category': 'ssl',
                            'message': f'Using outdated {version} encryption',
                            'impact': -10
                        })
            else:
                error = ssl_data.get('error', 'Unknown SSL error')
                signals.append({
                    'type': 'warning',
                    'category': 'ssl',
                    'message': f'SSL certificate issue: {error}',
                    'impact': -10
                })
        else:
            signals.append({
                'type': 'danger',
                'category': 'ssl',
                'message': 'HTTPS is not enabled - data transmitted in plaintext',
                'impact': -20
            })
        
        return signals
