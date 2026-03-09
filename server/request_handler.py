"""
HTTP Request Handler for PhishShield
Handles API endpoints and static file serving
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.predictor import get_predictor
from detection_engine.website_analyzer import get_analyzer


class PhishShieldHandler(BaseHTTPRequestHandler):
    """Custom HTTP request handler for PhishShield"""
    
    # Get predictor and analyzer instances
    predictor = None
    website_analyzer = None
    
    @classmethod
    def initialize_predictor(cls):
        """Initialize the ML predictor and website analyzer"""
        cls.predictor = get_predictor()
        cls.website_analyzer = get_analyzer()
    
    def log_message(self, format, *args):
        """Override to customize logging"""
        print(f"[{self.log_date_time_string()}] {args[0]}")
    
    def _set_headers(self, content_type='application/json', status_code=200):
        """Set response headers"""
        self.send_response(status_code)
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def _send_json_response(self, data, status_code=200):
        """Send JSON response"""
        self._set_headers('application/json', status_code)
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def _send_error(self, message, status_code=400):
        """Send error response"""
        self._send_json_response({'error': message}, status_code)
    
    def _read_json_body(self):
        """Read and parse JSON request body"""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return None
        
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS"""
        self._set_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # API endpoint: Health check
        if path == '/health':
            self._handle_health_check()
            return
        
        # Serve static files
        self._serve_static_file(path)
    
    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == '/analyze-email':
            self._handle_analyze_email()
        elif path == '/analyze-url':
            self._handle_analyze_url()
        elif path == '/analyze-website':
            self._handle_analyze_website()
        else:
            self._send_error('Not found', 404)
    
    def _handle_health_check(self):
        """Handle health check endpoint"""
        status = {
            'status': 'healthy',
            'models_loaded': self.predictor.models_loaded if self.predictor else False
        }
        self._send_json_response(status)
    
    def _handle_analyze_email(self):
        """Handle email analysis request"""
        data = self._read_json_body()
        
        if not data:
            self._send_error('Invalid JSON body')
            return
        
        email_text = data.get('email', '').strip()
        subject = data.get('subject', '').strip()
        
        if not email_text:
            self._send_error('Email text is required')
            return
        
        # Check request size (limit to 1MB)
        if len(email_text) > 1024 * 1024:
            self._send_error('Email text too large (max 1MB)')
            return
        
        # Extract subject from email text if not provided separately
        if not subject:
            subject = self._extract_subject_from_email(email_text)
        
        # Make prediction
        try:
            result = self.predictor.predict_email(email_text, subject)
            
            response = {
                'success': True,
                'type': 'email',
                'score': result['score'],
                'label': result['label'],
                'risk_level': result['risk_level'],
                'phishing_probability': result['phishing_probability'],
                'explanation': result['explanation'],
                'indicators': result.get('indicators', [])
            }
            
            self._send_json_response(response)
            
        except Exception as e:
            print(f"Error analyzing email: {e}")
            self._send_error(f'Analysis failed: {str(e)}', 500)
    
    def _handle_analyze_url(self):
        """Handle URL analysis request"""
        data = self._read_json_body()
        
        if not data:
            self._send_error('Invalid JSON body')
            return
        
        url = data.get('url', '').strip()
        
        if not url:
            self._send_error('URL is required')
            return
        
        # Validate URL length
        if len(url) > 2048:
            self._send_error('URL too long (max 2048 characters)')
            return
        
        # Sanitize URL (basic validation)
        if not self._is_valid_url(url):
            self._send_error('Invalid URL format')
            return
        
        # Make prediction
        try:
            result = self.predictor.predict_url(url)
            
            response = {
                'success': True,
                'type': 'url',
                'trust_score': result.get('trust_score', 100 - result['score']),
                'score': result['score'],
                'label': result['label'],
                'risk_level': result['risk_level'],
                'phishing_probability': result['phishing_probability'],
                'explanation': result['explanation'],
                'indicators': result.get('indicators', [])
            }
            
            self._send_json_response(response)
            
        except Exception as e:
            print(f"Error analyzing URL: {e}")
            self._send_error(f'Analysis failed: {str(e)}', 500)
    
    def _handle_analyze_website(self):
        """Handle comprehensive website analysis request"""
        data = self._read_json_body()
        
        if not data:
            self._send_error('Invalid JSON body')
            return
        
        url = data.get('url', '').strip()
        
        if not url:
            self._send_error('URL is required')
            return
        
        # Validate URL length
        if len(url) > 2048:
            self._send_error('URL too long (max 2048 characters)')
            return
        
        # Sanitize URL (basic validation)
        if not self._is_valid_url(url):
            self._send_error('Invalid URL format')
            return
        
        # Perform comprehensive analysis
        try:
            result = self.website_analyzer.analyze(url)
            
            response = {
                'success': True,
                'type': 'website',
                'url': result['url'],
                'domain': result['domain'],
                'trust_score': result['trust_score'],
                'risk_level': result['risk_level'],
                'confidence': result['confidence'],
                'positive_signals': result['positive_signals'],
                'negative_signals': result['negative_signals'],
                'recommendation': result['recommendation'],
                'domain_data': {
                    'domain_age_days': result['domain_data'].get('domain_age_days'),
                    'domain_age_category': result['domain_data'].get('domain_age_category'),
                    'registrar': result['domain_data'].get('registrar'),
                    'whois_hidden': result['domain_data'].get('whois_hidden'),
                    'ip_address': result['domain_data'].get('ip_address'),
                    'nameservers': result['domain_data'].get('nameservers', [])[:3]  # Limit for response size
                },
                'ssl_data': {
                    'has_https': result['ssl_data'].get('has_https'),
                    'certificate_valid': result['ssl_data'].get('certificate_valid'),
                    'issuer': result['ssl_data'].get('issuer'),
                    'days_until_expiry': result['ssl_data'].get('days_until_expiry'),
                    'ssl_version': result['ssl_data'].get('ssl_version')
                },
                'ml_prediction': result['ml_prediction'],
                'errors': result.get('errors', [])
            }
            
            self._send_json_response(response)
            
        except Exception as e:
            print(f"Error analyzing website: {e}")
            self._send_error(f'Analysis failed: {str(e)}', 500)
    
    def _extract_subject_from_email(self, email_text):
        """Extract subject line from email text if present"""
        import re
        
        # Look for Subject: line
        subject_match = re.search(r'^Subject:\s*(.+)$', email_text, re.MULTILINE | re.IGNORECASE)
        if subject_match:
            return subject_match.group(1).strip()
        
        # Look for subject in the first line if it looks like a subject
        lines = email_text.strip().split('\n')
        if lines and len(lines[0]) < 100 and not lines[0].startswith('From:'):
            return lines[0].strip()
        
        return ''
    
    def _is_valid_url(self, url):
        """Basic URL validation"""
        # Check for common URL patterns
        if not url:
            return False
        
        # Must have some valid characters
        if len(url) < 3:
            return False
        
        # Check for dangerous characters that could indicate injection
        dangerous_chars = ['<', '>', '{', '}', '|', '^', '`', '\\']
        if any(c in url for c in dangerous_chars):
            return False
        
        return True
    
    def _serve_static_file(self, path):
        """Serve static files from frontend directory"""
        # Default to index.html for root path
        if path == '/' or path == '':
            path = '/index.html'
        
        # Map paths to frontend directory
        frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
        
        # Remove leading slash and prevent directory traversal
        safe_path = path.lstrip('/').replace('..', '')
        
        # Map to frontend structure
        if safe_path.startswith('pages/'):
            file_path = os.path.join(frontend_dir, safe_path)
        elif safe_path.endswith('.html'):
            file_path = os.path.join(frontend_dir, 'pages', safe_path)
        elif safe_path.startswith('css/'):
            file_path = os.path.join(frontend_dir, safe_path)
        elif safe_path.startswith('js/'):
            file_path = os.path.join(frontend_dir, safe_path)
        elif safe_path.startswith('assets/'):
            file_path = os.path.join(frontend_dir, safe_path)
        else:
            file_path = os.path.join(frontend_dir, 'pages', safe_path)
        
        # Ensure file exists and is within frontend directory
        real_path = os.path.realpath(file_path)
        real_frontend = os.path.realpath(frontend_dir)
        
        if not real_path.startswith(real_frontend):
            self._send_error('Access denied', 403)
            return
        
        if not os.path.exists(real_path) or not os.path.isfile(real_path):
            # Try serving index.html for SPA routing
            index_path = os.path.join(frontend_dir, 'pages', 'index.html')
            if os.path.exists(index_path):
                self._serve_file(index_path)
            else:
                self._send_error('File not found', 404)
            return
        
        self._serve_file(real_path)
    
    def _serve_file(self, file_path):
        """Serve a file with appropriate content type"""
        # Determine content type
        content_types = {
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.json': 'application/json',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.svg': 'image/svg+xml',
            '.ico': 'image/x-icon'
        }
        
        ext = os.path.splitext(file_path)[1].lower()
        content_type = content_types.get(ext, 'application/octet-stream')
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            self._set_headers(content_type, 200)
            self.wfile.write(content)
            
        except Exception as e:
            print(f"Error serving file {file_path}: {e}")
            self._send_error('Error serving file', 500)
