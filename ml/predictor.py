"""
PhishShield Prediction Module
Provides interface for making phishing predictions
"""

import os
import pickle
import sys
import re
import numpy as np

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.preprocessing.text_cleaning import TextCleaner
from ml.feature_engineering.url_features import URLFeatureExtractor
from ml.feature_engineering.email_features import EmailFeatureExtractor
from scipy.sparse import hstack, csr_matrix

# Import trusted domains loader
try:
    from detection_engine.trusted_domains_loader import TrustedDomainsLoader
    _trusted_loader = TrustedDomainsLoader()
    TRUSTED_DOMAINS = _trusted_loader.get_all_domains()
except Exception:
    # Fallback
    TRUSTED_DOMAINS = []


class PhishingPredictor:
    """Main predictor class for email and URL phishing detection"""
    
    def __init__(self):
        self.email_model = None
        self.email_vectorizer = None
        self.url_model = None
        self.models_loaded = False
        self._load_models()
    
    def _load_models(self):
        """Load trained models from disk"""
        models_dir = os.path.join(os.path.dirname(__file__), 'models')
        
        try:
            # Load email model
            email_model_path = os.path.join(models_dir, 'email_model.pkl')
            email_vectorizer_path = os.path.join(models_dir, 'email_vectorizer.pkl')
            
            with open(email_model_path, 'rb') as f:
                self.email_model = pickle.load(f)
            
            with open(email_vectorizer_path, 'rb') as f:
                self.email_vectorizer = pickle.load(f)
            
            # Load URL model
            url_model_path = os.path.join(models_dir, 'url_model.pkl')
            
            with open(url_model_path, 'rb') as f:
                self.url_model = pickle.load(f)
            
            self.models_loaded = True
            print("Models loaded successfully")
            
        except FileNotFoundError as e:
            print(f"Warning: Models not found. Please run train_models.py first. Error: {e}")
            self.models_loaded = False
        except Exception as e:
            print(f"Error loading models: {e}")
            self.models_loaded = False
    
    def predict_email(self, email_text, subject=""):
        """
        Predict if an email is phishing
        
        Args:
            email_text: String containing email content
            subject: Optional email subject line
            
        Returns:
            dict: Prediction result with score, label, and explanation
        """
        if not self.models_loaded:
            return {
                'error': 'Models not loaded. Please train models first.',
                'score': 0,
                'label': 'Unknown',
                'risk_level': 'Unknown',
                'explanation': 'System error: Models not available'
            }
        
        if not email_text or not email_text.strip():
            return {
                'score': 0,
                'label': 'Safe',
                'risk_level': 'Safe',
                'explanation': 'Empty email content provided'
            }
        
        # Clean text for TF-IDF
        cleaned_text = TextCleaner.clean(email_text)
        
        # Extract suspicious patterns for explanation
        patterns = TextCleaner.extract_suspicious_patterns(email_text)
        
        # Extract engineered features
        engineered_features = EmailFeatureExtractor.get_feature_vector(email_text, subject)
        engineered_array = csr_matrix([engineered_features])
        
        # Vectorize text with TF-IDF
        text_vector = self.email_vectorizer.transform([cleaned_text])
        
        # Combine features
        combined_vector = hstack([text_vector, engineered_array])
        
        # Predict
        phishing_prob = self.email_model.predict_proba(combined_vector)[0][1]
        prediction = self.email_model.predict(combined_vector)[0]
        
        # Calculate phishing score (0-100)
        phishing_score = int(phishing_prob * 100)
        
        # Check for trusted domains in email URLs
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_text)
        has_trusted_url = False
        for url in urls:
            if self._is_trusted_domain(url):
                has_trusted_url = True
                break
        
        # If email contains trusted domain URLs, reduce the phishing score
        if has_trusted_url and phishing_score > 40:
            phishing_score = max(15, phishing_score - 60)  # Reduce score significantly
        
        # Calculate trust score (inverse of phishing score) - this is what we display
        trust_score = 100 - phishing_score
        
        # Determine risk level based on trust score (per specification)
        # 0-30: Dangerous, 31-70: Suspicious, 71-100: Safe
        if trust_score <= 30:
            risk_level = 'Dangerous'
        elif trust_score <= 70:
            risk_level = 'Suspicious'
        else:
            risk_level = 'Safe'
        
        label = 'Phishing' if phishing_score > 60 else 'Safe'
        
        # Generate explanation
        explanation = self._generate_email_explanation(patterns, phishing_score, label)
        
        # Get detailed indicators
        indicators = self._get_email_indicators(patterns)
        
        # Add engineered feature indicators
        eng_features = EmailFeatureExtractor.extract_features(email_text, subject)
        if eng_features.get('num_urls', 0) > 0:
            indicators.append({'type': 'info', 'message': f"Contains {eng_features['num_urls']} URL(s)"})
        if eng_features.get('has_html', 0) == 1:
            indicators.append({'type': 'info', 'message': 'Contains HTML content'})
        
        return {
            'score': phishing_score,  # Keep for backward compatibility
            'trust_score': trust_score,
            'label': label,
            'risk_level': risk_level,
            'phishing_probability': round(phishing_prob, 4),
            'explanation': explanation,
            'indicators': indicators
        }
    
    def _is_trusted_domain(self, url):
        """Check if URL is from a trusted domain"""
        try:
            return _trusted_loader.is_trusted(url)
        except Exception:
            # Fallback to basic check
            from urllib.parse import urlparse
            
            if not url:
                return False
            
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                if ':' in domain:
                    domain = domain.split(':')[0]
                
                for trusted in TRUSTED_DOMAINS:
                    if domain == trusted or domain.endswith('.' + trusted):
                        return True
                return False
            except Exception:
                return False
    
    def predict_url(self, url):
        """
        Predict if a URL is phishing
        
        Args:
            url: String URL to analyze
            
        Returns:
            dict: Prediction result with trust_score (0-100, higher=safer), risk_level, and explanation
        """
        if not self.models_loaded:
            return {
                'error': 'Models not loaded. Please train models first.',
                'trust_score': 50,
                'score': 50,
                'label': 'Unknown',
                'risk_level': 'Unknown',
                'explanation': 'System error: Models not available'
            }
        
        if not url or not url.strip():
            return {
                'trust_score': 50,
                'score': 50,
                'label': 'Safe',
                'risk_level': 'Safe',
                'explanation': 'Empty URL provided'
            }
        
        # Check if domain is trusted - return safe immediately
        if self._is_trusted_domain(url):
            return {
                'trust_score': 95,
                'score': 5,
                'label': 'Safe',
                'risk_level': 'Safe',
                'phishing_probability': 0.05,
                'explanation': 'This URL belongs to a well-known, trusted website.',
                'features': URLFeatureExtractor._trusted_domain_features(),
                'indicators': [
                    {'type': 'positive', 'message': 'Trusted domain'},
                    {'type': 'positive', 'message': 'HTTPS enabled'},
                    {'type': 'positive', 'message': 'Popular website'}
                ]
            }
        
        # Extract features
        features = URLFeatureExtractor.extract_features(url)
        feature_vector = URLFeatureExtractor.get_feature_vector(url)
        
        # Predict
        feature_array = np.array([feature_vector])
        phishing_prob = self.url_model.predict_proba(feature_array)[0][1]
        prediction = self.url_model.predict(feature_array)[0]
        
        # Calculate trust score (0-100, where higher is safer)
        trust_score = int((1 - phishing_prob) * 100)
        phishing_score = int(phishing_prob * 100)
        
        # Determine risk level based on trust score
        risk_level = self._get_trust_risk_level(trust_score)
        label = 'Phishing' if prediction == 1 else 'Safe'
        
        # Generate explanation with trust score context
        explanation = self._generate_url_explanation_trust(features, trust_score, risk_level)
        
        # Get detailed indicators
        indicators = self._get_url_indicators_trust(features, trust_score)
        
        return {
            'trust_score': trust_score,
            'score': phishing_score,  # Keep for backward compatibility
            'label': label,
            'risk_level': risk_level,
            'phishing_probability': round(phishing_prob, 4),
            'explanation': explanation,
            'features': features,
            'indicators': indicators
        }
    
    def _get_risk_level(self, score):
        """Determine risk level based on phishing score (0-100)"""
        # Adjusted thresholds to reduce false positives
        if score <= 40:
            return 'Safe'
        elif score <= 75:
            return 'Suspicious'
        else:
            return 'Dangerous'
    
    def _get_trust_risk_level(self, trust_score):
        """Determine risk level based on trust score (0-100, higher=safer)"""
        if trust_score >= 71:
            return 'Safe'
        elif trust_score >= 31:
            return 'Suspicious'
        else:
            return 'Dangerous'
    
    def _generate_email_explanation(self, patterns, score, label):
        """Generate human-readable explanation for email prediction"""
        explanations = []
        
        if label == 'Safe':
            if score < 10:
                explanations.append("This email appears to be legitimate with no suspicious indicators detected.")
            else:
                explanations.append("This email appears to be safe, though a few minor indicators were found.")
        else:
            explanations.append("This email exhibits characteristics commonly associated with phishing attempts.")
        
        # Add specific pattern explanations
        indicators = []
        
        if patterns.get('urgent_words', 0) > 0:
            indicators.append(f"contains urgent language ({patterns['urgent_words']} instances)")
        
        if patterns.get('suspicious_keywords', 0) > 0:
            indicators.append(f"uses suspicious keywords like 'verify', 'account', or 'password' ({patterns['suspicious_keywords']} instances)")
        
        if patterns.get('threat_words', 0) > 0:
            indicators.append(f"contains threatening language about account suspension ({patterns['threat_words']} instances)")
        
        if patterns.get('reward_words', 0) > 0:
            indicators.append(f"mentions prizes or rewards ({patterns['reward_words']} instances)")
        
        if patterns.get('click_words', 0) > 0:
            indicators.append(f"contains suspicious click requests ({patterns['click_words']} instances)")
        
        if patterns.get('exclamation_count', 0) > 3:
            indicators.append(f"excessive use of exclamation marks ({patterns['exclamation_count']} found)")
        
        if indicators:
            explanations.append("Specific indicators: " + ", ".join(indicators) + ".")
        
        # Add recommendations
        if label == 'Phishing':
            explanations.append("Recommendation: Do not click any links or download attachments. Verify sender identity through a separate channel.")
        
        return " ".join(explanations)
    
    def _generate_url_explanation(self, features, score, label):
        """Generate human-readable explanation for URL prediction"""
        explanations = []
        
        if label == 'Safe':
            if score < 10:
                explanations.append("This URL appears to be legitimate with no suspicious characteristics detected.")
            else:
                explanations.append("This URL appears to be safe, with minimal suspicious characteristics.")
        else:
            explanations.append("This URL exhibits structural characteristics commonly associated with phishing websites.")
        
        # Add specific feature explanations
        indicators = []
        
        if features.get('has_ip_address', 0) == 1:
            indicators.append("uses an IP address instead of a domain name")
        
        if features.get('has_at_symbol', 0) == 1:
            indicators.append("contains '@' symbol (commonly used to trick users)")
        
        if features.get('is_shortened', 0) == 1:
            indicators.append("uses a URL shortening service (hides true destination)")
        
        if features.get('has_suspicious_tld', 0) == 1:
            indicators.append("uses a suspicious top-level domain")
        
        if features.get('suspicious_keywords_count', 0) > 0:
            indicators.append(f"contains suspicious keywords ({features['suspicious_keywords_count']} found)")
        
        if features.get('subdomain_count', 0) > 2:
            indicators.append(f"has excessive subdomains ({features['subdomain_count']} levels)")
        
        if features.get('url_length', 0) > 100:
            indicators.append("unusually long URL (may be trying to hide malicious domain)")
        
        if features.get('has_https', 0) == 0:
            indicators.append("does not use HTTPS encryption")
        
        if indicators:
            explanations.append("Specific indicators: " + ", ".join(indicators) + ".")
        
        # Add recommendations
        if label == 'Phishing':
            explanations.append("Recommendation: Do not visit this URL. If you need to access the service, type the known legitimate address directly into your browser.")
        
        return " ".join(explanations)
    
    def _generate_url_explanation_trust(self, features, trust_score, risk_level):
        """Generate human-readable explanation based on trust score"""
        explanations = []
        
        if risk_level == 'Safe':
            explanations.append("This URL appears to be safe and legitimate.")
        elif risk_level == 'Suspicious':
            explanations.append("This URL has some unusual characteristics that warrant caution.")
        else:
            explanations.append("This URL exhibits multiple characteristics commonly associated with phishing websites.")
        
        # Add specific feature explanations with icons
        negative_indicators = []
        positive_indicators = []
        
        # Negative indicators
        if features.get('has_ip_address', 0) == 1:
            negative_indicators.append("URL uses IP address instead of domain name")
        
        if features.get('has_at_symbol', 0) == 1:
            negative_indicators.append("URL contains @ symbol (redirection trick)")
        
        if features.get('is_shortened', 0) == 1:
            negative_indicators.append("URL uses a shortening service (hides true destination)")
        
        if features.get('has_suspicious_tld', 0) == 1:
            negative_indicators.append("Suspicious top-level domain detected")
        
        if features.get('suspicious_keywords_count', 0) > 0:
            negative_indicators.append(f"Suspicious keywords detected ({features['suspicious_keywords_count']})")
        
        if features.get('subdomain_count', 0) > 2:
            negative_indicators.append(f"Excessive subdomains ({features['subdomain_count']} levels)")
        
        if features.get('url_length', 0) > 75:
            negative_indicators.append("Abnormally long URL structure")
        
        if features.get('has_https', 0) == 0:
            negative_indicators.append("Connection is not encrypted (no HTTPS)")
        
        # Positive indicators
        if features.get('has_https', 0) == 1:
            positive_indicators.append("HTTPS encryption enabled")
        
        if features.get('url_length', 0) < 50 and features.get('suspicious_keywords_count', 0) == 0:
            positive_indicators.append("Normal URL structure")
        
        if features.get('subdomain_count', 0) <= 1:
            positive_indicators.append("Simple domain structure")
        
        # Build explanation
        if negative_indicators:
            explanations.append("Negative signals: " + "; ".join(negative_indicators) + ".")
        
        if positive_indicators and risk_level != 'Dangerous':
            explanations.append("Positive signals: " + "; ".join(positive_indicators) + ".")
        
        # Add recommendations
        if risk_level == 'Dangerous':
            explanations.append("Recommendation: Do NOT visit this website. If you need the service, type the known legitimate address directly into your browser.")
        elif risk_level == 'Suspicious':
            explanations.append("Recommendation: Exercise caution. Verify the website through official channels before entering any information.")
        
        return " ".join(explanations)
    
    def _get_email_indicators(self, patterns):
        """Get list of email risk indicators"""
        indicators = []
        
        if patterns.get('urgent_words', 0) > 0:
            indicators.append({'type': 'warning', 'message': f"Urgent language detected ({patterns['urgent_words']} instances)"})
        
        if patterns.get('suspicious_keywords', 0) > 0:
            indicators.append({'type': 'warning', 'message': f"Suspicious keywords detected ({patterns['suspicious_keywords']} instances)"})
        
        if patterns.get('threat_words', 0) > 0:
            indicators.append({'type': 'danger', 'message': f"Threatening language detected ({patterns['threat_words']} instances)"})
        
        if patterns.get('reward_words', 0) > 0:
            indicators.append({'type': 'caution', 'message': f"Reward/ prize mentions ({patterns['reward_words']} instances)"})
        
        if patterns.get('click_words', 0) > 0:
            indicators.append({'type': 'warning', 'message': f"Suspicious click requests ({patterns['click_words']} instances)"})
        
        return indicators
    
    def _get_url_indicators(self, features):
        """Get list of URL risk indicators"""
        indicators = []
        
        if features.get('has_ip_address', 0) == 1:
            indicators.append({'type': 'danger', 'message': 'URL uses IP address instead of domain name'})
        
        if features.get('has_at_symbol', 0) == 1:
            indicators.append({'type': 'danger', 'message': 'URL contains @ symbol (redirection trick)'})
        
        if features.get('is_shortened', 0) == 1:
            indicators.append({'type': 'warning', 'message': 'URL uses a shortening service'})
        
        if features.get('has_suspicious_tld', 0) == 1:
            indicators.append({'type': 'warning', 'message': 'Suspicious top-level domain detected'})
        
        if features.get('suspicious_keywords_count', 0) > 0:
            indicators.append({'type': 'warning', 'message': f"Suspicious keywords in URL ({features['suspicious_keywords_count']})"})
        
        if features.get('subdomain_count', 0) > 2:
            indicators.append({'type': 'caution', 'message': f"Excessive subdomains ({features['subdomain_count']})"})
        
        if features.get('has_https', 0) == 0:
            indicators.append({'type': 'caution', 'message': 'Connection is not encrypted (no HTTPS)'})
        
        return indicators
    
    def _get_url_indicators_trust(self, features, trust_score):
        """Get list of URL risk indicators with trust-based icons"""
        indicators = []
        
        # Danger indicators (red)
        if features.get('has_ip_address', 0) == 1:
            indicators.append({'type': 'danger', 'message': 'URL uses IP address instead of domain name'})
        
        if features.get('has_at_symbol', 0) == 1:
            indicators.append({'type': 'danger', 'message': 'URL contains @ symbol (redirection trick)'})
        
        if features.get('suspicious_keywords_count', 0) >= 4:
            indicators.append({'type': 'danger', 'message': f"Multiple suspicious keywords ({features['suspicious_keywords_count']})"})
        
        if features.get('subdomain_count', 0) >= 3:
            indicators.append({'type': 'danger', 'message': f"Excessive subdomains ({features['subdomain_count']} levels) - possible brand impersonation"})
        
        # Warning indicators (orange)
        if features.get('is_shortened', 0) == 1:
            indicators.append({'type': 'warning', 'message': 'URL uses a shortening service'})
        
        if features.get('has_suspicious_tld', 0) == 1:
            indicators.append({'type': 'warning', 'message': 'Suspicious top-level domain detected'})
        
        if features.get('suspicious_keywords_count', 0) > 0 and features.get('suspicious_keywords_count', 0) < 4:
            indicators.append({'type': 'warning', 'message': f"Suspicious keywords detected ({features['suspicious_keywords_count']})"})
        
        if features.get('url_length', 0) > 75:
            indicators.append({'type': 'warning', 'message': 'Abnormally long URL structure'})
        
        # Caution indicators (yellow)
        if features.get('subdomain_count', 0) > 1 and features.get('subdomain_count', 0) < 3:
            indicators.append({'type': 'caution', 'message': f"Multiple subdomains ({features['subdomain_count']})"})
        
        if features.get('has_https', 0) == 0:
            indicators.append({'type': 'caution', 'message': 'Connection is not encrypted (no HTTPS)'})
        
        # Positive indicators (green) - only for safer URLs
        if trust_score >= 70:
            if features.get('has_https', 0) == 1:
                indicators.append({'type': 'positive', 'message': 'HTTPS encryption enabled'})
            
            if features.get('url_length', 0) < 50:
                indicators.append({'type': 'positive', 'message': 'Normal URL length'})
            
            if features.get('subdomain_count', 0) <= 1:
                indicators.append({'type': 'positive', 'message': 'Simple domain structure'})
            
            if features.get('suspicious_keywords_count', 0) == 0:
                indicators.append({'type': 'positive', 'message': 'No suspicious keywords detected'})
        
        return indicators


# Singleton instance for reuse
_predictor_instance = None

def get_predictor():
    """Get or create predictor instance"""
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = PhishingPredictor()
    return _predictor_instance


if __name__ == "__main__":
    # Test the predictor
    predictor = get_predictor()
    
    # Test email prediction
    test_email = """
    URGENT: Your account has been compromised!
    
    Dear Customer,
    
    We have detected suspicious activity on your account. 
    Please verify your account immediately by clicking the link below.
    
    Click here to verify: http://suspicious-bank.com/verify
    
    Failure to verify within 24 hours will result in account suspension.
    
    Thank you,
    Security Team
    """
    
    print("=" * 60)
    print("Email Prediction Test")
    print("=" * 60)
    result = predictor.predict_email(test_email)
    print(f"Score: {result['score']}")
    print(f"Label: {result['label']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Explanation: {result['explanation']}")
    
    # Test URL prediction
    test_url = "http://192.168.1.1/bank/verify/login.php"
    
    print("\n" + "=" * 60)
    print("URL Prediction Test")
    print("=" * 60)
    result = predictor.predict_url(test_url)
    print(f"Score: {result['score']}")
    print(f"Label: {result['label']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Explanation: {result['explanation']}")
