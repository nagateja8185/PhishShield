"""
Email Feature Engineering Module for PhishShield
Extracts phishing indicators from email content
"""

import re
import string
from urllib.parse import urlparse


class EmailFeatureExtractor:
    """Extract features from email text for phishing detection"""
    
    # Suspicious keywords commonly found in phishing emails
    SUSPICIOUS_KEYWORDS = [
        'verify', 'verify your', 'account verify', 'verification',
        'login', 'log in', 'sign in', 'signin',
        'password', 'passcode', 'credential',
        'update', 'update your', 'account update',
        'confirm', 'confirmation', 'confirm your',
        'bank', 'banking', 'credit card', 'debit card',
        'urgent', 'immediately', 'immediate action', 'asap',
        'suspended', 'suspension', 'restricted', 'locked',
        'unauthorized', 'unusual activity', 'suspicious activity',
        'click here', 'click below', 'click the link',
        'limited time', 'expires', 'expiration', 'deadline',
        'free', 'won', 'winner', 'prize', 'reward', 'bonus',
        'claim', 'claim now', 'collect your',
        'congratulations', 'you won', 'you have won',
        'social security', 'ssn', 'tax id', 'personal information',
        'security alert', 'security warning', 'important notice'
    ]
    
    # Urgency indicators
    URGENCY_WORDS = [
        'urgent', 'immediate', 'immediately', 'asap', 'hurry',
        'quick', 'quickly', 'fast', 'now', 'today',
        'limited time', 'expires', 'expiration', 'deadline',
        'last chance', 'final notice', 'warning', 'alert',
        'act now', 'don\'t wait', 'time sensitive'
    ]
    
    # Threat indicators
    THREAT_WORDS = [
        'suspend', 'suspended', 'suspension', 'terminate', 'terminated',
        'termination', 'block', 'blocked', 'restrict', 'restricted',
        'disable', 'disabled', 'close', 'closed', 'cancel', 'cancelled',
        'unauthorized', 'suspicious', 'fraud', 'fraudulent',
        'security breach', 'account compromised', 'unusual activity'
    ]
    
    @staticmethod
    def extract_features(email_text, subject=""):
        """
        Extract comprehensive features from email text
        
        Args:
            email_text: The body/content of the email
            subject: The email subject line (optional)
            
        Returns:
            dict: Dictionary of extracted features
        """
        if not email_text:
            email_text = ""
        if not subject:
            subject = ""
            
        text = str(email_text)
        full_text = str(subject) + " " + text
        text_lower = full_text.lower()
        
        features = {}
        
        # Basic text statistics
        features['email_length'] = len(text)
        features['subject_length'] = len(str(subject))
        features['total_length'] = len(full_text)
        
        # URL-related features
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        features['num_urls'] = len(urls)
        features['has_url'] = 1 if len(urls) > 0 else 0
        
        # URL domain analysis
        suspicious_domains = 0
        ip_urls = 0
        short_urls = 0
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # Check for IP-based URLs
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    ip_urls += 1
                    
                # Check for URL shorteners
                shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 
                             'short.link', 'is.gd', 'buff.ly', 'adf.ly']
                if any(s in domain for s in shorteners):
                    short_urls += 1
                    
                # Check for suspicious TLDs
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.click', '.link']
                if any(domain.endswith(tld) for tld in suspicious_tlds):
                    suspicious_domains += 1
                    
            except:
                pass
        
        features['ip_urls'] = ip_urls
        features['short_urls'] = short_urls
        features['suspicious_domains'] = suspicious_domains
        
        # Email address features
        emails = re.findall(r'\S+@\S+', text)
        features['num_emails'] = len(emails)
        
        # HTML content features
        features['has_html'] = 1 if any(tag in text_lower for tag in ['<html>', '<body>', '<div>', '<table>']) else 0
        features['has_form'] = 1 if '<form' in text_lower else 0
        features['has_script'] = 1 if '<script' in text_lower else 0
        features['has_iframe'] = 1 if '<iframe' in text_lower else 0
        
        # Punctuation and formatting
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['dollar_count'] = text.count('$')
        features['percent_count'] = text.count('%')
        features['all_caps_words'] = len(re.findall(r'\b[A-Z]{3,}\b', text))
        features['digit_count'] = sum(c.isdigit() for c in text)
        
        # Suspicious keyword counts
        features['suspicious_keywords'] = sum(1 for keyword in EmailFeatureExtractor.SUSPICIOUS_KEYWORDS 
                                             if keyword in text_lower)
        features['urgency_words'] = sum(1 for word in EmailFeatureExtractor.URGENCY_WORDS 
                                       if word in text_lower)
        features['threat_words'] = sum(1 for word in EmailFeatureExtractor.THREAT_WORDS 
                                      if word in text_lower)
        
        # Special phishing indicators
        features['has_verify'] = 1 if 'verify' in text_lower else 0
        features['has_urgent'] = 1 if 'urgent' in text_lower else 0
        features['has_account'] = 1 if 'account' in text_lower else 0
        features['has_password'] = 1 if any(word in text_lower for word in ['password', 'passcode']) else 0
        features['has_bank'] = 1 if any(word in text_lower for word in ['bank', 'credit card', 'debit']) else 0
        features['has_update'] = 1 if 'update' in text_lower else 0
        features['has_confirm'] = 1 if 'confirm' in text_lower else 0
        features['has_suspended'] = 1 if any(word in text_lower for word in ['suspend', 'suspended', 'locked']) else 0
        features['has_click_here'] = 1 if 'click here' in text_lower else 0
        features['has_limited_time'] = 1 if any(phrase in text_lower for phrase in ['limited time', 'expires soon']) else 0
        features['has_won'] = 1 if any(word in text_lower for word in ['won', 'winner', 'congratulations']) else 0
        features['has_free'] = 1 if 'free' in text_lower else 0
        
        # Subject line features
        subject_lower = str(subject).lower()
        features['subject_exclamation'] = str(subject).count('!')
        features['subject_question'] = str(subject).count('?')
        features['subject_all_caps'] = 1 if str(subject).isupper() and len(str(subject)) > 5 else 0
        features['subject_has_urgent'] = 1 if 'urgent' in subject_lower else 0
        features['subject_has_verify'] = 1 if 'verify' in subject_lower else 0
        
        return features
    
    @staticmethod
    def get_feature_names():
        """Return list of feature names in consistent order"""
        dummy_features = EmailFeatureExtractor.extract_features("test", "test")
        return list(dummy_features.keys())
    
    @staticmethod
    def get_feature_vector(email_text, subject=""):
        """Get feature values as a list in consistent order"""
        features = EmailFeatureExtractor.extract_features(email_text, subject)
        return list(features.values())
