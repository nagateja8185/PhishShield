"""
Text Preprocessing Module for Email Analysis
"""

import re
import string


class TextCleaner:
    """Clean and preprocess email text for analysis"""
    
    @staticmethod
    def clean(text):
        """
        Clean email text by:
        - Converting to lowercase
        - Removing URLs
        - Removing email addresses
        - Removing special characters
        - Removing extra whitespace
        
        Args:
            text: Raw email text
            
        Returns:
            str: Cleaned text
        """
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove URLs
        text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', ' ', text)
        text = re.sub(r'www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', ' ', text)
        
        # Remove email addresses
        text = re.sub(r'\S+@\S+', ' ', text)
        
        # Remove numbers
        text = re.sub(r'\d+', ' ', text)
        
        # Remove punctuation
        text = text.translate(str.maketrans('', '', string.punctuation))
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text
    
    @staticmethod
    def extract_suspicious_patterns(text):
        """
        Extract suspicious patterns from email text
        
        Args:
            text: Raw email text
            
        Returns:
            dict: Dictionary of suspicious pattern counts
        """
        if not text:
            return {}
        
        text_lower = text.lower()
        
        patterns = {
            'urgent_words': len(re.findall(r'\b(urgent|immediate|action required|asap|hurry|limited time|expires?|deadline)\b', text_lower)),
            'suspicious_keywords': len(re.findall(r'\b(verify|confirm|update|account|password|credit card|bank|login|credential|ssn|social security)\b', text_lower)),
            'threat_words': len(re.findall(r'\b(suspend|terminate|block|restrict|disable|close|cancel|unauthorized|suspicious activity)\b', text_lower)),
            'reward_words': len(re.findall(r'\b(won|winner|prize|reward|bonus|free|gift|claim|collect|congratulations)\b', text_lower)),
            'click_words': len(re.findall(r'\b(click here|click below|click the link|follow the link|visit|go to)\b', text_lower)),
            'exclamation_count': text.count('!'),
            'all_caps_words': len(re.findall(r'\b[A-Z]{3,}\b', text)),
            'dollar_signs': text.count('$'),
        }
        
        return patterns
