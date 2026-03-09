"""
Website Analyzer
Main orchestrator for website safety analysis
"""

from .domain_intelligence import DomainIntelligence
from .ssl_checker import SSLChecker
from .reputation_checker import ReputationChecker
from .trust_score import TrustScoreEngine
import sys
import os

# Add parent directory to path for ML imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.predictor import get_predictor


class WebsiteAnalyzer:
    """Comprehensive website safety analyzer"""
    
    def __init__(self):
        self.domain_intel = DomainIntelligence()
        self.ssl_checker = SSLChecker()
        self.reputation_checker = ReputationChecker()
        self.trust_engine = TrustScoreEngine()
        self.ml_predictor = get_predictor()
    
    def analyze(self, url):
        """
        Perform comprehensive website analysis
        
        Args:
            url: URL to analyze
            
        Returns:
            dict: Complete analysis results
        """
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        result = {
            'url': url,
            'domain': None,
            'trust_score': 0,
            'risk_level': 'Unknown',
            'confidence': 'Low',
            'analysis_time': None,
            'domain_data': {},
            'ssl_data': {},
            'reputation_data': {},
            'ml_prediction': {},
            'positive_signals': [],
            'negative_signals': [],
            'recommendation': {},
            'errors': []
        }
        
        all_signals = []
        
        try:
            # 1. Domain Intelligence Analysis
            try:
                result['domain_data'] = self.domain_intel.analyze(url)
                domain_signals = self.domain_intel.get_risk_signals(result['domain_data'])
                all_signals.extend(domain_signals)
                result['domain'] = result['domain_data'].get('domain')
            except Exception as e:
                result['errors'].append(f'Domain analysis error: {str(e)}')
            
            # 2. SSL Certificate Analysis
            try:
                result['ssl_data'] = self.ssl_checker.check(url)
                ssl_signals = self.ssl_checker.get_risk_signals(result['ssl_data'])
                all_signals.extend(ssl_signals)
            except Exception as e:
                result['errors'].append(f'SSL analysis error: {str(e)}')
            
            # 3. Reputation Analysis
            try:
                result['reputation_data'] = self.reputation_checker.check(url)
                reputation_signals = self.reputation_checker.get_risk_signals(result['reputation_data'])
                all_signals.extend(reputation_signals)
            except Exception as e:
                result['errors'].append(f'Reputation analysis error: {str(e)}')
            
            # 4. ML Prediction
            try:
                if self.ml_predictor.models_loaded:
                    ml_result = self.ml_predictor.predict_url(url)
                    result['ml_prediction'] = {
                        'score': ml_result['score'],
                        'label': ml_result['label'],
                        'probability': ml_result['phishing_probability']
                    }
                    ml_score = ml_result['score']
                else:
                    ml_score = None
                    result['errors'].append('ML models not loaded')
            except Exception as e:
                result['errors'].append(f'ML prediction error: {str(e)}')
                ml_score = None
            
            # 5. Calculate Trust Score
            trust_result = self.trust_engine.calculate(all_signals, ml_score)
            result['trust_score'] = trust_result['trust_score']
            result['risk_level'] = trust_result['risk_level']
            result['confidence'] = trust_result['confidence']
            result['positive_signals'] = trust_result['positive_signals']
            result['negative_signals'] = trust_result['negative_signals']
            result['recommendation'] = trust_result['recommendation']
            
            # Get score breakdown
            result['score_breakdown'] = self.trust_engine.get_score_breakdown(all_signals, ml_score)
            
        except Exception as e:
            result['errors'].append(f'General analysis error: {str(e)}')
        
        return result
    
    def quick_check(self, url):
        """
        Quick check for basic safety indicators
        
        Args:
            url: URL to check
            
        Returns:
            dict: Quick check results
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        result = {
            'url': url,
            'is_safe': False,
            'risk_level': 'Unknown',
            'quick_signals': []
        }
        
        signals = []
        
        # Quick reputation check
        rep_data = self.reputation_checker.check(url)
        rep_signals = self.reputation_checker.get_risk_signals(rep_data)
        signals.extend(rep_signals)
        
        # Quick SSL check
        ssl_data = self.ssl_checker.check(url)
        if ssl_data.get('has_https'):
            signals.append({
                'type': 'positive',
                'category': 'ssl',
                'message': 'HTTPS enabled',
                'impact': 10
            })
        
        # Calculate quick score
        score = 50 + sum(s.get('impact', 0) for s in signals)
        score = max(0, min(100, score))
        
        result['trust_score'] = score
        result['risk_level'] = 'Safe' if score >= 71 else ('Suspicious' if score >= 31 else 'Dangerous')
        result['is_safe'] = score >= 71
        result['quick_signals'] = signals
        
        return result


# Singleton instance
_analyzer_instance = None

def get_analyzer():
    """Get or create analyzer instance"""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = WebsiteAnalyzer()
    return _analyzer_instance
