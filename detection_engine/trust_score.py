"""
Trust Score Engine
Combines all signals to calculate final trust score
"""


class TrustScoreEngine:
    """Calculate trust score based on all analysis signals"""
    
    def __init__(self):
        self.weights = {
            'domain_age': 0.25,
            'ssl': 0.20,
            'reputation': 0.20,
            'ml_prediction': 0.25,
            'whois': 0.10
        }
    
    def calculate(self, signals, ml_score=None):
        """
        Calculate trust score from all signals
        
        Args:
            signals: List of signal dictionaries with 'impact' key
            ml_score: Optional ML model score (0-100, where higher = more phishing)
            
        Returns:
            dict: Trust score results
        """
        # Start with perfect score
        base_score = 100
        
        # Apply all signal impacts
        total_impact = 0
        positive_signals = []
        negative_signals = []
        
        for signal in signals:
            impact = signal.get('impact', 0)
            total_impact += impact
            
            # Categorize signal
            signal_info = {
                'category': signal.get('category', 'general'),
                'message': signal.get('message', ''),
                'impact': impact
            }
            
            if impact > 0:
                positive_signals.append(signal_info)
            elif impact < 0:
                negative_signals.append(signal_info)
        
        # Calculate preliminary score
        score = base_score + total_impact
        
        # Incorporate ML score if available (invert because ML score is phishing probability)
        if ml_score is not None:
            # ML score is 0-100 where 100 = definitely phishing
            # Convert to trust contribution (0 = phishing, 100 = safe)
            ml_trust = 100 - ml_score
            # Weight the ML score
            score = (score * 0.7) + (ml_trust * 0.3)
        
        # Clamp to 0-100 range
        score = max(0, min(100, score))
        
        # Determine risk level
        risk_level = self._get_risk_level(score)
        
        # Calculate confidence based on number of signals
        confidence = self._calculate_confidence(signals)
        
        return {
            'trust_score': round(score),
            'risk_level': risk_level,
            'confidence': confidence,
            'positive_signals': sorted(positive_signals, key=lambda x: abs(x['impact']), reverse=True),
            'negative_signals': sorted(negative_signals, key=lambda x: abs(x['impact']), reverse=True),
            'total_signals': len(signals),
            'recommendation': self._get_recommendation(risk_level, score)
        }
    
    def _get_risk_level(self, score):
        """Determine risk level from score"""
        if score >= 71:
            return 'Safe'
        elif score >= 31:
            return 'Suspicious'
        else:
            return 'Dangerous'
    
    def _calculate_confidence(self, signals):
        """Calculate confidence level based on number of signals"""
        signal_count = len(signals)
        
        if signal_count >= 8:
            return 'High'
        elif signal_count >= 4:
            return 'Medium'
        else:
            return 'Low'
    
    def _get_recommendation(self, risk_level, score):
        """Get recommendation based on risk level"""
        recommendations = {
            'Safe': {
                'title': 'This website appears to be safe',
                'actions': [
                    'You can proceed with caution',
                    'Always verify you are on the correct website before entering credentials',
                    'Ensure the connection is secure (look for the lock icon)'
                ]
            },
            'Suspicious': {
                'title': 'Exercise caution with this website',
                'actions': [
                    'Verify the website through official channels before proceeding',
                    'Do not enter sensitive information unless you are certain it is legitimate',
                    'Check for HTTPS and valid certificates',
                    'Look for contact information and verify it'
                ]
            },
            'Dangerous': {
                'title': 'This website is likely dangerous',
                'actions': [
                    'DO NOT visit this website',
                    'Do not enter any credentials or personal information',
                    'If you need the service, type the known legitimate address directly',
                    'Report this URL to your security team or authorities'
                ]
            }
        }
        
        return recommendations.get(risk_level, recommendations['Suspicious'])
    
    def get_score_breakdown(self, signals, ml_score=None):
        """
        Get detailed score breakdown by category
        
        Returns:
            dict: Score breakdown by category
        """
        categories = {}
        
        for signal in signals:
            category = signal.get('category', 'general')
            impact = signal.get('impact', 0)
            
            if category not in categories:
                categories[category] = {
                    'total_impact': 0,
                    'signal_count': 0,
                    'signals': []
                }
            
            categories[category]['total_impact'] += impact
            categories[category]['signal_count'] += 1
            categories[category]['signals'].append({
                'message': signal.get('message', ''),
                'impact': impact,
                'type': signal.get('type', 'info')
            })
        
        # Add ML score if available
        if ml_score is not None:
            categories['ml_prediction'] = {
                'total_impact': (100 - ml_score) - 50,  # Convert to impact
                'signal_count': 1,
                'signals': [{
                    'message': f'ML model detected {ml_score}% phishing probability',
                    'impact': (100 - ml_score) - 50,
                    'type': 'ml'
                }]
            }
        
        return categories
