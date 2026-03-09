/**
 * Website Analyzer Module
 * Handles comprehensive website safety analysis UI
 */

// Example URLs for testing
const EXAMPLE_SUSPICIOUS_URL = 'http://paypal-security-update-login.com/verify';
const EXAMPLE_SAFE_URL = 'https://www.google.com';
const EXAMPLE_NEW_DOMAIN = 'http://shop-now-deals.xyz';

/**
 * Load example URL into the input
 */
function loadExample() {
    const input = document.getElementById('url-input');
    const examples = [EXAMPLE_SUSPICIOUS_URL, EXAMPLE_SAFE_URL, EXAMPLE_NEW_DOMAIN];
    const randomExample = examples[Math.floor(Math.random() * examples.length)];
    input.value = randomExample;
}

/**
 * Clear the input field
 */
function clearInput() {
    const input = document.getElementById('url-input');
    input.value = '';
    hideResult();
}

/**
 * Hide the result section
 */
function hideResult() {
    const resultSection = document.getElementById('result-section');
    resultSection.style.display = 'none';
}

/**
 * Show loading state
 */
function showLoading() {
    const loadingOverlay = document.getElementById('loading-overlay');
    loadingOverlay.style.display = 'flex';
}

/**
 * Hide loading state
 */
function hideLoading() {
    const loadingOverlay = document.getElementById('loading-overlay');
    loadingOverlay.style.display = 'none';
}

/**
 * Analyze the website
 */
async function analyzeWebsite() {
    const input = document.getElementById('url-input');
    const url = input.value.trim();
    
    if (!url) {
        alert('Please enter a URL to analyze');
        return;
    }
    
    // Basic URL validation
    if (!isValidURL(url)) {
        alert('Please enter a valid URL');
        return;
    }
    
    showLoading();
    
    try {
        const result = await analyzeWebsiteAPI(url);
        displayResult(result);
        saveScanToHistory({
            type: 'website',
            url: url,
            score: 100 - result.trust_score, // Invert for consistency with other scans
            label: result.risk_level === 'Safe' ? 'Safe' : 'Suspicious',
            risk_level: result.risk_level
        });
    } catch (error) {
        alert('Error analyzing website: ' + error.message);
    } finally {
        hideLoading();
    }
}

/**
 * Call the website analysis API
 * @param {string} url - URL to analyze
 * @returns {Promise<Object>} Analysis result
 */
async function analyzeWebsiteAPI(url) {
    const response = await fetch('/analyze-website', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to analyze website');
    }

    return await response.json();
}

/**
 * Validate URL format
 * @param {string} url - URL to validate
 * @returns {boolean} Whether URL is valid
 */
function isValidURL(url) {
    const pattern = /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/;
    return pattern.test(url) || url.includes('.');
}

/**
 * Display the analysis result
 * @param {Object} result - Analysis result
 */
function displayResult(result) {
    const resultSection = document.getElementById('result-section');
    const trustScoreCircle = document.getElementById('trust-score-circle');
    const trustScoreValue = document.getElementById('trust-score-value');
    const riskLevel = document.getElementById('risk-level');
    const confidenceBadge = document.getElementById('confidence-badge');
    const domainDisplay = document.getElementById('domain-display');
    const timestamp = document.getElementById('timestamp');
    
    // Show result section
    resultSection.style.display = 'block';
    
    // Update timestamp
    timestamp.textContent = new Date().toLocaleString();
    
    // Update trust score display
    const score = result.trust_score;
    trustScoreValue.textContent = score;
    
    // Set score color based on risk level
    const scoreColor = getScoreColor(result.risk_level);
    trustScoreCircle.style.setProperty('--score-color', scoreColor);
    trustScoreCircle.style.setProperty('--score-percent', score + '%');
    
    // Update risk level
    riskLevel.textContent = result.risk_level;
    riskLevel.style.color = scoreColor;
    
    // Update confidence
    confidenceBadge.textContent = result.confidence + ' Confidence';
    
    // Update domain display
    domainDisplay.textContent = result.domain || result.url;
    
    // Update signals
    updateSignals(result.positive_signals, result.negative_signals);
    
    // Update technical details
    updateTechnicalDetails(result);
    
    // Update recommendation
    updateRecommendation(result.recommendation);
    
    // Scroll to result
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Get color for score based on risk level
 * @param {string} riskLevel - Risk level
 * @returns {string} CSS color
 */
function getScoreColor(riskLevel) {
    switch (riskLevel.toLowerCase()) {
        case 'safe':
            return '#10b981';
        case 'suspicious':
            return '#f59e0b';
        case 'dangerous':
            return '#ef4444';
        default:
            return '#64748b';
    }
}

/**
 * Update signals display
 * @param {Array} positive - Positive signals
 * @param {Array} negative - Negative signals
 */
function updateSignals(positive, negative) {
    const positiveList = document.getElementById('positive-signals-list');
    const negativeList = document.getElementById('negative-signals-list');
    const positiveCard = document.getElementById('positive-signals-card');
    const negativeCard = document.getElementById('negative-signals-card');
    
    // Update positive signals
    positiveList.innerHTML = '';
    if (positive && positive.length > 0) {
        positive.forEach(signal => {
            const li = document.createElement('li');
            li.className = 'signal-item';
            li.innerHTML = `
                <span class="signal-icon positive">&#10003;</span>
                <div class="signal-content">
                    <div>${signal.message}</div>
                    <span class="signal-impact positive">+${signal.impact} pts</span>
                </div>
            `;
            positiveList.appendChild(li);
        });
        positiveCard.style.display = 'block';
    } else {
        positiveList.innerHTML = '<li class="signal-item"><span class="signal-icon">&#8226;</span><div class="signal-content">No positive signals detected</div></li>';
    }
    
    // Update negative signals
    negativeList.innerHTML = '';
    if (negative && negative.length > 0) {
        negative.forEach(signal => {
            const li = document.createElement('li');
            li.className = 'signal-item';
            li.innerHTML = `
                <span class="signal-icon negative">&#10007;</span>
                <div class="signal-content">
                    <div>${signal.message}</div>
                    <span class="signal-impact negative">${signal.impact} pts</span>
                </div>
            `;
            negativeList.appendChild(li);
        });
        negativeCard.style.display = 'block';
    } else {
        negativeList.innerHTML = '<li class="signal-item"><span class="signal-icon">&#8226;</span><div class="signal-content">No negative signals detected</div></li>';
    }
}

/**
 * Update technical details
 * @param {Object} result - Analysis result
 */
function updateTechnicalDetails(result) {
    const domainData = result.domain_data || {};
    const sslData = result.ssl_data || {};
    const mlPrediction = result.ml_prediction || {};
    
    // Domain age
    const domainAgeEl = document.getElementById('detail-domain-age');
    if (domainData.domain_age_days !== null && domainData.domain_age_days !== undefined) {
        const years = Math.floor(domainData.domain_age_days / 365);
        const days = domainData.domain_age_days % 365;
        if (years > 0) {
            domainAgeEl.textContent = `${years} year${years > 1 ? 's' : ''} ${days} days`;
        } else {
            domainAgeEl.textContent = `${domainData.domain_age_days} days`;
        }
    } else {
        domainAgeEl.textContent = 'Unknown';
    }
    
    // IP Address
    const ipEl = document.getElementById('detail-ip');
    ipEl.textContent = domainData.ip_address || 'Unknown';
    
    // SSL Certificate
    const sslEl = document.getElementById('detail-ssl');
    if (sslData.certificate_valid) {
        const daysLeft = sslData.days_until_expiry;
        if (daysLeft !== null && daysLeft !== undefined) {
            sslEl.textContent = `Valid (${daysLeft} days left)`;
            sslEl.style.color = daysLeft > 30 ? '#10b981' : '#f59e0b';
        } else {
            sslEl.textContent = 'Valid';
            sslEl.style.color = '#10b981';
        }
    } else {
        sslEl.textContent = sslData.error || 'Invalid/Not found';
        sslEl.style.color = '#ef4444';
    }
    
    // HTTPS
    const httpsEl = document.getElementById('detail-https');
    if (sslData.has_https) {
        httpsEl.textContent = 'Enabled';
        httpsEl.style.color = '#10b981';
    } else {
        httpsEl.textContent = 'Not enabled';
        httpsEl.style.color = '#ef4444';
    }
    
    // WHOIS Privacy
    const whoisEl = document.getElementById('detail-whois');
    if (domainData.whois_hidden) {
        whoisEl.textContent = 'Hidden (Privacy Protection)';
        whoisEl.style.color = '#f59e0b';
    } else {
        whoisEl.textContent = 'Public';
        whoisEl.style.color = '#10b981';
    }
    
    // ML Prediction
    const mlEl = document.getElementById('detail-ml');
    if (mlPrediction.score !== undefined) {
        const mlScore = mlPrediction.score;
        mlEl.textContent = `${mlScore}% phishing probability`;
        if (mlScore < 30) {
            mlEl.style.color = '#10b981';
        } else if (mlScore < 70) {
            mlEl.style.color = '#f59e0b';
        } else {
            mlEl.style.color = '#ef4444';
        }
    } else {
        mlEl.textContent = 'Not available';
    }
}

/**
 * Update recommendation
 * @param {Object} recommendation - Recommendation data
 */
function updateRecommendation(recommendation) {
    const titleEl = document.getElementById('recommendation-title');
    const listEl = document.getElementById('recommendation-list');
    
    titleEl.textContent = recommendation.title || 'Recommendation';
    
    listEl.innerHTML = '';
    if (recommendation.actions && recommendation.actions.length > 0) {
        recommendation.actions.forEach(action => {
            const li = document.createElement('li');
            li.textContent = action;
            listEl.appendChild(li);
        });
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Add enter key support for input
    const input = document.getElementById('url-input');
    if (input) {
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                analyzeWebsite();
            }
        });
    }
});
