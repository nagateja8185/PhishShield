/**
 * URL Analyzer Module
 * Handles URL analysis UI and interactions
 */

// Example URLs for testing
const EXAMPLE_PHISHING_URL = 'http://paypal-security-update-login.com';
const EXAMPLE_SUSPICIOUS_URL = 'http://login-account-update.com';
const EXAMPLE_SAFE_URL = 'https://www.linkedin.com';

/**
 * Load example URL into the input
 */
function loadExample() {
    const input = document.getElementById('url-input');
    const examples = [EXAMPLE_PHISHING_URL, EXAMPLE_SUSPICIOUS_URL, EXAMPLE_SAFE_URL];
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
 * Analyze the URL
 */
async function analyzeURL() {
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
        const result = await analyzeURLAPI(url);
        result.url = url; // Store URL for history
        displayResult(result);
        saveScanToHistory(result);
    } catch (error) {
        alert('Error analyzing URL: ' + error.message);
    } finally {
        hideLoading();
    }
}

/**
 * Validate URL format
 * @param {string} url - URL to validate
 * @returns {boolean} Whether URL is valid
 */
function isValidURL(url) {
    // Allow URLs with or without protocol
    const pattern = /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/;
    return pattern.test(url) || url.includes('.');
}

/**
 * Call the URL analysis API
 * @param {string} url - URL to analyze
 * @returns {Promise<Object>} Analysis result
 */
async function analyzeURLAPI(url) {
    const response = await fetch('/analyze-url', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to analyze URL');
    }

    return await response.json();
}

/**
 * Display the analysis result
 * @param {Object} result - Analysis result
 */
function displayResult(result) {
    const resultSection = document.getElementById('result-section');
    const scoreCircle = document.getElementById('score-circle');
    const scoreValue = document.getElementById('score-value');
    const riskBadge = document.getElementById('risk-badge');
    const confidence = document.getElementById('confidence');
    const explanation = document.getElementById('explanation');
    const indicatorsList = document.getElementById('indicators-list');
    const recommendationsList = document.getElementById('recommendations-list');
    const timestamp = document.getElementById('timestamp');
    const urlFeatures = document.getElementById('url-features');
    const featuresTableBody = document.getElementById('features-table-body');
    
    // Show result section
    resultSection.style.display = 'block';
    
    // Update timestamp
    timestamp.textContent = new Date().toLocaleString();
    
    // Update score - use trust_score (0-100, higher is safer) or calculate from score
    const trustScore = result.trust_score !== undefined ? result.trust_score : (100 - result.score);
    scoreValue.textContent = trustScore;
    
    // Update score circle color based on trust score (higher = safer)
    scoreCircle.className = 'score-circle';
    if (result.risk_level === 'Dangerous' || trustScore < 30) {
        scoreCircle.classList.add('dangerous');
    } else if (result.risk_level === 'Suspicious' || trustScore < 70) {
        scoreCircle.classList.add('suspicious');
    } else {
        scoreCircle.classList.add('safe');
    }
    
    // Update risk badge
    riskBadge.textContent = result.risk_level;
    riskBadge.className = 'risk-badge ' + getRiskLevelClass(result.risk_level);
    
    // Update confidence - show phishing probability as confidence
    const phishingPercent = (result.phishing_probability * 100).toFixed(1);
    confidence.textContent = `Phishing Probability: ${phishingPercent}%`;
    
    // Update explanation
    explanation.textContent = result.explanation;
    
    // Update indicators
    indicatorsList.innerHTML = '';
    if (result.indicators && result.indicators.length > 0) {
        result.indicators.forEach(indicator => {
            const li = document.createElement('li');
            const icon = getIndicatorIcon(indicator.type);
            li.innerHTML = `<span class="indicator-icon ${indicator.type}">${icon}</span> ${indicator.message}`;
            indicatorsList.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.innerHTML = '<span class="indicator-icon safe">&#10003;</span> No suspicious indicators detected';
        indicatorsList.appendChild(li);
    }
    
    // Update recommendations
    recommendationsList.innerHTML = '';
    const recommendations = getRecommendations(result.risk_level, result.label);
    recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.textContent = rec;
        recommendationsList.appendChild(li);
    });
    
    // Update features table
    if (result.features) {
        urlFeatures.style.display = 'block';
        featuresTableBody.innerHTML = '';
        
        const featureLabels = {
            url_length: 'URL Length',
            domain_length: 'Domain Length',
            path_length: 'Path Length',
            num_dots: 'Number of Dots',
            num_hyphens: 'Number of Hyphens',
            num_underscores: 'Number of Underscores',
            num_slashes: 'Number of Slashes',
            num_digits: 'Number of Digits',
            has_at_symbol: 'Contains @ Symbol',
            has_double_slash: 'Contains Double Slash',
            has_ip_address: 'Uses IP Address',
            has_https: 'Uses HTTPS',
            domain_entropy: 'Domain Entropy',
            suspicious_keywords_count: 'Suspicious Keywords',
            is_shortened: 'URL Shortened',
            has_suspicious_tld: 'Suspicious TLD',
            subdomain_count: 'Subdomain Count',
            has_port: 'Non-Standard Port',
            query_length: 'Query Length',
            has_hex_chars: 'Contains Hex Encoded Chars'
        };
        
        Object.entries(result.features).forEach(([key, value]) => {
            const row = document.createElement('tr');
            const label = featureLabels[key] || key;
            const displayValue = typeof value === 'number' 
                ? (Number.isInteger(value) ? value : value.toFixed(2))
                : value;
            
            row.innerHTML = `
                <td>${label}</td>
                <td>${displayValue}</td>
            `;
            featuresTableBody.appendChild(row);
        });
    } else {
        urlFeatures.style.display = 'none';
    }
    
    // Scroll to result
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Get indicator icon based on type
 * @param {string} type - Indicator type
 * @returns {string} HTML entity for icon
 */
function getIndicatorIcon(type) {
    switch (type) {
        case 'danger':
            return '&#10007;';
        case 'warning':
            return '&#9888;';
        case 'caution':
            return '&#8505;';
        case 'safe':
            return '&#10003;';
        default:
            return '&#8226;';
    }
}

/**
 * Get risk level CSS class
 * @param {string} riskLevel - Risk level
 * @returns {string} CSS class
 */
function getRiskLevelClass(riskLevel) {
    switch (riskLevel.toLowerCase()) {
        case 'safe':
            return 'safe';
        case 'suspicious':
            return 'suspicious';
        case 'dangerous':
            return 'dangerous';
        default:
            return '';
    }
}

/**
 * Get recommendations based on risk level
 * @param {string} riskLevel - Risk level
 * @param {string} label - Label (Safe/Phishing)
 * @returns {Array} List of recommendations
 */
function getRecommendations(riskLevel, label) {
    const recommendations = [];
    
    if (label === 'Phishing') {
        recommendations.push('DO NOT visit this URL');
        recommendations.push('Do not enter any credentials or personal information on this site');
        recommendations.push('If you need to access the service, type the known legitimate address directly into your browser');
        recommendations.push('Report this URL to your IT department or security team');
        recommendations.push('Check if you have already entered credentials - if so, change them immediately on the legitimate site');
    } else if (riskLevel === 'Suspicious') {
        recommendations.push('Exercise caution before visiting this URL');
        recommendations.push('Verify the URL through official channels before proceeding');
        recommendations.push('Check for HTTPS and valid certificates before entering any information');
        recommendations.push('Consider using a link scanner service for additional verification');
    } else {
        recommendations.push('This URL appears to be safe');
        recommendations.push('Continue to exercise normal caution when browsing');
        recommendations.push('Always verify you are on the correct website before entering sensitive information');
        recommendations.push('Ensure the connection is secure (look for the lock icon) when entering credentials');
    }
    
    return recommendations;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Add enter key support for input
    const input = document.getElementById('url-input');
    if (input) {
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                analyzeURL();
            }
        });
    }
});
