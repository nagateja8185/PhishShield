/**
 * Email Analyzer Module
 * Handles email analysis UI and interactions
 */

// Example phishing email for testing
const EXAMPLE_PHISHING_EMAIL = `From: security@bankofamerica-secure.com
To: victim@email.com
Subject: URGENT: Your Account Has Been Compromised

Dear Valued Customer,

We have detected suspicious activity on your account. Your account will be SUSPENDED within 24 hours if you do not verify your information immediately.

Click here to verify your account: http://192.168.1.1/bank/login.php

Please verify the following information:
- Account Number
- Password
- Social Security Number
- Credit Card Details

This is an automated message. Please do not reply.

URGENT ACTION REQUIRED!!!

Best regards,
Bank Security Team`;

// Example safe email for testing
const EXAMPLE_SAFE_EMAIL = `From: john.colleague@company.com
To: team@company.com
Subject: Meeting Notes - Project Review

Hi Team,

Thanks for attending today's project review meeting. Here are the key points we discussed:

1. Project timeline has been updated - new deadline is March 15th
2. Budget allocation approved for Q2
3. Need to schedule follow-up with the design team

Action items:
- Sarah: Prepare updated mockups by Friday
- Mike: Review the technical specifications
- Everyone: Submit feedback on the proposal by EOD Thursday

Let me know if you have any questions.

Best regards,
John`;

/**
 * Load example email into the textarea
 */
function loadExample() {
    const textarea = document.getElementById('email-input');
    const usePhishing = Math.random() > 0.5;
    textarea.value = usePhishing ? EXAMPLE_PHISHING_EMAIL : EXAMPLE_SAFE_EMAIL;
}

/**
 * Clear the input textarea
 */
function clearInput() {
    const textarea = document.getElementById('email-input');
    textarea.value = '';
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
 * Analyze the email
 */
async function analyzeEmail() {
    const textarea = document.getElementById('email-input');
    const emailText = textarea.value.trim();
    
    if (!emailText) {
        alert('Please enter email content to analyze');
        return;
    }
    
    showLoading();
    
    try {
        const result = await analyzeEmailAPI(emailText);
        displayResult(result);
        saveScanToHistory(result);
    } catch (error) {
        alert('Error analyzing email: ' + error.message);
    } finally {
        hideLoading();
    }
}

/**
 * Call the email analysis API
 * @param {string} emailText - Email content
 * @returns {Promise<Object>} Analysis result
 */
async function analyzeEmailAPI(emailText) {
    const response = await fetch('/analyze-email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: emailText })
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to analyze email');
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
    const phishingProbability = document.getElementById('phishing-probability');
    const explanation = document.getElementById('explanation');
    const indicatorsList = document.getElementById('indicators-list');
    const recommendationsList = document.getElementById('recommendations-list');
    const timestamp = document.getElementById('timestamp');
    
    // Show result section
    resultSection.style.display = 'block';
    
    // Update timestamp
    timestamp.textContent = new Date().toLocaleString();
    
    // Use trust_score if available, otherwise calculate from score
    const trustScore = result.trust_score !== undefined ? result.trust_score : (100 - result.score);
    
    // Update score - show trust score (like URL scanner)
    scoreValue.textContent = trustScore;
    
    // Update score circle color based on risk level
    scoreCircle.className = 'score-circle';
    if (result.risk_level === 'Dangerous') {
        scoreCircle.classList.add('dangerous');
    } else if (result.risk_level === 'Suspicious') {
        scoreCircle.classList.add('suspicious');
    } else {
        scoreCircle.classList.add('safe');
    }
    
    // Update risk badge
    riskBadge.textContent = result.risk_level;
    riskBadge.className = 'risk-badge ' + getRiskLevelClass(result.risk_level);
    
    // Update phishing probability display
    const probPercent = (result.phishing_probability * 100).toFixed(1);
    phishingProbability.textContent = `Phishing Probability: ${probPercent}%`;
    
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
        recommendations.push('Do not click any links in this email');
        recommendations.push('Do not download any attachments');
        recommendations.push('Do not reply to this email or provide any personal information');
        recommendations.push('Verify the sender through official channels (not by replying to this email)');
        recommendations.push('Report this email to your IT department or email provider');
        recommendations.push('Delete this email after reporting');
    } else if (riskLevel === 'Suspicious') {
        recommendations.push('Exercise caution with this email');
        recommendations.push('Verify the sender identity before taking any action');
        recommendations.push('Hover over links to check the actual URL before clicking');
        recommendations.push('Contact the organization directly using known contact information');
    } else {
        recommendations.push('This email appears to be legitimate');
        recommendations.push('Continue to exercise normal caution with any email');
        recommendations.push('Always verify unexpected requests for sensitive information');
    }
    
    return recommendations;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Add enter key support for textarea
    const textarea = document.getElementById('email-input');
    if (textarea) {
        textarea.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'Enter') {
                analyzeEmail();
            }
        });
    }
});
