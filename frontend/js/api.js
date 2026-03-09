/**
 * PhishShield API Client
 * Handles communication with the backend server
 */

const API_BASE_URL = window.location.origin;

/**
 * Analyze email content for phishing
 * @param {string} emailText - The email content to analyze
 * @returns {Promise<Object>} Analysis result
 */
async function analyzeEmail(emailText) {
    try {
        const response = await fetch(`${API_BASE_URL}/analyze-email`, {
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
    } catch (error) {
        console.error('Email analysis error:', error);
        throw error;
    }
}

/**
 * Analyze URL for phishing
 * @param {string} url - The URL to analyze
 * @returns {Promise<Object>} Analysis result
 */
async function analyzeURL(url) {
    try {
        const response = await fetch(`${API_BASE_URL}/analyze-url`, {
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
    } catch (error) {
        console.error('URL analysis error:', error);
        throw error;
    }
}

/**
 * Check server health status
 * @returns {Promise<Object>} Health status
 */
async function checkHealth() {
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        return await response.json();
    } catch (error) {
        console.error('Health check error:', error);
        return { status: 'unhealthy', models_loaded: false };
    }
}

/**
 * Save scan to localStorage history
 * @param {Object} scan - Scan result to save
 */
function saveScanToHistory(scan) {
    try {
        const history = JSON.parse(localStorage.getItem('phishshield_history') || '[]');
        
        const scanEntry = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            type: scan.type,
            score: scan.score,
            label: scan.label,
            risk_level: scan.risk_level,
            preview: scan.type === 'email' 
                ? 'Email scan' 
                : (scan.url || 'URL scan')
        };
        
        // Add to beginning, limit to 50 entries
        history.unshift(scanEntry);
        if (history.length > 50) {
            history.pop();
        }
        
        localStorage.setItem('phishshield_history', JSON.stringify(history));
    } catch (error) {
        console.error('Failed to save scan history:', error);
    }
}

/**
 * Get scan history from localStorage
 * @returns {Array} Scan history
 */
function getScanHistory() {
    try {
        return JSON.parse(localStorage.getItem('phishshield_history') || '[]');
    } catch (error) {
        console.error('Failed to get scan history:', error);
        return [];
    }
}

/**
 * Clear scan history
 */
function clearScanHistory() {
    try {
        localStorage.removeItem('phishshield_history');
    } catch (error) {
        console.error('Failed to clear scan history:', error);
    }
}

/**
 * Format timestamp for display
 * @param {string} isoString - ISO timestamp string
 * @returns {string} Formatted timestamp
 */
function formatTimestamp(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString();
}

/**
 * Get risk level color class
 * @param {string} riskLevel - Risk level string
 * @returns {string} CSS class name
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
 * Get risk level color value
 * @param {string} riskLevel - Risk level string
 * @returns {string} CSS color value
 */
function getRiskLevelColor(riskLevel) {
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

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        analyzeEmail,
        analyzeURL,
        checkHealth,
        saveScanToHistory,
        getScanHistory,
        clearScanHistory,
        formatTimestamp,
        getRiskLevelClass,
        getRiskLevelColor
    };
}
