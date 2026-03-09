/**
 * Dashboard Module
 * Handles scan history and dashboard functionality
 */

/**
 * Initialize dashboard on page load
 */
document.addEventListener('DOMContentLoaded', function() {
    loadRecentScans();
    
    // Check server health
    checkServerHealth();
});

/**
 * Load and display recent scans
 */
function loadRecentScans() {
    const container = document.getElementById('recent-scans-container');
    if (!container) return;
    
    const history = getScanHistory();
    
    if (history.length === 0) {
        container.innerHTML = '<p class="no-scans">No recent scans. Start by scanning an email or URL.</p>';
        return;
    }
    
    // Display last 5 scans
    const recentScans = history.slice(0, 5);
    
    let html = '<div class="scan-list">';
    recentScans.forEach(scan => {
        const date = new Date(scan.timestamp);
        const formattedDate = date.toLocaleDateString();
        const formattedTime = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        html += `
            <div class="scan-item ${getRiskLevelClass(scan.risk_level)}">
                <div class="scan-info">
                    <span class="scan-type">${scan.type === 'email' ? '&#128231;' : '&#128279;'} ${scan.type.toUpperCase()}</span>
                    <span class="scan-preview" title="${scan.preview}">${truncateText(scan.preview, 40)}</span>
                </div>
                <div class="scan-result">
                    <span class="scan-score">${scan.score}%</span>
                    <span class="risk-badge ${getRiskLevelClass(scan.risk_level)}">${scan.risk_level}</span>
                </div>
                <div class="scan-time">${formattedDate} ${formattedTime}</div>
            </div>
        `;
    });
    html += '</div>';
    
    container.innerHTML = html;
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
        
        // Refresh display if on dashboard
        loadRecentScans();
    } catch (error) {
        console.error('Failed to save scan history:', error);
    }
}

/**
 * Clear scan history
 */
function clearScanHistory() {
    try {
        localStorage.removeItem('phishshield_history');
        loadRecentScans();
    } catch (error) {
        console.error('Failed to clear scan history:', error);
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
 * Truncate text to specified length
 * @param {string} text - Text to truncate
 * @param {number} maxLength - Maximum length
 * @returns {string} Truncated text
 */
function truncateText(text, maxLength) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

/**
 * Check server health
 */
async function checkServerHealth() {
    try {
        const response = await fetch('/health');
        const data = await response.json();
        
        if (!data.models_loaded) {
            console.warn('ML models not loaded on server');
        }
    } catch (error) {
        console.error('Server health check failed:', error);
    }
}

// Add styles for scan list
const style = document.createElement('style');
style.textContent = `
    .scan-list {
        display: flex;
        flex-direction: column;
        gap: 12px;
    }
    
    .scan-item {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 16px;
        background: var(--card-bg);
        border-radius: var(--radius);
        box-shadow: var(--shadow);
        border-left: 4px solid var(--border-color);
    }
    
    .scan-item.safe {
        border-left-color: var(--success-color);
    }
    
    .scan-item.suspicious {
        border-left-color: var(--warning-color);
    }
    
    .scan-item.dangerous {
        border-left-color: var(--danger-color);
    }
    
    .scan-info {
        display: flex;
        flex-direction: column;
        gap: 4px;
        flex: 1;
    }
    
    .scan-type {
        font-size: 0.75rem;
        font-weight: 700;
        color: var(--text-secondary);
        text-transform: uppercase;
    }
    
    .scan-preview {
        color: var(--text-primary);
        font-size: 0.9375rem;
    }
    
    .scan-result {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    
    .scan-score {
        font-weight: 700;
        font-size: 1.125rem;
    }
    
    .scan-time {
        font-size: 0.75rem;
        color: var(--text-secondary);
        margin-left: 16px;
    }
    
    @media (max-width: 768px) {
        .scan-item {
            flex-direction: column;
            align-items: flex-start;
            gap: 12px;
        }
        
        .scan-result {
            width: 100%;
            justify-content: space-between;
        }
        
        .scan-time {
            margin-left: 0;
        }
    }
`;
document.head.appendChild(style);
