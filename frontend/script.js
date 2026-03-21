// Configuration
const API_URL = 'http://localhost:5000';

// State
let isMonitoring = false;
let eventSource = null;
let stats = {
    threats: 0,
    blocked: 0,
    confidence: 98
};

// DOM Elements
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const statusBadge = document.getElementById('statusBadge');
const heroSection = document.getElementById('heroSection');
const dashboard = document.getElementById('dashboard');
const threatsCount = document.getElementById('threatsCount');
const blockedCount = document.getElementById('blockedCount');
const confidence = document.getElementById('confidence');
const logEntries = document.getElementById('logEntries');
const patternsList = document.getElementById('patternsList');
const radarLine = document.querySelector('.radar-line');
const scrollTopBtn = document.getElementById('scrollTop');
const fullscreenBtn = document.getElementById('fullscreen');

// Event Listeners
startBtn.addEventListener('click', startMonitoring);
stopBtn.addEventListener('click', stopMonitoring);
scrollTopBtn.addEventListener('click', scrollToTop);
fullscreenBtn.addEventListener('click', toggleFullscreen);

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkBackendStatus();
    loadAttackPatterns();
});

// Backend Status Check
async function checkBackendStatus() {
    try {
        const response = await fetch(`${API_URL}/api/status`);
        if (response.ok) {
            console.log('Backend is running');
        }
    } catch (error) {
        console.warn('Backend not running. Start the Python server.');
    }
}

// Start Monitoring
async function startMonitoring() {
    try {
        startBtn.disabled = true;
        
        const response = await fetch(`${API_URL}/api/start`, {
            method: 'POST'
        });
        
        if (!response.ok) throw new Error('Failed to start monitoring');
        
        isMonitoring = true;
        
        // Update UI
        statusBadge.textContent = 'SYSTEM ONLINE';
        statusBadge.classList.add('online');
        startBtn.style.display = 'none';
        stopBtn.style.display = 'block';
        
        // Fade out hero, show dashboard
        heroSection.classList.add('fade-out');
        setTimeout(() => {
            heroSection.style.display = 'none';
            dashboard.classList.add('active');
        }, 500);
        
        // Start radar animation
        radarLine.classList.remove('paused');
        
        // Start event stream
        connectEventStream();
        
    } catch (error) {
        console.error('Error starting monitoring:', error);
        alert('Failed to start monitoring. Make sure the backend is running.');
        startBtn.disabled = false;
    }
}

// Stop Monitoring
async function stopMonitoring() {
    try {
        const response = await fetch(`${API_URL}/api/stop`, {
            method: 'POST'
        });
        
        if (!response.ok) throw new Error('Failed to stop monitoring');
        
        isMonitoring = false;
        
        // Disconnect event stream
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }
        
        // Update UI
        statusBadge.textContent = 'SYSTEM OFFLINE';
        statusBadge.classList.remove('online');
        stopBtn.style.display = 'none';
        startBtn.style.display = 'block';
        startBtn.disabled = false;
        
        // Show hero, hide dashboard
        dashboard.classList.remove('active');
        heroSection.style.display = 'block';
        setTimeout(() => {
            heroSection.classList.remove('fade-out');
        }, 50);
        
        // Pause radar
        radarLine.classList.add('paused');
        
    } catch (error) {
        console.error('Error stopping monitoring:', error);
        alert('Failed to stop monitoring');
    }
}

// Connect to Event Stream (Server-Sent Events)
function connectEventStream() {
    eventSource = new EventSource(`${API_URL}/api/stream`);
    
    eventSource.addEventListener('log', (event) => {
        const data = JSON.parse(event.data);
        addLogEntry(data);
    });
    
    eventSource.addEventListener('stats', (event) => {
        const data = JSON.parse(event.data);
        updateStats(data);
    });
    
    eventSource.addEventListener('pattern', (event) => {
        const data = JSON.parse(event.data);
        addPattern(data);
    });
    
    eventSource.onerror = (error) => {
        console.error('EventSource error:', error);
        if (isMonitoring) {
            // Try to reconnect
            setTimeout(() => {
                if (isMonitoring) {
                    eventSource.close();
                    connectEventStream();
                }
            }, 5000);
        }
    };
}

// Add Log Entry
function addLogEntry(data) {
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    
    const time = new Date(data.timestamp).toLocaleTimeString();
    const threatClass = data.is_threat ? 'log-threat' : 'log-safe';
    const threatText = data.is_threat ? 'THREAT' : 'SAFE';
    
    entry.innerHTML = `
        <span class="log-time">[${time}]</span>
        <span class="${threatClass}">[${threatText}]</span>
        ${data.message}
    `;
    
    logEntries.insertBefore(entry, logEntries.firstChild);
    
    // Keep only last 50 entries
    while (logEntries.children.length > 50) {
        logEntries.removeChild(logEntries.lastChild);
    }
    
    // Update stats if threat
    if (data.is_threat) {
        stats.threats++;
        stats.blocked++;
        updateStatsDisplay();
    }
}

// Update Stats
function updateStats(data) {
    stats = {
        threats: data.threats_detected || stats.threats,
        blocked: data.attacks_blocked || stats.blocked,
        confidence: data.confidence || stats.confidence
    };
    updateStatsDisplay();
}

// Update Stats Display
function updateStatsDisplay() {
    threatsCount.textContent = stats.threats;
    blockedCount.textContent = stats.blocked;
    confidence.textContent = `${stats.confidence}%`;
}

// Load Attack Patterns
async function loadAttackPatterns() {
    try {
        const response = await fetch(`${API_URL}/api/patterns`);
        if (!response.ok) return;
        
        const patterns = await response.json();
        displayPatterns(patterns);
    } catch (error) {
        console.error('Error loading patterns:', error);
    }
}

// Display Patterns
function displayPatterns(patterns) {
    patternsList.innerHTML = '';
    
    patterns.forEach(pattern => {
        const item = document.createElement('div');
        item.className = 'pattern-item';
        item.innerHTML = `
            <div class="pattern-name">${pattern.name}</div>
            <div class="pattern-details">
                Detected: ${pattern.count} times | 
                Confidence: ${(pattern.confidence * 100).toFixed(1)}% |
                Type: ${pattern.attack_type}
            </div>
        `;
        patternsList.appendChild(item);
    });
}

// Add New Pattern
function addPattern(pattern) {
    const item = document.createElement('div');
    item.className = 'pattern-item';
    item.innerHTML = `
        <div class="pattern-name">${pattern.name}</div>
        <div class="pattern-details">
            Detected: ${pattern.count} times | 
            Confidence: ${(pattern.confidence * 100).toFixed(1)}% |
            Type: ${pattern.attack_type}
        </div>
    `;
    patternsList.insertBefore(item, patternsList.firstChild);
}

// Scroll to Top
function scrollToTop() {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
}

// Toggle Fullscreen
function toggleFullscreen() {
    if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().catch(err => {
            console.error('Error attempting to enable fullscreen:', err);
        });
    } else {
        document.exitFullscreen();
    }
}

// Simulate data when backend is not available (for testing)
function simulateData() {
    const attackTypes = [
        'SQL Injection Attempt',
        'XSS Attack Detected',
        'Ransomware Signature',
        'Port Scan Detected',
        'Brute Force Login',
        'Data Exfiltration Attempt',
        'Suspicious API Call',
        'Malware Upload Blocked'
    ];
    
    setInterval(() => {
        if (isMonitoring) {
            const isThread = Math.random() > 0.7;
            const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
            
            addLogEntry({
                timestamp: new Date().toISOString(),
                is_threat: isThread,
                message: isThread ? attackType : 'Normal traffic from 192.168.1.' + Math.floor(Math.random() * 255)
            });
        }
    }, 2000);
}

// Uncomment to test without backend
// simulateData();
