// 1. Initialize Connection (Fixed: Only declare ONCE)
const socket = io('/logs'); 

// 2. DOM Selectors
const logBody = document.getElementById('log-body');
const logCountElement = document.getElementById('log-count');
const statusIndicator = document.getElementById('status');

let logCount = 0;

// 3. Socket Event Listeners
socket.on('connect', () => {
    updateStatus("Connected", "text-success");
    console.log("WebSocket connected to /logs namespace.");
});

socket.on('disconnect', () => {
    updateStatus("Disconnected", "text-danger");
});

/**
 * Handle standard log updates
 * Matches: socketio.emit('new_log', ...) in app.py
 */
socket.on('new_log', function(data) {
    console.log("New log received:", data);
    updateLogCounter();
    appendLogRow(data); // Unified function name
});

/**
 * Handle high-priority threat alerts
 * Matches: socketio.emit('threat_alert', ...) in app.py
 */
socket.on('threat_alert', function(alert) {
    console.warn("THREAT ALERT:", alert.message);
    
    // Visual Alert
    document.body.style.border = "5px solid red";
    setTimeout(() => { document.body.style.border = "none"; }, 2000);
    
    // Optional: Alert notification (if you have an alertUser function)
    if (typeof alertUser === "function") {
        alertUser(alert.message);
    } else {
        alert(alert.message); // Fallback browser alert
    }
});

// 4. Helper Functions
function updateStatus(text, className) {
    if (statusIndicator) {
        statusIndicator.innerText = text;
        statusIndicator.className = className;
    }
}

function updateLogCounter() {
    logCount++;
    if (logCountElement) {
        logCountElement.innerText = logCount;
    }
}

function appendLogRow(data) {
    if (!logBody) return;

    const row = document.createElement('tr');
    
    // Fallbacks for data
    const timestamp = data.timestamp || new Date().toLocaleTimeString();
    const sourceIp = data.ip || 'Unknown';
    const eventType = data.type || 'TRAFFIC';
    const severity = data.severity || 'LOW';
    const message = data.msg || 'No details provided';

    row.innerHTML = `
        <td>${timestamp}</td>
        <td class="fw-bold">${sourceIp}</td>
        <td><span class="badge bg-secondary">${eventType}</span></td>
        <td class="severity-${severity}">${severity}</td>
        <td class="text-truncate" style="max-width: 400px;">${message}</td>
    `;

    // Insert at top
    logBody.insertBefore(row, logBody.firstChild);

    // Memory Management
    if (logBody.children.length > 100) {
        logBody.removeChild(logBody.lastChild);
    }
    
    // Highlight effect
    row.style.backgroundColor = 'rgba(0, 123, 255, 0.1)';
    setTimeout(() => { row.style.backgroundColor = 'transparent'; }, 500);
}