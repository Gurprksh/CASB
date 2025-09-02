const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Serve the HTML file and other static assets from the current directory
app.use(express.static(path.join(__dirname)));

// In-memory database with updated, realistic data
let mockData = {
    shadowIT: [
        { id: 1, name: 'Dropbox', category: 'Cloud Storage', risk: 'High', users: 152, status: 'Unsanctioned' },
        { id: 2, name: 'Salesforce', category: 'CRM', risk: 'Low', users: 84, status: 'Sanctioned' },
        { id: 3, name: 'Slack', category: 'Collaboration', risk: 'Low', users: 212, status: 'Sanctioned' },
        { id: 4, name: 'Trello', category: 'Project Management', risk: 'Medium', users: 45, status: 'Unsanctioned' },
        { id: 5, name: 'Asana', category: 'Project Management', risk: 'Medium', users: 98, status: 'Unsanctioned' },
        { id: 6, name: 'Google Drive', category: 'Cloud Storage', risk: 'Low', users: 350, status: 'Sanctioned' },
        { id: 7, name: 'Microsoft 365', category: 'Productivity Suite', risk: 'Low', users: 410, status: 'Sanctioned' },
        { id: 8, name: 'Notion', category: 'Collaboration', risk: 'Medium', users: 76, status: 'Unsanctioned' }
    ],
    dlpIncidents: [
        { ts: '2025-09-02 14:21:05', user: 'alice.jones@example.com', policy: 'PII Sharing Violation', app: 'Dropbox', severity: 'Critical', action: 'Blocked' },
        { ts: '2025-09-02 11:45:12', user: 'bob.smith@example.com', policy: 'Financial Data Leak', app: 'Google Drive', severity: 'High', action: 'Quarantined' },
        { ts: '2025-09-02 09:15:33', user: 'charlie.brown@example.com', policy: 'Confidential Document Access', app: 'Slack', severity: 'Medium', action: 'Alerted' },
    ],
    threats: [
        { ts: '2025-09-02 13:05:11', type: 'Impossible Travel', user: 'diana.prince@example.com', ip: '198.51.100.2', details: 'Login from new country', status: 'Blocked' },
        { ts: '2025-09-02 10:30:45', type: 'Malware Detected', user: 'eva.green@example.com', ip: '203.0.113.5', details: 'Malicious file upload to Asana', status: 'Remediated' },
    ],
    policies: [
        { id: 'dlp1', name: 'Block PII Sharing to Unsanctioned Apps', category: 'Data Loss Prevention', enabled: true },
        { id: 'dlp2', name: 'Alert on Bulk Download from Salesforce', category: 'Data Loss Prevention', enabled: true },
        { id: 'threat1', name: 'Block Logins from Risky IPs', category: 'Threat Protection', enabled: true },
        { id: 'threat2', name: 'Detect Impossible Travel Anomalies', category: 'Threat Protection', enabled: false },
        { id: 'access1', name: 'Require MFA for Unmanaged Devices', category: 'Access Control', enabled: true },
    ],
    settings: {
        user: { name: 'Admin User', email: 'admin@casb-portal.com', role: 'Security Administrator' },
        notifications: {
            emailOnCriticalDLP: true,
            emailOnHighThreat: false,
        }
    },
    users: [
        { id: 101, name: 'Admin User', email: 'admin@casb-portal.com', role: 'Admin', status: 'Active', usualCountry: 'India' },
        { id: 102, name: 'Alice Jones', email: 'alice.jones@example.com', role: 'User', status: 'Active', usualCountry: 'India' },
        { id: 103, name: 'Bob Smith', email: 'bob.smith@example.com', role: 'User', status: 'Inactive', usualCountry: 'USA' },
        { id: 104, name: 'Charlie Brown', email: 'charlie.brown@example.com', role: 'User', status: 'Active', usualCountry: 'India' },
    ],
    services: [
        { id: 's1', name: 'Microsoft 365', type: 'SaaS', status: 'Connected' },
        { id: 's2', name: 'Google Workspace', type: 'SaaS', status: 'Connected' },
        { id: 's3', name: 'Salesforce', type: 'SaaS', status: 'Disconnected' },
        { id: 's4', name: 'Amazon Web Services', type: 'IaaS', status: 'Connected' },
        { id: 's5', name: 'Box', type: 'SaaS', status: 'Disconnected' },
        { id: 's6', name: 'GitHub', type: 'DevOps', status: 'Connected' },
    ],
    userEvents: [
        { ts: new Date(Date.now() - 300000).toISOString(), user: 'alice.jones@example.com', action: 'Login', details: { ip: '103.27.100.5', location: 'Bhopal, India' } },
        { ts: new Date(Date.now() - 240000).toISOString(), user: 'alice.jones@example.com', action: 'File Upload', details: { app: 'Google Drive', file: 'project_report_final.docx' } },
        { ts: new Date(Date.now() - 180000).toISOString(), user: 'charlie.brown@example.com', action: 'Login', details: { ip: '103.27.101.21', location: 'Bhopal, India' } },
        { ts: new Date(Date.now() - 120000).toISOString(), user: 'bob.smith@example.com', action: 'Login', details: { ip: '203.0.113.5', location: 'New York, USA' } }
    ]
};

// --- ML Anomaly Detection Simulation ---
const userBehaviorModel = {};
mockData.users.forEach(u => {
    userBehaviorModel[u.email] = { usualCountry: u.usualCountry };
});

function runAnomalyDetection() {
    const recentEvents = mockData.userEvents.slice(-10); 
    recentEvents.forEach(event => {
        if (event.action === 'Login' && event.details.location) {
            const country = event.details.location.split(', ')[1];
            const userModel = userBehaviorModel[event.user];
            if (userModel && country !== userModel.usualCountry) {
                const threatExists = mockData.threats.some(t => t.details.includes(event.ts));
                if (!threatExists) {
                    const newThreat = {
                        ts: new Date().toISOString().replace('T', ' ').slice(0, 19),
                        type: 'Unusual Login Location',
                        user: event.user,
                        ip: event.details.ip,
                        details: `ML Model: Login from ${event.details.location} deviates from normal behavior. (Event TS: ${event.ts})`,
                        status: 'Alerted'
                    };
                    mockData.threats.unshift(newThreat);
                    console.log('Anomaly Detected:', newThreat);
                }
            }
        }
    });
}

setInterval(() => {
    const randomUser = mockData.users[Math.floor(Math.random() * mockData.users.length)];
    if (randomUser) {
         const newEvent = {
            ts: new Date().toISOString(),
            user: randomUser.email,
            action: 'File Access',
            details: { app: 'Microsoft 365', file: 'document.xlsx', location: 'Bhopal, India' }
        };
        mockData.userEvents.push(newEvent);
        if(mockData.userEvents.length > 100) mockData.userEvents.shift();
    }
    runAnomalyDetection();
}, 10000);

// --- API Endpoints ---
app.get('/api/stats', (req, res) => {
    res.json({
        discoveredApps: mockData.shadowIT.length,
        dlpIncidents: mockData.dlpIncidents.length,
        threatsDetected: mockData.threats.length,
        activePolicies: mockData.policies.filter(p => p.enabled).length,
        managedUsers: mockData.users.length,
        connectedServices: mockData.services.filter(s => s.status === 'Connected').length,
    });
});

// Shadow IT
app.get('/api/shadow-it', (req, res) => res.json(mockData.shadowIT));
app.post('/api/shadow-it/:id/toggle-status', (req, res) => {
    const appId = parseInt(req.params.id, 10);
    const app = mockData.shadowIT.find(a => a.id === appId);
    if (app) {
        app.status = app.status === 'Sanctioned' ? 'Unsanctioned' : 'Sanctioned';
        return res.status(200).json(app);
    }
    return res.status(404).send('App not found');
});

// DLP, Threats, Policies
app.get('/api/dlp-incidents', (req, res) => res.json(mockData.dlpIncidents));
app.get('/api/threats', (req, res) => res.json(mockData.threats.sort((a,b) => new Date(b.ts) - new Date(a.ts))));
app.get('/api/policies', (req, res) => res.json(mockData.policies));
app.post('/api/policies/:id/toggle-status', (req, res) => {
    const policy = mockData.policies.find(p => p.id === req.params.id);
    if (policy) {
        policy.enabled = !policy.enabled;
        return res.status(200).json(policy);
    }
    return res.status(404).send('Policy not found');
});

// Settings
app.get('/api/settings', (req, res) => res.json(mockData.settings));
app.post('/api/settings', (req, res) => {
    mockData.settings.notifications = req.body.notifications;
    res.status(200).json(mockData.settings);
});

// Users
app.get('/api/users', (req, res) => res.json(mockData.users));
app.post('/api/users', (req, res) => {
    const newUser = {
        id: Date.now(),
        ...req.body,
        status: 'Active',
        usualCountry: 'India' // Default for new users
    };
    mockData.users.push(newUser);
    userBehaviorModel[newUser.email] = { usualCountry: newUser.usualCountry };
    res.status(201).json(newUser);
});
app.post('/api/users/:id/toggle-status', (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const user = mockData.users.find(u => u.id === userId);
    if (user) {
        user.status = user.status === 'Active' ? 'Inactive' : 'Active';
        return res.status(200).json(user);
    }
    return res.status(404).send('User not found');
});
app.delete('/api/users/:id', (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const index = mockData.users.findIndex(u => u.id === userId);
    if (index !== -1) {
        mockData.users.splice(index, 1);
        return res.status(200).send('User deleted');
    }
    return res.status(404).send('User not found');
});

// Services
app.get('/api/services', (req, res) => res.json(mockData.services));
app.post('/api/services/:id/toggle-status', (req, res) => {
    const service = mockData.services.find(s => s.id === req.params.id);
    if (service) {
        service.status = service.status === 'Connected' ? 'Disconnected' : 'Connected';
        return res.status(200).json(service);
    }
    return res.status(404).send('Service not found');
});

// ML Feature
app.get('/api/events', (req, res) => {
    res.json([...mockData.userEvents].reverse());
});

app.post('/api/simulate-anomaly', (req, res) => {
    const anomalousEvent = {
        ts: new Date().toISOString(),
        user: 'alice.jones@example.com',
        action: 'Login',
        details: { ip: '95.12.110.8', location: 'Frankfurt, Germany' }
    };
    mockData.userEvents.push(anomalousEvent);
    runAnomalyDetection();
    res.status(200).json({ message: 'Anomaly simulated successfully', event: anomalousEvent });
});

app.listen(PORT, () => {
    console.log(`CASB backend server running at http://localhost:${PORT}`);
    console.log('Current virtual time is set to ~September 2, 2025 in Bhopal, India for demo purposes.');
});


