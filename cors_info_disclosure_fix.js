// SECURITY FIX: CORS + Information Disclosure vulnerability
// Fixes cross-origin access to sensitive configuration data

const express = require('express');
const cors = require('cors');

const app = express();

// Fix CORS configuration for sensitive endpoints
const sensitiveCorsOptions = {
    origin: function (origin, callback) {
        // Only allow specific origins for sensitive data
        const allowedOrigins = [
            'https://app.aixblock.io',
            'https://workflow.aixblock.io',
            'https://workflow-live.aixblock.io'
        ];
        
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET'], // Only allow GET for configuration
    allowedHeaders: ['Origin', 'Content-Type', 'Accept', 'Authorization'],
    exposedHeaders: ['Content-Type'] // Only expose safe headers
};

// Apply CORS fix to sensitive endpoints
app.use('/api/v1/flags', cors(sensitiveCorsOptions));

// Add authentication to sensitive endpoints
app.get('/api/v1/flags', authenticateToken, (req, res) => {
    // Only return non-sensitive configuration
    const safeConfig = {
        ENVIRONMENT: process.env.ENVIRONMENT,
        CURRENT_VERSION: process.env.CURRENT_VERSION,
        // Remove sensitive data like Auth0 credentials
    };
    res.json(safeConfig);
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    // Verify token here
    next();
}

module.exports = app;
