// 🛡️ AIxBlock Security Fixes - Express.js Application Level
// Fixes for 5 new vulnerabilities discovered

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// SECURITY FIX 1: Comprehensive security headers (Missing Security Headers)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "https:"],
            frameAncestors: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: { policy: "require-corp" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-origin" },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Additional security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=(), vibrate=(), fullscreen=(), sync-xhr=()');
    res.setHeader('X-Download-Options', 'noopen');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    
    // Hide server version
    res.removeHeader('Server');
    res.setHeader('Server', 'AIxBlock');
    
    next();
});

// SECURITY FIX 2: Fix CORS misconfiguration (CORS Main Domain)
const corsOptions = {
    origin: function (origin, callback) {
        // Allow specific origins only
        const allowedOrigins = [
            'https://app.aixblock.io',
            'https://workflow.aixblock.io',
            'https://workflow-live.aixblock.io'
        ];
        
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Origin', 'Content-Type', 'Accept', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400
};

app.use(cors(corsOptions));

// SECURITY FIX 3: IP header validation (IP Header Injection)
app.use((req, res, next) => {
    // Validate and sanitize IP headers
    const suspiciousHeaders = ['x-forwarded-for', 'x-real-ip', 'x-client-ip', 'x-originating-ip'];
    
    suspiciousHeaders.forEach(header => {
        if (req.headers[header]) {
            // Check for CRLF injection
            if (req.headers[header].includes('\r') || req.headers[header].includes('\n')) {
                return res.status(400).json({ error: 'Invalid header format' });
            }
            
            // Remove suspicious IP headers
            delete req.headers[header];
        }
    });
    
    // Use only trusted proxy IPs
    const clientIP = req.connection.remoteAddress || req.socket.remoteAddress;
    req.clientIP = clientIP;
    
    next();
});

// SECURITY FIX 4: HTTP header injection prevention (HTTP Header Injection)
app.use((req, res, next) => {
    // Sanitize User-Agent header
    if (req.headers['user-agent']) {
        // Check for CRLF injection
        if (req.headers['user-agent'].includes('\r') || req.headers['user-agent'].includes('\n')) {
            return res.status(400).json({ error: 'Invalid User-Agent header' });
        }
        
        // Limit User-Agent length
        if (req.headers['user-agent'].length > 1000) {
            return res.status(400).json({ error: 'User-Agent header too long' });
        }
        
        // Sanitize User-Agent
        req.headers['user-agent'] = req.headers['user-agent']
            .replace(/[\r\n]/g, '')
            .substring(0, 1000);
    }
    
    // Sanitize other headers
    const headersToSanitize = ['accept', 'accept-language', 'accept-encoding'];
    headersToSanitize.forEach(header => {
        if (req.headers[header]) {
            // Check for CRLF injection
            if (req.headers[header].includes('\r') || req.headers[header].includes('\n')) {
                return res.status(400).json({ error: `Invalid ${header} header` });
            }
        }
    });
    
    next();
});

// SECURITY FIX 5: Rate limiting and additional security measures
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(limiter);

// Additional security middleware
app.use((req, res, next) => {
    // Request size limits
    if (req.headers['content-length'] && parseInt(req.headers['content-length']) > 10 * 1024 * 1024) {
        return res.status(413).json({ error: 'Request entity too large' });
    }
    
    // Timeout handling
    req.setTimeout(30000, () => {
        res.status(408).json({ error: 'Request timeout' });
    });
    
    next();
});

// Error handling middleware
app.use((err, req, res, next) => {
    if (err.message === 'Not allowed by CORS') {
        res.status(403).json({ error: 'CORS policy violation' });
    } else {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// API routes
app.use('/api', (req, res, next) => {
    // Additional API-specific security
    res.setHeader('X-API-Version', '1.0');
    next();
});

module.exports = app;
