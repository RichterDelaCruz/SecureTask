const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const winston = require('winston');
const csrf = require('csrf');
const crypto = require('crypto');

// Import route handlers
const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const adminRoutes = require('./routes/admin');
const accountRoutes = require('./routes/account');

// Import middleware
const { authenticateUser, authorizeRole, checkSessionTimeout, preventSessionFixation } = require('./middleware/auth');
const { securityLogger, setDbHelpers } = require('./utils/logger');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize CSRF protection
const tokens = new csrf();
const secret = tokens.secretSync();

// Security middleware with enhanced output encoding protection
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
        },
        reportOnly: false
    },
    crossOriginEmbedderPolicy: false, // Allow external resources like Bootstrap
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // limit each IP to 50 login requests per windowMs (increased from 20)
    message: 'Too many login attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for GET requests (viewing login page)
        return req.method === 'GET';
    },
    skipSuccessfulRequests: true // Don't count successful requests towards the limit
});

app.use(limiter);
app.use('/login', loginLimiter);

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Body parsing middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Static files with appropriate cache control
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0, // Cache static files for 1 day in production
    etag: true,
    lastModified: true,
    setHeaders: (res, path) => {
        // Additional cache control for static assets
        if (process.env.NODE_ENV === 'production') {
            res.setHeader('Cache-Control', 'public, max-age=86400'); // 24 hours for static assets
        } else {
            res.setHeader('Cache-Control', 'no-cache'); // No cache in development
        }
    }
}));

// Session configuration with hardening
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');

app.use(session({
    // Store sessions in SQLite database for persistence and security
    store: new SQLiteStore({
        db: 'sessions.db',
        dir: './database',
        table: 'sessions',
        concurrentDB: true,
    }),

    // Session security settings
    secret: sessionSecret,
    name: 'sessionId', // Change default session name to avoid fingerprinting
    resave: false,
    saveUninitialized: false,
    rolling: true, // Reset expiry on activity

    cookie: {
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        httpOnly: true, // Prevent XSS access to cookies
        maxAge: 1000 * 60 * 30, // 30 minutes (shorter for security)
        sameSite: 'strict' // CSRF protection
    },

    // Generate new session ID on login to prevent session fixation
    genid: () => {
        return crypto.randomBytes(32).toString('hex');
    }
}));

// Session security middleware
app.use((req, res, next) => {
    // Regenerate session ID on privilege escalation or login
    if (req.session.user && !req.session.regenerated) {
        req.session.regenerated = true;
        req.session.save((err) => {
            if (err) {
                securityLogger.error('Session save failed', {
                    error: err.message,
                    ip: req.ip
                });
            }
        });
    }

    // Track session activity for security monitoring
    if (req.session.user) {
        req.session.lastActivity = new Date();
        req.session.ipAddress = req.ip;
        req.session.userAgent = req.get('User-Agent');

        // Check for session hijacking (IP change detection)
        if (req.session.originalIP && req.session.originalIP !== req.ip) {
            securityLogger.warn('Potential session hijacking detected', {
                username: req.session.user.username,
                originalIP: req.session.originalIP,
                currentIP: req.ip,
                userAgent: req.get('User-Agent')
            });

            // Destroy suspicious session
            req.session.destroy((err) => {
                if (err) {
                    securityLogger.error('Failed to destroy suspicious session', { error: err.message });
                }
                return res.redirect('/login?error=security');
            });
            return;
        }

        // Set original IP on first login
        if (!req.session.originalIP) {
            req.session.originalIP = req.ip;
        }
    }

    next();
});

// Initialize database
const { db, dbHelpers } = require('./database/init');

// Set database helpers for logger
setDbHelpers(dbHelpers);

// Cache Control Middleware - applies different policies based on content type and auth status
app.use((req, res, next) => {
    // Default: No cache for all dynamic content and authenticated pages
    let cacheControl = 'no-store, no-cache, must-revalidate, proxy-revalidate';
    let pragma = 'no-cache';
    let expires = '0';

    // More permissive caching for public, non-sensitive static assets
    if (req.url.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/)) {
        if (process.env.NODE_ENV === 'production') {
            cacheControl = 'public, max-age=86400'; // 24 hours for static assets in production
            pragma = 'cache';
            expires = new Date(Date.now() + 86400000).toUTCString(); // 24 hours from now
        } else {
            cacheControl = 'no-cache'; // No cache in development
        }
    }
    // Authenticated pages and sensitive content - strict no-cache policy
    else if (req.session && req.session.user) {
        cacheControl = 'no-store, no-cache, must-revalidate, proxy-revalidate, private';
        res.setHeader('Surrogate-Control', 'no-store');
    }
    // Public pages (login, register) - limited cache to prevent replay attacks
    else {
        cacheControl = 'no-cache, no-store, must-revalidate';
    }

    // Apply cache control headers
    res.setHeader('Cache-Control', cacheControl);
    res.setHeader('Pragma', pragma);
    res.setHeader('Expires', expires);

    next();
});

// Output encoding middleware - adds security headers and encoding helpers
app.use((req, res, next) => {
    // Add additional security headers for output protection
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Override res.render to ensure all data is properly encoded
    const originalRender = res.render;
    res.render = function (view, options = {}, callback) {
        // Ensure encoding functions are available in all templates
        if (typeof options === 'object' && options !== null) {
            const { htmlEncode, jsEncode, urlEncode, cssEncode } = require('./utils/validation');
            options.htmlEncode = htmlEncode;
            options.jsEncode = jsEncode;
            options.urlEncode = urlEncode;
            options.cssEncode = cssEncode;
        }

        return originalRender.call(this, view, options, callback);
    };

    next();
});

// Apply session hardening middleware
app.use(checkSessionTimeout);
app.use(preventSessionFixation);

// CSRF Protection Middleware
app.use((req, res, next) => {
    // Skip CSRF for GET requests (they should be safe)
    if (req.method === 'GET') {
        const token = tokens.create(secret);
        req.csrfToken = token;
        res.locals.csrfToken = token;
        return next();
    }

    // For POST, PUT, DELETE requests, verify CSRF token
    const token = req.body._csrf || req.headers['x-csrf-token'];

    if (!token || !tokens.verify(secret, token)) {
        securityLogger.warn('CSRF token validation failed', {
            ip: req.ip,
            method: req.method,
            url: req.url,
            userAgent: req.get('User-Agent'),
            user: req.session.user?.username
        });
        return res.status(403).render('error', {
            message: 'Invalid CSRF token',
            user: req.session.user
        });
    }

    // Create new token for next request
    const newToken = tokens.create(secret);
    req.csrfToken = newToken;
    res.locals.csrfToken = newToken;
    next();
});

// Favicon route to prevent 404 warnings
app.get('/favicon.ico', (req, res) => {
    res.status(204).end(); // No Content response
});

// Routes
app.use('/', authRoutes);
app.use('/dashboard', authenticateUser, dashboardRoutes);
app.use('/admin', authenticateUser, authorizeRole(['Administrator']), adminRoutes);
app.use('/account', authenticateUser, accountRoutes);

// Logout route with strict cache control
app.post('/logout', authenticateUser, (req, res) => {
    // Ensure logout response is never cached
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');

    const username = req.session.user?.username;
    securityLogger.info(`User logout`, { username, ip: req.ip });

    req.session.destroy((err) => {
        if (err) {
            securityLogger.error('Session destruction failed', { username, error: err.message });
            return res.status(500).render('error', {
                message: 'Logout failed',
                user: req.session.user
            });
        }
        res.redirect('/login');
    });
});

// Error handling middleware
app.use((req, res, next) => {
    securityLogger.warn('404 Not Found', {
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });
    res.status(404).render('error', {
        message: 'Page not found',
        user: req.session.user
    });
});

app.use((err, req, res, next) => {
    securityLogger.error('Application error', {
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        user: req.session.user?.username
    });

    res.status(500).render('error', {
        message: 'Internal server error',
        user: req.session.user
    });
});

app.listen(PORT, () => {
    console.log(`SecureTask server running on port ${PORT}`);
    securityLogger.info('Server started', { port: PORT });
});

module.exports = app;
