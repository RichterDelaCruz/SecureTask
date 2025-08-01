const express = require('express');
const session = require('express-session');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const winston = require('winston');

// Import route handlers
const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const adminRoutes = require('./routes/admin');
const accountRoutes = require('./routes/account');

// Import middleware
const { authenticateUser, authorizeRole } = require('./middleware/auth');
const { addSecurityHeaders } = require('./middleware/authorization');
const { validateSessionIntegrity, sensitiveOperationLimiter } = require('./middleware/authz-audit');
const { errorHandler, notFoundHandler, asyncErrorHandler } = require('./middleware/error-handler');
const { securityLogger, setDbHelpers } = require('./utils/logger');
const { validateRequest } = require('./utils/validation');
const { logAuthenticationEvent, SECURITY_EVENTS } = require('./utils/security-logger');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

// Additional security headers
app.use(addSecurityHeaders);

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

// Body parsing middleware with strict limits
app.use(express.urlencoded({ 
    extended: true,
    limit: '10mb',
    parameterLimit: 100 // Limit number of parameters  
}));
app.use(express.json({
    limit: '1mb',
    strict: true // Only accept arrays and objects
}));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-super-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 // 24 hours
    }
}));

// Initialize database
const { db, dbHelpers } = require('./database/init');

// Set database helpers for logger
setDbHelpers(dbHelpers);

// Apply session integrity validation to all routes
app.use(validateSessionIntegrity);

// Apply comprehensive request validation
app.use(validateRequest({
    maxBodySize: 10 * 1024 * 1024, // 10MB
    maxParams: 100,
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    requireHttps: false, // Set to true in production
    checkContentType: true
}));

// Favicon route to prevent 404 warnings
app.get('/favicon.ico', (req, res) => {
    res.status(204).end(); // No Content response
});

// Routes
app.use('/', authRoutes);
app.use('/dashboard', authenticateUser, dashboardRoutes);
app.use('/admin', authenticateUser, authorizeRole(['Administrator']), adminRoutes);
app.use('/account', authenticateUser, accountRoutes);

// Logout route
app.post('/logout', authenticateUser, (req, res) => {
    const username = req.session.user?.username;
    
    // Log logout event
    logAuthenticationEvent(SECURITY_EVENTS.LOGOUT, req, true, { username });
    
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

// Error handling middleware - use centralized handlers
app.use(notFoundHandler);
app.use(errorHandler);

app.listen(PORT, () => {
    console.log(`SecureTask server running on port ${PORT}`);
    securityLogger.info('Server started', { port: PORT });
});

module.exports = app;
