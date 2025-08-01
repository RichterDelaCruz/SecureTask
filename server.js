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
const { securityLogger, setDbHelpers } = require('./utils/logger');

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
