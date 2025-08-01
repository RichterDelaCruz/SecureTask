const { securityLogger } = require('../utils/logger');

// Authentication middleware with enhanced security logging
const authenticateUser = (req, res, next) => {
    if (!req.session.user) {
        securityLogger.warn('Unauthorized access attempt', {
            url: req.url,
            method: req.method,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            timestamp: new Date().toISOString()
        });
        return res.redirect('/login');
    }

    // Add user context to request for consistent access
    req.user = req.session.user;
    next();
};

// Legacy authorization middleware for role-based access (maintained for backward compatibility)
const authorizeRole = (allowedRoles) => {
    return (req, res, next) => {
        // Fail securely - require authentication first
        if (!req.session.user) {
            securityLogger.warn('Unauthenticated access attempt', {
                url: req.url,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                requiredRoles: allowedRoles,
                timestamp: new Date().toISOString()
            });
            return res.redirect('/login');
        }

        // Validate role exists and is not empty
        if (!req.session.user.role || typeof req.session.user.role !== 'string') {
            securityLogger.error('Invalid user role detected', {
                username: req.session.user.username,
                role: req.session.user.role,
                url: req.url,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date().toISOString()
            });
            return res.status(403).render('error', {
                message: 'Access denied. Invalid user role.',
                user: req.session.user
            });
        }

        // Check if user's role is in allowed roles
        if (!Array.isArray(allowedRoles) || !allowedRoles.includes(req.session.user.role)) {
            securityLogger.warn('Access denied - insufficient privileges', {
                username: req.session.user.username,
                role: req.session.user.role,
                requiredRoles: allowedRoles,
                url: req.url,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date().toISOString()
            });
            return res.status(403).render('error', {
                message: 'Access denied. You do not have permission to view this page.',
                user: req.session.user
            });
        }

        // Add user context to request for consistent access
        req.user = req.session.user;
        next();
    };
};

// Middleware to prevent authenticated users from accessing auth pages
const redirectIfAuthenticated = (req, res, next) => {
    if (req.session.user) {
        securityLogger.info('Authenticated user redirected from auth page', {
            username: req.session.user.username,
            role: req.session.user.role,
            requestedUrl: req.url,
            ip: req.ip,
            timestamp: new Date().toISOString()
        });
        return res.redirect('/dashboard');
    }
    next();
};

module.exports = {
    authenticateUser,
    authorizeRole,
    redirectIfAuthenticated
};
