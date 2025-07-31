const { securityLogger } = require('../utils/logger');

// Authentication middleware
const authenticateUser = (req, res, next) => {
    if (!req.session.user) {
        securityLogger.warn('Unauthorized access attempt', {
            url: req.url,
            method: req.method,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
        return res.redirect('/login');
    }
    next();
};

// Authorization middleware for role-based access
const authorizeRole = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.session.user) {
            securityLogger.warn('Unauthenticated access attempt', {
                url: req.url,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            return res.redirect('/login');
        }

        if (!allowedRoles.includes(req.session.user.role)) {
            securityLogger.warn('Access denied - insufficient privileges', {
                username: req.session.user.username,
                role: req.session.user.role,
                requiredRoles: allowedRoles,
                url: req.url,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            return res.status(403).render('error', {
                message: 'Access denied. You do not have permission to view this page.',
                user: req.session.user
            });
        }

        next();
    };
};

// Middleware to prevent authenticated users from accessing auth pages
const redirectIfAuthenticated = (req, res, next) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    next();
};

module.exports = {
    authenticateUser,
    authorizeRole,
    redirectIfAuthenticated
};
