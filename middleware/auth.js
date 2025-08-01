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

// Session timeout check middleware
const checkSessionTimeout = (req, res, next) => {
    if (req.session.user) {
        const now = new Date();
        const lastActivity = req.session.lastActivity ? new Date(req.session.lastActivity) : new Date();
        const sessionTimeout = 30 * 60 * 1000; // 30 minutes in milliseconds

        if (now - lastActivity > sessionTimeout) {
            securityLogger.warn('Session timeout - auto logout', {
                username: req.session.user.username,
                lastActivity: lastActivity,
                ip: req.ip,
                sessionDuration: now - lastActivity
            });

            req.session.destroy((err) => {
                if (err) {
                    securityLogger.error('Session destruction failed during timeout', {
                        error: err.message,
                        ip: req.ip
                    });
                }
                return res.redirect('/login?error=timeout');
            });
            return;
        }

        // Update last activity
        req.session.lastActivity = now;
    }
    next();
};

// Session fixation protection
const preventSessionFixation = (req, res, next) => {
    // Regenerate session ID periodically for active sessions
    if (req.session.user && req.session.lastRegeneration) {
        const now = new Date();
        const lastRegen = new Date(req.session.lastRegeneration);
        const regenInterval = 15 * 60 * 1000; // 15 minutes

        if (now - lastRegen > regenInterval) {
            req.session.regenerate((err) => {
                if (err) {
                    securityLogger.error('Periodic session regeneration failed', {
                        username: req.session.user?.username,
                        error: err.message,
                        ip: req.ip
                    });
                    return next();
                }

                req.session.lastRegeneration = now;
                req.session.save(next);
            });
            return;
        }
    } else if (req.session.user) {
        req.session.lastRegeneration = new Date();
    }

    next();
};

module.exports = {
    authenticateUser,
    authorizeRole,
    redirectIfAuthenticated,
    checkSessionTimeout,
    preventSessionFixation
};
