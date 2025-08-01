const { securityLogger } = require('../utils/logger');

/**
 * Authorization Audit Middleware
 * Provides comprehensive logging and monitoring of authorization decisions
 * for security compliance and debugging purposes.
 */

// Track authorization events for audit purposes
const auditAuthorizationEvent = (eventType, req, details = {}) => {
    const auditData = {
        event: eventType,
        username: req.session?.user?.username || 'anonymous',
        role: req.session?.user?.role || 'none',
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
        ...details
    };
    
    securityLogger.info('Authorization Event', auditData);
    
    // Additional security monitoring for suspicious patterns
    if (eventType === 'ACCESS_DENIED' || eventType === 'PERMISSION_DENIED') {
        securityLogger.warn('Security Event - Access Denied', auditData);
    }
};

// Middleware to check if route has proper authorization
const validateRouteProtection = (requiredProtection = 'authentication') => {
    return (req, res, next) => {
        // Check if user is authenticated for protected routes
        if (requiredProtection === 'authentication' && !req.session.user) {
            auditAuthorizationEvent('UNAUTHENTICATED_ACCESS', req, {
                requiredProtection: requiredProtection
            });
            return res.redirect('/login');
        }
        
        // Log successful authentication
        if (req.session.user) {
            auditAuthorizationEvent('AUTHENTICATED_ACCESS', req, {
                userId: req.session.user.id
            });
        }
        
        next();
    };
};

// Enhanced session validation with integrity checks
const validateSessionIntegrity = (req, res, next) => {
    if (req.session.user) {
        // Validate session data integrity
        const user = req.session.user;
        
        // Check for required session fields
        if (!user.id || !user.username || !user.role) {
            auditAuthorizationEvent('SESSION_INTEGRITY_FAILURE', req, {
                missingFields: {
                    id: !user.id,
                    username: !user.username,
                    role: !user.role
                }
            });
            
            req.session.destroy((err) => {
                if (err) {
                    securityLogger.error('Failed to destroy corrupted session', {
                        error: err.message,
                        ip: req.ip
                    });
                }
            });
            
            return res.redirect('/login');
        }
        
        // Validate role is a valid role
        const validRoles = ['Administrator', 'Project Manager', 'Employee'];
        if (!validRoles.includes(user.role)) {
            auditAuthorizationEvent('INVALID_ROLE_DETECTED', req, {
                invalidRole: user.role,
                validRoles: validRoles
            });
            
            req.session.destroy();
            return res.redirect('/login');
        }
        
        auditAuthorizationEvent('SESSION_VALIDATED', req, {
            sessionDuration: Date.now() - (req.session.cookie.originalMaxAge || 0)
        });
    }
    
    next();
};

// Comprehensive route protection summary
const getRouteProtectionSummary = () => {
    return {
        'Authentication Required': [
            '/dashboard/*',
            '/admin/*',
            '/account/*',
            '/logout'
        ],
        'Role-Based Authorization': {
            'Administrator Only': [
                '/admin/managers',
                '/admin/logs',
                '/admin/create-manager',
                '/admin/delete-manager'
            ],
            'Project Manager Only': [
                '/dashboard/create-task',
                '/dashboard/reassign-task',
                '/dashboard/delete-task'
            ],
            'Employee Only': [
                '/dashboard/update-task-status'
            ],
            'All Authenticated Users': [
                '/dashboard',
                '/account/change-password',
                '/logout'
            ]
        },
        'Resource Ownership Validation': [
            'Task operations (create, edit, delete, reassign)',
            'Profile access and modifications',
            'User-specific data access'
        ],
        'Business Logic Enforcement': [
            'Manager deletion restrictions',
            'Task assignment to employees only',
            'Resource ownership validation'
        ]
    };
};

// Rate limiting for sensitive operations
const sensitiveOperationLimiter = (operationType, maxAttempts = 5, windowMs = 15 * 60 * 1000) => {
    const attempts = new Map();
    
    return (req, res, next) => {
        if (!req.session.user) {
            return next();
        }
        
        const key = `${req.session.user.id}:${operationType}`;
        const now = Date.now();
        const userAttempts = attempts.get(key) || { count: 0, resetTime: now + windowMs };
        
        // Reset counter if window has expired
        if (now > userAttempts.resetTime) {
            userAttempts.count = 0;
            userAttempts.resetTime = now + windowMs;
        }
        
        // Check if limit exceeded
        if (userAttempts.count >= maxAttempts) {
            auditAuthorizationEvent('RATE_LIMIT_EXCEEDED', req, {
                operationType: operationType,
                attempts: userAttempts.count,
                maxAttempts: maxAttempts
            });
            
            return res.status(429).render('error', {
                message: 'Too many attempts. Please try again later.',
                user: req.session.user
            });
        }
        
        // Increment counter
        userAttempts.count++;
        attempts.set(key, userAttempts);
        
        // Clean up old entries periodically
        if (Math.random() < 0.01) { // 1% chance
            const cutoff = now - windowMs;
            for (const [k, v] of attempts.entries()) {
                if (v.resetTime < cutoff) {
                    attempts.delete(k);
                }
            }
        }
        
        next();
    };
};

module.exports = {
    auditAuthorizationEvent,
    validateRouteProtection,
    validateSessionIntegrity,
    getRouteProtectionSummary,
    sensitiveOperationLimiter
};
