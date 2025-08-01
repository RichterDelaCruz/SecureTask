const { securityLogger } = require('../utils/logger');

/**
 * Centralized Error Handler Middleware
 * Provides comprehensive error handling with security-focused logging
 * while preventing information leakage to end users.
 */

// Error categorization for better monitoring
const ERROR_CATEGORIES = {
    VALIDATION: 'validation',
    AUTHENTICATION: 'authentication', 
    AUTHORIZATION: 'authorization',
    DATABASE: 'database',
    SECURITY: 'security',
    SYSTEM: 'system',
    BUSINESS_LOGIC: 'business_logic'
};

// Error severity levels
const ERROR_SEVERITY = {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical'
};

// Security-focused error classification
const classifyError = (error, req) => {
    const message = (error.message || '').toLowerCase();
    const url = req.url.toLowerCase();
    
    // Security-related errors (high priority)
    if (message.includes('dangerous') || message.includes('injection') || 
        message.includes('xss') || message.includes('suspicious') ||
        message.includes('malicious') || message.includes('attack')) {
        return { category: ERROR_CATEGORIES.SECURITY, severity: ERROR_SEVERITY.CRITICAL };
    }
    
    // Authentication errors
    if (message.includes('auth') || message.includes('login') || 
        message.includes('password') || message.includes('credential') ||
        url.includes('/login') || url.includes('/auth')) {
        return { category: ERROR_CATEGORIES.AUTHENTICATION, severity: ERROR_SEVERITY.HIGH };
    }
    
    // Authorization errors
    if (message.includes('permission') || message.includes('access denied') ||
        message.includes('forbidden') || message.includes('unauthorized') ||
        error.status === 403) {
        return { category: ERROR_CATEGORIES.AUTHORIZATION, severity: ERROR_SEVERITY.HIGH };
    }
    
    // Database errors
    if (message.includes('database') || message.includes('sql') || 
        message.includes('sqlite') || message.includes('db') ||
        message.includes('connection')) {
        return { category: ERROR_CATEGORIES.DATABASE, severity: ERROR_SEVERITY.MEDIUM };
    }
    
    // Validation errors
    if (message.includes('validation') || message.includes('invalid') ||
        message.includes('required') || message.includes('format') ||
        error.status === 400) {
        return { category: ERROR_CATEGORIES.VALIDATION, severity: ERROR_SEVERITY.LOW };
    }
    
    // Business logic errors
    if (message.includes('business') || message.includes('rule') ||
        message.includes('not allowed')) {
        return { category: ERROR_CATEGORIES.BUSINESS_LOGIC, severity: ERROR_SEVERITY.MEDIUM };
    }
    
    // Default to system error
    return { category: ERROR_CATEGORIES.SYSTEM, severity: ERROR_SEVERITY.MEDIUM };
};

// Create comprehensive error context for logging
const createErrorContext = (error, req, classification) => {
    const user = req.session?.user;
    
    const context = {
        // Error information (sanitized)
        errorId: generateErrorId(),
        category: classification.category,
        severity: classification.severity,
        message: error.message,
        status: error.status || 500,
        
        // Request information
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        
        // User information (if available)
        userId: user?.id || null,
        username: user?.username || 'anonymous',
        userRole: user?.role || 'none',
        
        // Security context
        isAuthenticated: !!user,
        sessionId: req.sessionID,
        
        // Timing
        timestamp: new Date().toISOString(),
        
        // Additional context for debugging (only in logs, never to user)
        requestHeaders: {
            'content-type': req.get('Content-Type'),
            'content-length': req.get('Content-Length'),
            'host': req.get('Host')
        }
    };
    
    // Add stack trace only for system errors and only in logs
    if (classification.category === ERROR_CATEGORIES.SYSTEM && error.stack) {
        context.stack = error.stack;
    }
    
    return context;
};

// Generate unique error ID for tracking
const generateErrorId = () => {
    return `ERR_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};

// Get user-safe error message (never expose sensitive information)
const getUserSafeMessage = (error, classification, req) => {
    const status = error.status || 500;
    
    // Security errors - generic message to prevent information leakage
    if (classification.category === ERROR_CATEGORIES.SECURITY) {
        return 'Your request has been blocked for security reasons.';
    }
    
    // Authentication errors
    if (classification.category === ERROR_CATEGORIES.AUTHENTICATION) {
        if (status === 401) {
            return 'Please log in to access this page.';
        }
        return 'Authentication failed. Please try again.';
    }
    
    // Authorization errors
    if (classification.category === ERROR_CATEGORIES.AUTHORIZATION) {
        return 'You do not have permission to access this resource.';
    }
    
    // Validation errors - can be more specific but safe
    if (classification.category === ERROR_CATEGORIES.VALIDATION) {
        // Only return validation messages that don't contain sensitive info
        const message = error.message || '';
        if (message.includes('dangerous') || message.includes('injection') || 
            message.includes('suspicious')) {
            return 'Invalid input provided.';
        }
        return message || 'Invalid input provided.';
    }
    
    // Business logic errors
    if (classification.category === ERROR_CATEGORIES.BUSINESS_LOGIC) {
        return error.message || 'Operation not allowed.';
    }
    
    // Default messages by status code
    switch (status) {
        case 400:
            return 'Bad request. Please check your input.';
        case 401:
            return 'Please log in to access this page.';
        case 403:
            return 'You do not have permission to access this resource.';
        case 404:
            return 'The requested page could not be found.';
        case 429:
            return 'Too many requests. Please try again later.';
        case 500:
        default:
            return 'Something went wrong. Please try again later.';
    }
};

// Main error handling middleware
const errorHandler = (error, req, res, next) => {
    // Classify the error
    const classification = classifyError(error, req);
    
    // Create comprehensive error context
    const errorContext = createErrorContext(error, req, classification);
    
    // Log the error with appropriate severity
    switch (classification.severity) {
        case ERROR_SEVERITY.CRITICAL:
            securityLogger.error('CRITICAL ERROR', errorContext);
            break;
        case ERROR_SEVERITY.HIGH:
            securityLogger.error('HIGH SEVERITY ERROR', errorContext);
            break;
        case ERROR_SEVERITY.MEDIUM:
            securityLogger.warn('MEDIUM SEVERITY ERROR', errorContext);
            break;
        case ERROR_SEVERITY.LOW:
        default:
            securityLogger.info('LOW SEVERITY ERROR', errorContext);
            break;
    }
    
    // Get user-safe message
    const userMessage = getUserSafeMessage(error, classification, req);
    const status = error.status || 500;
    
    // Prevent response if headers already sent
    if (res.headersSent) {
        return next(error);
    }
    
    // Handle different response formats
    if (req.accepts('html')) {
        // HTML response for web requests
        res.status(status).render('error', {
            message: userMessage,
            user: req.session?.user || null,
            errorId: errorContext.errorId // Include error ID for support purposes
        });
    } else if (req.accepts('json')) {
        // JSON response for API requests
        res.status(status).json({
            error: {
                message: userMessage,
                errorId: errorContext.errorId,
                status: status
            }
        });
    } else {
        // Plain text fallback
        res.status(status).type('txt').send(userMessage);
    }
};

// 404 Not Found handler
const notFoundHandler = (req, res, next) => {
    const errorContext = {
        errorId: generateErrorId(),
        category: ERROR_CATEGORIES.SYSTEM,
        severity: ERROR_SEVERITY.LOW,
        message: 'Page not found',
        status: 404,
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        referer: req.get('Referer'),
        userId: req.session?.user?.id || null,
        username: req.session?.user?.username || 'anonymous',
        userRole: req.session?.user?.role || 'none',
        isAuthenticated: !!req.session?.user,
        timestamp: new Date().toISOString()
    };
    
    securityLogger.warn('404 Not Found', errorContext);
    
    if (req.accepts('html')) {
        res.status(404).render('error', {
            message: 'The requested page could not be found.',
            user: req.session?.user || null,
            errorId: errorContext.errorId
        });
    } else if (req.accepts('json')) {
        res.status(404).json({
            error: {
                message: 'Not found',
                errorId: errorContext.errorId,
                status: 404
            }
        });
    } else {
        res.status(404).type('txt').send('Not found');
    }
};

// Async error wrapper for route handlers
const asyncErrorHandler = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

// Rate limiting error handler
const rateLimitErrorHandler = (req, res, next) => {
    const errorContext = {
        errorId: generateErrorId(),
        category: ERROR_CATEGORIES.SECURITY,
        severity: ERROR_SEVERITY.HIGH,
        message: 'Rate limit exceeded',
        status: 429,
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.session?.user?.id || null,
        username: req.session?.user?.username || 'anonymous',
        timestamp: new Date().toISOString()
    };
    
    securityLogger.warn('RATE LIMIT EXCEEDED', errorContext);
    
    const error = new Error('Too many requests');
    error.status = 429;
    next(error);
};

module.exports = {
    errorHandler,
    notFoundHandler,
    asyncErrorHandler,
    rateLimitErrorHandler,
    ERROR_CATEGORIES,
    ERROR_SEVERITY,
    classifyError,
    createErrorContext,
    getUserSafeMessage
};
