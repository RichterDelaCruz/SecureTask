const { securityLogger } = require('./logger');

/**
 * Centralized Security Event Logging
 * Ensures consistent logging of all security-related events
 * across the application with proper categorization and context.
 */

// Security event types for consistent logging
const SECURITY_EVENTS = {
    // Authentication events
    LOGIN_SUCCESS: 'login_success',
    LOGIN_FAILURE: 'login_failure',
    LOGIN_LOCKED_ACCOUNT: 'login_locked_account',
    LOGOUT: 'logout',
    REGISTRATION_SUCCESS: 'registration_success',
    REGISTRATION_FAILURE: 'registration_failure',
    
    // Authorization events
    ACCESS_GRANTED: 'access_granted',
    ACCESS_DENIED: 'access_denied',
    PERMISSION_DENIED: 'permission_denied',
    RESOURCE_ACCESS_DENIED: 'resource_access_denied',
    
    // Password events
    PASSWORD_CHANGE_SUCCESS: 'password_change_success',
    PASSWORD_CHANGE_FAILURE: 'password_change_failure',
    PASSWORD_RESET_REQUEST: 'password_reset_request',
    REAUTH_SUCCESS: 'reauth_success',
    REAUTH_FAILURE: 'reauth_failure',
    
    // Validation events
    VALIDATION_FAILURE: 'validation_failure',
    SECURITY_VALIDATION_FAILURE: 'security_validation_failure',
    MALICIOUS_INPUT_DETECTED: 'malicious_input_detected',
    
    // Administrative events
    ADMIN_ACTION: 'admin_action',
    USER_CREATED: 'user_created',
    USER_DELETED: 'user_deleted',
    ROLE_CHANGED: 'role_changed',
    
    // System events
    RATE_LIMIT_EXCEEDED: 'rate_limit_exceeded',
    SESSION_EXPIRED: 'session_expired',
    SESSION_HIJACK_ATTEMPT: 'session_hijack_attempt',
    
    // Task events (business logic)
    TASK_CREATED: 'task_created',
    TASK_DELETED: 'task_deleted',
    TASK_REASSIGNED: 'task_reassigned',
    TASK_STATUS_CHANGED: 'task_status_changed',
    
    // System monitoring
    LOG_SYSTEM_ACCESSED: 'log_system_accessed',
    SYSTEM_ERROR: 'system_error',
    DATABASE_ERROR: 'database_error'
};

// Risk levels for security events
const RISK_LEVELS = {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical'
};

// Create standardized context for security events
const createSecurityContext = (req, additionalContext = {}) => {
    const user = req.session?.user;
    
    return {
        // Request context
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        method: req.method,
        url: req.url,
        referer: req.get('Referer'),
        
        // User context
        userId: user?.id || null,
        username: user?.username || 'anonymous',
        userRole: user?.role || 'none',
        sessionId: req.sessionID,
        
        // Timing
        timestamp: new Date().toISOString(),
        
        // Additional context
        ...additionalContext
    };
};

// Main security event logger
const logSecurityEvent = (eventType, req, riskLevel = RISK_LEVELS.MEDIUM, additionalContext = {}) => {
    const context = createSecurityContext(req, additionalContext);
    
    const logData = {
        securityEvent: eventType,
        riskLevel: riskLevel,
        ...context
    };
    
    // Log with appropriate severity based on risk level
    switch (riskLevel) {
        case RISK_LEVELS.CRITICAL:
            securityLogger.error(`SECURITY EVENT [${eventType.toUpperCase()}]`, logData);
            break;
        case RISK_LEVELS.HIGH:
            securityLogger.error(`SECURITY EVENT [${eventType.toUpperCase()}]`, logData);
            break;
        case RISK_LEVELS.MEDIUM:
            securityLogger.warn(`SECURITY EVENT [${eventType.toUpperCase()}]`, logData);
            break;
        case RISK_LEVELS.LOW:
        default:
            securityLogger.info(`SECURITY EVENT [${eventType.toUpperCase()}]`, logData);
            break;
    }
    
    return logData;
};

// Convenience methods for common security events

const logAuthenticationEvent = (eventType, req, success = true, additionalContext = {}) => {
    const riskLevel = success ? RISK_LEVELS.LOW : RISK_LEVELS.HIGH;
    return logSecurityEvent(eventType, req, riskLevel, additionalContext);
};

const logAuthorizationEvent = (eventType, req, granted = false, additionalContext = {}) => {
    const riskLevel = granted ? RISK_LEVELS.LOW : RISK_LEVELS.HIGH;
    return logSecurityEvent(eventType, req, riskLevel, additionalContext);
};

const logValidationEvent = (req, errors, isSecurity = false, additionalContext = {}) => {
    const eventType = isSecurity ? SECURITY_EVENTS.SECURITY_VALIDATION_FAILURE : SECURITY_EVENTS.VALIDATION_FAILURE;
    const riskLevel = isSecurity ? RISK_LEVELS.CRITICAL : RISK_LEVELS.MEDIUM;
    
    const context = {
        validationErrors: errors.map(err => ({
            field: err.param,
            message: err.msg,
            value: err.value ? 'REDACTED' : undefined
        })),
        ...additionalContext
    };
    
    return logSecurityEvent(eventType, req, riskLevel, context);
};

const logAdministrativeEvent = (action, req, target = null, additionalContext = {}) => {
    const context = {
        adminAction: action,
        targetUser: target,
        ...additionalContext
    };
    
    return logSecurityEvent(SECURITY_EVENTS.ADMIN_ACTION, req, RISK_LEVELS.MEDIUM, context);
};

const logBusinessEvent = (eventType, req, details = {}, additionalContext = {}) => {
    const context = {
        businessOperation: details,
        ...additionalContext
    };
    
    return logSecurityEvent(eventType, req, RISK_LEVELS.LOW, context);
};

const logSystemEvent = (eventType, req, severity = RISK_LEVELS.MEDIUM, additionalContext = {}) => {
    return logSecurityEvent(eventType, req, severity, additionalContext);
};

// Rate limiting and anomaly detection helpers
const trackUserBehavior = (req, action) => {
    const user = req.session?.user;
    if (!user) return;
    
    const userActivity = {
        action: action,
        timestamp: Date.now(),
        ip: req.ip,
        userAgent: req.get('User-Agent')
    };
    
    // Could extend this to implement behavioral analysis
    logSecurityEvent('user_activity', req, RISK_LEVELS.LOW, { activity: userActivity });
};

// Export all functionality
module.exports = {
    SECURITY_EVENTS,
    RISK_LEVELS,
    logSecurityEvent,
    logAuthenticationEvent,
    logAuthorizationEvent,
    logValidationEvent,
    logAdministrativeEvent,
    logBusinessEvent,
    logSystemEvent,
    createSecurityContext,
    trackUserBehavior
};
