const { body, validationResult, param, query } = require('express-validator');

// Centralized validation patterns for strict data validation
const VALIDATION_PATTERNS = {
    // Username: 3-20 chars, alphanumeric and underscore only
    USERNAME: /^[a-zA-Z0-9_]{3,20}$/,
    
    // Password: 6-128 chars, must contain at least one letter and one number
    PASSWORD: /^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z\d@$!%*?&#+\-_=[\]{}|\\:";'<>?,./]{6,128}$/,
    
    // Task priority levels (exact match)
    TASK_PRIORITY: /^(Low|Medium|High)$/,
    
    // Task status (exact match)
    TASK_STATUS: /^(Pending|Completed)$/,
    
    // Email pattern (RFC 5322 compliant)
    EMAIL: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
    
    // Phone number (international format)
    PHONE: /^[\+]?[1-9][\d]{0,15}$/,
    
    // Date format (YYYY-MM-DD)
    DATE: /^\d{4}-\d{2}-\d{2}$/,
    
    // Time format (HH:MM)
    TIME: /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/,
    
    // URL pattern (HTTP/HTTPS only)
    URL: /^https?:\/\/(?:[-\w.])+(?:\:[0-9]+)?(?:\/(?:[\w\._~!$&'()*+,;=:@]|%[\da-fA-F]{2})*)*(?:\?(?:[\w\._~!$&'()*+,;=:@/?]|%[\da-fA-F]{2})*)?(?:\#(?:[\w\._~!$&'()*+,;=:@/?]|%[\da-fA-F]{2})*)?$/,
    
    // Dangerous content detection (enhanced)
    DANGEROUS_CONTENT: /<script|javascript:|data:|vbscript:|on\w+\s*=|<iframe|<object|<embed|<form|<link|<meta|<style|<base|<applet|<body|<html|<head|expression\s*\(|@import|url\s*\(|eval\s*\(|setTimeout|setInterval/i,
    
    // SQL injection patterns (enhanced)
    SQL_INJECTION: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|DECLARE|SCRIPT|TRUNCATE|MERGE|REPLACE|CALL|EXECUTE|LOAD|HANDLER|PREPARE|DEALLOCATE)\b)|('(''|[^'])*')|(;)|(--)|(\/\*|\*\/)|(\bOR\b|\bAND\b)\s*\d+\s*=\s*\d+|(\bOR\b|\bAND\b)\s*['"][^'"]*['"]\s*=\s*['"][^'"]*['"]|\bhex\s*\(|\bchar\s*\(|\bconcat\s*\(|\bsubstring\s*\(|\bascii\s*\(|\border\s+by\b|\bgroup\s+by\b|\bhaving\b|\blimit\b|\boffset\b/i,
    
    // NoSQL injection patterns
    NOSQL_INJECTION: /\$where|\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin|\$regex|\$exists|\$type|\$mod|\$all|\$size|\$elemMatch|\$slice/i,
    
    // XSS patterns (enhanced)
    XSS_PATTERNS: /<script|<\/script|javascript:|vbscript:|onload|onerror|onclick|onmouseover|onfocus|onblur|onchange|onsubmit|<img[^>]*src[^>]*=|<link[^>]*href|<iframe|<object|<embed|<applet|<meta[^>]*http-equiv|<base[^>]*href|expression\s*\(|@import|url\s*\(|&lt;script|&lt;\/script|&lt;img|&lt;iframe|%3Cscript|%3C\/script|%3Cimg|%3Ciframe|\uFEFF|\u200B|\u200C|\u200D|\uFFFE|\uFFFF/i,
    
    // Command injection patterns
    COMMAND_INJECTION: /(\||&|;|\$\(|\$\{|`|\$\$|exec|system|passthru|shell_exec|popen|proc_open|eval|assert|include|require|file_get_contents|file_put_contents|fopen|fwrite|readfile|unlink|rmdir|mkdir|chmod|chown|touch|copy|move|rename|ls|dir|cat|type|more|less|head|tail|grep|find|locate|which|whoami|id|pwd|cd|rm|del|copy|move|mv|cp|ln|tar|zip|unzip|gzip|gunzip|wget|curl|nc|netcat|telnet|ssh|ftp|ping|nslookup|dig|arp|netstat|ps|top|kill|killall|su|sudo|chmod|chown|mount|umount|fdisk|df|du|free|uname|hostname|uptime|crontab|at|service|systemctl|iptables|route|ifconfig|iwconfig)/i,
    
    // Path traversal patterns
    PATH_TRAVERSAL: /\.\.|\/\.\.|\\\.\.|\.\.\//i,
    
    // LDAP injection patterns (disabled - not using LDAP authentication)
    // LDAP_INJECTION: /(\*|\(|\)|\||&|!|=|<|>|~|;|,|\+|"|'|\\|\/|\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x09|\x0a|\x0b|\x0c|\x0d|\x0e|\x0f)/,
    
    // XXE patterns
    XXE_PATTERNS: /<!ENTITY|<!DOCTYPE|SYSTEM\s+["']|PUBLIC\s+["']|&[a-zA-Z0-9_]+;|\[CDATA\[/i,
    
    // Template injection patterns
    TEMPLATE_INJECTION: /\{\{.*\}\}|\{%.*%\}|\{#.*#\}|\$\{.*\}|<%.*%>|#\{.*\}/
};

// Validation ranges and limits
const VALIDATION_LIMITS = {
    USERNAME: { min: 3, max: 20 },
    PASSWORD: { min: 6, max: 128 },
    TASK_TITLE: { min: 1, max: 100 },
    TASK_DESCRIPTION: { min: 0, max: 500 },
    USER_ID: { min: 1, max: 2147483647 }, // Max 32-bit integer
    TASK_ID: { min: 1, max: 2147483647 },
    EMAIL: { min: 5, max: 254 }, // RFC 5321 limit
    PHONE: { min: 7, max: 15 }, // ITU-T E.164 recommendation
    URL: { min: 10, max: 2048 }, // Practical URL length limit
    TEXT_SHORT: { min: 1, max: 255 },
    TEXT_MEDIUM: { min: 1, max: 1000 },
    TEXT_LONG: { min: 1, max: 5000 },
    NAME: { min: 1, max: 50 },
    COMMENT: { min: 1, max: 2000 },
    // Age validation (for future user profiles)
    AGE: { min: 18, max: 120 },
    // Numeric ranges for various fields
    PRIORITY_LEVEL: { min: 1, max: 5 },
    RATING: { min: 1, max: 10 },
    PERCENTAGE: { min: 0, max: 100 },
    // File size limits (in bytes)
    FILE_SIZE_SMALL: { max: 1048576 }, // 1MB
    FILE_SIZE_MEDIUM: { max: 10485760 }, // 10MB
    FILE_SIZE_LARGE: { max: 104857600 }, // 100MB
    // Request limits
    REQUEST_BODY_SIZE: { max: 10485760 }, // 10MB
    REQUEST_PARAMS: { max: 100 },
    ARRAY_LENGTH: { max: 1000 }
};

// Strict validation helper functions
const strictValidation = {
    // Reject any input containing dangerous patterns
    rejectDangerousInput: (value) => {
        if (!value || typeof value !== 'string') return true;
        
        // Check for dangerous content
        if (VALIDATION_PATTERNS.DANGEROUS_CONTENT.test(value)) {
            throw new Error('Input contains potentially dangerous content and has been rejected');
        }
        
        // Check for SQL injection
        if (VALIDATION_PATTERNS.SQL_INJECTION.test(value)) {
            throw new Error('Input contains suspicious SQL patterns and has been rejected');
        }
        
        // Check for NoSQL injection
        if (VALIDATION_PATTERNS.NOSQL_INJECTION.test(value)) {
            throw new Error('Input contains suspicious NoSQL patterns and has been rejected');
        }
        
        // Check for XSS patterns
        if (VALIDATION_PATTERNS.XSS_PATTERNS.test(value)) {
            throw new Error('Input contains potential XSS patterns and has been rejected');
        }
        
        // Check for command injection
        if (VALIDATION_PATTERNS.COMMAND_INJECTION.test(value)) {
            throw new Error('Input contains potential command injection patterns and has been rejected');
        }
        
        // Check for path traversal
        if (VALIDATION_PATTERNS.PATH_TRAVERSAL.test(value)) {
            throw new Error('Input contains path traversal patterns and has been rejected');
        }
        
        // Check for LDAP injection (disabled - not using LDAP authentication)
        // if (VALIDATION_PATTERNS.LDAP_INJECTION.test(value)) {
        //     throw new Error('Input contains potential LDAP injection patterns and has been rejected');
        // }
        
        // Check for XXE patterns
        if (VALIDATION_PATTERNS.XXE_PATTERNS.test(value)) {
            throw new Error('Input contains potential XXE patterns and has been rejected');
        }
        
        // Check for template injection
        if (VALIDATION_PATTERNS.TEMPLATE_INJECTION.test(value)) {
            throw new Error('Input contains potential template injection patterns and has been rejected');
        }
        
        return true;
    },
    
    // Validate string length within strict bounds
    validateStringLength: (value, min, max, fieldName) => {
        if (!value || typeof value !== 'string') {
            if (min > 0) {
                throw new Error(`${fieldName} is required`);
            }
            return true;
        }
        
        const trimmed = value.trim();
        if (trimmed.length < min) {
            throw new Error(`${fieldName} must be at least ${min} characters long`);
        }
        if (trimmed.length > max) {
            throw new Error(`${fieldName} must not exceed ${max} characters`);
        }
        
        return true;
    },
    
    // Validate integer within range
    validateIntegerRange: (value, min, max, fieldName) => {
        const num = parseInt(value, 10);
        if (isNaN(num)) {
            throw new Error(`${fieldName} must be a valid number`);
        }
        if (num < min || num > max) {
            throw new Error(`${fieldName} must be between ${min} and ${max}`);
        }
        return true;
    },
    
    // Validate decimal/float within range
    validateFloatRange: (value, min, max, fieldName, decimalPlaces = 2) => {
        const num = parseFloat(value);
        if (isNaN(num)) {
            throw new Error(`${fieldName} must be a valid number`);
        }
        if (num < min || num > max) {
            throw new Error(`${fieldName} must be between ${min} and ${max}`);
        }
        // Check decimal places
        const decimals = (value.toString().split('.')[1] || '').length;
        if (decimals > decimalPlaces) {
            throw new Error(`${fieldName} must have at most ${decimalPlaces} decimal places`);
        }
        return true;
    },
    
    // Validate date is valid and within range
    validateDateRange: (value, minDate, maxDate, fieldName) => {
        if (!VALIDATION_PATTERNS.DATE.test(value)) {
            throw new Error(`${fieldName} must be in YYYY-MM-DD format`);
        }
        
        const date = new Date(value);
        if (isNaN(date.getTime())) {
            throw new Error(`${fieldName} must be a valid date`);
        }
        
        if (minDate && date < new Date(minDate)) {
            throw new Error(`${fieldName} must be after ${minDate}`);
        }
        
        if (maxDate && date > new Date(maxDate)) {
            throw new Error(`${fieldName} must be before ${maxDate}`);
        }
        
        return true;
    },
    
    // Validate array length and content
    validateArray: (value, minLength, maxLength, fieldName, itemValidator = null) => {
        if (!Array.isArray(value)) {
            throw new Error(`${fieldName} must be an array`);
        }
        
        if (value.length < minLength) {
            throw new Error(`${fieldName} must contain at least ${minLength} items`);
        }
        
        if (value.length > maxLength) {
            throw new Error(`${fieldName} must contain at most ${maxLength} items`);
        }
        
        // Validate each item if validator provided
        if (itemValidator) {
            value.forEach((item, index) => {
                try {
                    itemValidator(item);
                } catch (error) {
                    throw new Error(`${fieldName}[${index}]: ${error.message}`);
                }
            });
        }
        
        return true;
    },
    
    // Validate boolean
    validateBoolean: (value, fieldName) => {
        if (typeof value !== 'boolean' && value !== 'true' && value !== 'false' && value !== true && value !== false) {
            throw new Error(`${fieldName} must be a boolean value`);
        }
        return true;
    },
    
    // Validate JSON string
    validateJSON: (value, fieldName) => {
        if (typeof value !== 'string') {
            throw new Error(`${fieldName} must be a valid JSON string`);
        }
        
        try {
            JSON.parse(value);
        } catch (error) {
            throw new Error(`${fieldName} must be valid JSON: ${error.message}`);
        }
        
        return true;
    },
    
    // Validate file size
    validateFileSize: (size, maxSize, fieldName) => {
        if (typeof size !== 'number' || size < 0) {
            throw new Error(`${fieldName} size must be a positive number`);
        }
        
        if (size > maxSize) {
            const maxSizeMB = Math.round(maxSize / 1024 / 1024 * 100) / 100;
            throw new Error(`${fieldName} size must not exceed ${maxSizeMB}MB`);
        }
        
        return true;
    }
};

// Enhanced validation rules with strict validation
const validationRules = {
    username: body('username')
        .trim()
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .custom((value) => strictValidation.validateStringLength(value, VALIDATION_LIMITS.USERNAME.min, VALIDATION_LIMITS.USERNAME.max, 'Username'))
        .matches(VALIDATION_PATTERNS.USERNAME)
        .withMessage('Username must be 3-20 characters long and contain only letters, numbers, and underscores'),

    password: body('password')
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .custom((value) => strictValidation.validateStringLength(value, VALIDATION_LIMITS.PASSWORD.min, VALIDATION_LIMITS.PASSWORD.max, 'Password'))
        .matches(VALIDATION_PATTERNS.PASSWORD)
        .withMessage('Password must be 6-128 characters and contain at least one letter and one number')
        .custom((value) => {
            // Additional password strength validation
            const commonPasswords = ['password', '12345678', 'qwerty123', 'admin123', 'password123'];
            if (commonPasswords.some(common => value.toLowerCase().includes(common.toLowerCase()))) {
                throw new Error('Password contains common patterns and has been rejected');
            }
            return true;
        }),

    confirmPassword: body('confirmPassword')
        .custom((value, { req }) => {
            if (!value) {
                throw new Error('Password confirmation is required');
            }
            if (value !== req.body.password) {
                throw new Error('Password confirmation does not match the password');
            }
            return true;
        }),

    currentPassword: body('currentPassword')
        .notEmpty()
        .withMessage('Current password is required')
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .isLength({ min: 1, max: 128 })
        .withMessage('Current password must not exceed 128 characters'),

    taskTitle: body('title')
        .trim()
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .custom((value) => strictValidation.validateStringLength(value, VALIDATION_LIMITS.TASK_TITLE.min, VALIDATION_LIMITS.TASK_TITLE.max, 'Task title'))
        .matches(/^[a-zA-Z0-9\s\-_.,:;!?()[\]{}'"@#$%^&*+=<>|\\\/]*$/)
        .withMessage('Task title contains invalid characters'),

    taskDescription: body('description')
        .trim()
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .custom((value) => strictValidation.validateStringLength(value, VALIDATION_LIMITS.TASK_DESCRIPTION.min, VALIDATION_LIMITS.TASK_DESCRIPTION.max, 'Task description'))
        .matches(/^[a-zA-Z0-9\s\-_.,:;!?()[\]{}'"@#$%^&*+=<>|\\\/\n\r]*$/)
        .withMessage('Task description contains invalid characters'),

    assignedTo: body('assignedTo')
        .custom((value) => strictValidation.validateIntegerRange(value, VALIDATION_LIMITS.USER_ID.min, VALIDATION_LIMITS.USER_ID.max, 'Assigned user ID'))
        .isInt({ min: VALIDATION_LIMITS.USER_ID.min, max: VALIDATION_LIMITS.USER_ID.max })
        .withMessage('Please select a valid employee'),

    priority: body('priority')
        .trim()
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .matches(VALIDATION_PATTERNS.TASK_PRIORITY)
        .withMessage('Priority must be exactly one of: Low, Medium, High'),

    // New validation rules for missing endpoints
    taskId: body('taskId')
        .custom((value) => strictValidation.validateIntegerRange(value, VALIDATION_LIMITS.TASK_ID.min, VALIDATION_LIMITS.TASK_ID.max, 'Task ID'))
        .isInt({ min: VALIDATION_LIMITS.TASK_ID.min, max: VALIDATION_LIMITS.TASK_ID.max })
        .withMessage('Invalid task ID'),

    taskStatus: body('status')
        .trim()
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .matches(VALIDATION_PATTERNS.TASK_STATUS)
        .withMessage('Status must be exactly one of: Pending, Completed'),

    newAssignedTo: body('newAssignedTo')
        .custom((value) => strictValidation.validateIntegerRange(value, VALIDATION_LIMITS.USER_ID.min, VALIDATION_LIMITS.USER_ID.max, 'New assigned user ID'))
        .isInt({ min: VALIDATION_LIMITS.USER_ID.min, max: VALIDATION_LIMITS.USER_ID.max })
        .withMessage('Please select a valid employee for reassignment'),

    managerId: body('managerId')
        .custom((value) => strictValidation.validateIntegerRange(value, VALIDATION_LIMITS.USER_ID.min, VALIDATION_LIMITS.USER_ID.max, 'Manager ID'))
        .isInt({ min: VALIDATION_LIMITS.USER_ID.min, max: VALIDATION_LIMITS.USER_ID.max })
        .withMessage('Invalid manager ID'),
    
    // Email validation (for future features)
    email: body('email')
        .trim()
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .custom((value) => strictValidation.validateStringLength(value, VALIDATION_LIMITS.EMAIL.min, VALIDATION_LIMITS.EMAIL.max, 'Email'))
        .matches(VALIDATION_PATTERNS.EMAIL)
        .withMessage('Please provide a valid email address'),
    
    // URL validation (for future features)
    url: body('url')
        .trim()
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .custom((value) => strictValidation.validateStringLength(value, VALIDATION_LIMITS.URL.min, VALIDATION_LIMITS.URL.max, 'URL'))
        .matches(VALIDATION_PATTERNS.URL)
        .withMessage('Please provide a valid HTTP or HTTPS URL'),
    
    // Phone validation (for future features)
    phone: body('phone')
        .trim()
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .custom((value) => strictValidation.validateStringLength(value, VALIDATION_LIMITS.PHONE.min, VALIDATION_LIMITS.PHONE.max, 'Phone number'))
        .matches(VALIDATION_PATTERNS.PHONE)
        .withMessage('Please provide a valid phone number'),
    
    // Date validation (for future features like task due dates)
    date: body('date')
        .trim()
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .matches(VALIDATION_PATTERNS.DATE)
        .withMessage('Date must be in YYYY-MM-DD format')
        .custom((value) => {
            const date = new Date(value);
            if (isNaN(date.getTime())) {
                throw new Error('Please provide a valid date');
            }
            // Ensure date is not in the past (for due dates)
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            if (date < today) {
                throw new Error('Date cannot be in the past');
            }
            return true;
        }),
    
    // Time validation (for future features)
    time: body('time')
        .trim()
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .matches(VALIDATION_PATTERNS.TIME)
        .withMessage('Time must be in HH:MM format'),
    
    // Numeric validation with decimal support (for future features like progress percentage)
    percentage: body('percentage')
        .custom((value) => strictValidation.validateFloatRange(value, VALIDATION_LIMITS.PERCENTAGE.min, VALIDATION_LIMITS.PERCENTAGE.max, 'Percentage', 1))
        .isFloat({ min: VALIDATION_LIMITS.PERCENTAGE.min, max: VALIDATION_LIMITS.PERCENTAGE.max })
        .withMessage('Percentage must be between 0 and 100'),
    
    // Generic text validation for comments/notes
    comment: body('comment')
        .trim()
        .custom((value) => strictValidation.rejectDangerousInput(value))
        .custom((value) => strictValidation.validateStringLength(value, VALIDATION_LIMITS.COMMENT.min, VALIDATION_LIMITS.COMMENT.max, 'Comment'))
        .matches(/^[a-zA-Z0-9\s\-_.,:;!?()[\]{}'"@#$%^&*+=<>|\\\/\n\r]*$/)
        .withMessage('Comment contains invalid characters'),
    
    // Array validation (for future multi-select features)
    tags: body('tags')
        .optional()
        .custom((value) => {
            if (value && !Array.isArray(value)) {
                throw new Error('Tags must be an array');
            }
            if (value) {
                strictValidation.validateArray(value, 0, 10, 'Tags', (tag) => {
                    if (typeof tag !== 'string' || tag.length > 50) {
                        throw new Error('Each tag must be a string with maximum 50 characters');
                    }
                    strictValidation.rejectDangerousInput(tag);
                });
            }
            return true;
        }),
    
    // JSON validation (for future metadata fields)
    metadata: body('metadata')
        .optional()
        .custom((value) => {
            if (value) {
                strictValidation.validateJSON(value, 'Metadata');
                // Additional size check for JSON
                if (value.length > 10000) {
                    throw new Error('Metadata JSON must not exceed 10KB');
                }
            }
            return true;
        })
};

// Enhanced validation rule sets for different forms
const validationSets = {
    registration: [
        validationRules.username,
        validationRules.password,
        validationRules.confirmPassword
    ],

    login: [
        body('username')
            .trim()
            .notEmpty()
            .withMessage('Username is required')
            .custom((value) => strictValidation.rejectDangerousInput(value))
            .isLength({ min: 1, max: 30 })
            .withMessage('Username must be between 1 and 30 characters'),
        body('password')
            .notEmpty()
            .withMessage('Password is required')
            .custom((value) => strictValidation.rejectDangerousInput(value))
            .isLength({ min: 1, max: 128 })
            .withMessage('Password must not exceed 128 characters')
    ],

    changePassword: [
        validationRules.currentPassword,
        validationRules.password,
        validationRules.confirmPassword
    ],

    createTask: [
        validationRules.taskTitle,
        validationRules.taskDescription,
        validationRules.assignedTo,
        validationRules.priority
    ],

    createManager: [
        validationRules.username,
        validationRules.password
    ],

    // New validation sets for previously unvalidated endpoints
    updateTaskStatus: [
        validationRules.taskId,
        validationRules.taskStatus
    ],

    reassignTask: [
        validationRules.taskId,
        validationRules.newAssignedTo
    ],

    deleteTask: [
        validationRules.taskId
    ],

    deleteManager: [
        validationRules.managerId
    ],
    
    // Additional validation sets for future features
    userProfile: [
        validationRules.email,
        validationRules.phone
    ],
    
    taskWithDueDate: [
        validationRules.taskTitle,
        validationRules.taskDescription,
        validationRules.assignedTo,
        validationRules.priority,
        validationRules.date
    ],
    
    commentValidation: [
        validationRules.comment
    ],
    
    metadataValidation: [
        validationRules.metadata
    ],
    
    // Query parameter validation
    searchQuery: [
        query('q')
            .optional()
            .trim()
            .custom((value) => strictValidation.rejectDangerousInput(value))
            .isLength({ min: 1, max: 100 })
            .withMessage('Search query must be between 1 and 100 characters'),
        query('page')
            .optional()
            .isInt({ min: 1, max: 1000 })
            .withMessage('Page must be a positive integer'),
        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 })
            .withMessage('Limit must be between 1 and 100')
    ],
    
    // Parameter validation (for route parameters)
    idParam: [
        param('id')
            .isInt({ min: 1, max: VALIDATION_LIMITS.USER_ID.max })
            .withMessage('Invalid ID parameter')
    ]
};

// Enhanced middleware to handle validation errors with strict rejection
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // Categorize errors for better security monitoring
        const errorCategories = {
            security: [],
            validation: [],
            business: []
        };
        
        errors.array().forEach(error => {
            const message = error.msg.toLowerCase();
            if (message.includes('dangerous') || message.includes('suspicious') || 
                message.includes('injection') || message.includes('xss') ||
                message.includes('rejected')) {
                errorCategories.security.push(error);
            } else if (message.includes('business') || message.includes('not allowed') ||
                      message.includes('permission')) {
                errorCategories.business.push(error);
            } else {
                errorCategories.validation.push(error);
            }
        });
        
        // Enhanced security logging
        const { securityLogger } = require('./logger');
        securityLogger.warn('Validation failed', {
            url: req.url,
            method: req.method,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            userId: req.session?.user?.id || 'anonymous',
            username: req.session?.user?.username || 'anonymous',
            errorCategories: {
                security: errorCategories.security.length,
                validation: errorCategories.validation.length,
                business: errorCategories.business.length
            },
            securityErrors: errorCategories.security.map(err => err.msg),
            timestamp: new Date().toISOString(),
            requestBody: req.method === 'POST' ? Object.keys(req.body || {}) : undefined
        });
        
        // If security-related errors, log with higher severity
        if (errorCategories.security.length > 0) {
            securityLogger.error('SECURITY ALERT - Potentially malicious input detected', {
                url: req.url,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                username: req.session?.user?.username || 'anonymous',
                securityErrors: errorCategories.security.map(err => err.msg),
                timestamp: new Date().toISOString()
            });
        }
        
        // Store errors in session to display after redirect
        req.session.validationErrors = errors.array();
        req.session.formData = req.body;
        
        // Determine redirect location based on the original URL
        const referer = req.get('Referer') || '/';
        return res.redirect(referer);
    }
    next();
};

// Comprehensive request validation middleware
const validateRequest = (options = {}) => {
    return (req, res, next) => {
        const {
            maxBodySize = VALIDATION_LIMITS.REQUEST_BODY_SIZE.max,
            maxParams = VALIDATION_LIMITS.REQUEST_PARAMS.max,
            allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
            requireHttps = false,
            checkContentType = true
        } = options;
        
        try {
            // Check HTTP method
            if (!allowedMethods.includes(req.method)) {
                throw new Error(`HTTP method ${req.method} not allowed`);
            }
            
            // Check HTTPS requirement
            if (requireHttps && !req.secure && req.get('X-Forwarded-Proto') !== 'https') {
                throw new Error('HTTPS required for this endpoint');
            }
            
            // Check body size
            const contentLength = parseInt(req.get('Content-Length') || '0', 10);
            if (contentLength > maxBodySize) {
                throw new Error(`Request body too large (${contentLength} > ${maxBodySize})`);
            }
            
            // Check number of parameters
            const paramCount = Object.keys(req.body || {}).length + 
                              Object.keys(req.query || {}).length + 
                              Object.keys(req.params || {}).length;
            if (paramCount > maxParams) {
                throw new Error(`Too many parameters (${paramCount} > ${maxParams})`);
            }
            
            // Check Content-Type for POST/PUT requests
            if (checkContentType && ['POST', 'PUT', 'PATCH'].includes(req.method)) {
                const contentType = req.get('Content-Type') || '';
                if (!contentType.includes('application/x-www-form-urlencoded') && 
                    !contentType.includes('application/json') &&
                    !contentType.includes('multipart/form-data')) {
                    throw new Error('Invalid Content-Type');
                }
            }
            
            // Check for suspicious headers
            const suspiciousHeaders = ['x-forwarded-host', 'x-real-ip'];
            for (const header of suspiciousHeaders) {
                const value = req.get(header);
                if (value && strictValidation.rejectDangerousInput) {
                    try {
                        strictValidation.rejectDangerousInput(value);
                    } catch (error) {
                        throw new Error(`Suspicious header value in ${header}`);
                    }
                }
            }
            
            next();
        } catch (error) {
            const { securityLogger } = require('./logger');
            securityLogger.warn('Request validation failed', {
                url: req.url,
                method: req.method,
                ip: req.ip,
                error: error.message,
                timestamp: new Date().toISOString()
            });
            
            return res.status(400).json({
                error: 'Bad Request',
                message: 'Invalid request parameters'
            });
        }
    };
};

// Middleware to inject validation errors and form data into templates
const injectValidationData = (req, res, next) => {
    res.locals.validationErrors = req.session.validationErrors || [];
    res.locals.formData = req.session.formData || {};
    
    // Clear session data after using it
    delete req.session.validationErrors;
    delete req.session.formData;
    
    next();
};

// Enhanced sanitization functions with strict rejection approach
const sanitize = {
    // Reject input containing potentially dangerous characters - NO auto-correction
    rejectDangerousChars: (input) => {
        if (!input || typeof input !== 'string') return '';
        
        if (VALIDATION_PATTERNS.DANGEROUS_CONTENT.test(input)) {
            throw new Error('Input contains potentially dangerous content and has been rejected');
        }
        
        if (VALIDATION_PATTERNS.SQL_INJECTION.test(input)) {
            throw new Error('Input contains suspicious patterns and has been rejected');
        }
        
        return input.trim();
    },

    // Validate and clean text input - strict rejection, no auto-correction
    cleanText: (input, maxLength = 500) => {
        if (!input || typeof input !== 'string') {
            return '';
        }
        
        const trimmed = input.trim();
        
        if (trimmed.length > maxLength) {
            throw new Error(`Input exceeds maximum length of ${maxLength} characters`);
        }
        
        return sanitize.rejectDangerousChars(trimmed);
    },

    // Validate integer with strict type checking
    validateInteger: (input, min = 1, max = 2147483647) => {
        if (input === null || input === undefined || input === '') {
            throw new Error('Numeric value is required');
        }
        
        const num = parseInt(input, 10);
        if (isNaN(num) || num.toString() !== input.toString()) {
            throw new Error('Invalid numeric value - must be a valid integer');
        }
        
        if (num < min || num > max) {
            throw new Error(`Numeric value must be between ${min} and ${max}`);
        }
        
        return num;
    },

    // Validate enum values with strict matching
    validateEnum: (input, allowedValues, fieldName) => {
        if (!input || typeof input !== 'string') {
            throw new Error(`${fieldName} is required`);
        }
        
        const trimmed = input.trim();
        if (!allowedValues.includes(trimmed)) {
            throw new Error(`${fieldName} must be one of: ${allowedValues.join(', ')}`);
        }
        
        return trimmed;
    },
    
    // Validate and clean email
    cleanEmail: (input) => {
        if (!input || typeof input !== 'string') {
            throw new Error('Email is required');
        }
        
        const trimmed = input.trim().toLowerCase();
        
        if (!VALIDATION_PATTERNS.EMAIL.test(trimmed)) {
            throw new Error('Invalid email format');
        }
        
        strictValidation.rejectDangerousInput(trimmed);
        return trimmed;
    },
    
    // Validate and clean URL
    cleanURL: (input) => {
        if (!input || typeof input !== 'string') {
            throw new Error('URL is required');
        }
        
        const trimmed = input.trim();
        
        if (!VALIDATION_PATTERNS.URL.test(trimmed)) {
            throw new Error('Invalid URL format - must be HTTP or HTTPS');
        }
        
        strictValidation.rejectDangerousInput(trimmed);
        return trimmed;
    },
    
    // Validate and clean phone number
    cleanPhone: (input) => {
        if (!input || typeof input !== 'string') {
            throw new Error('Phone number is required');
        }
        
        // Remove all non-digit characters except +
        const cleaned = input.replace(/[^\d+]/g, '');
        
        if (!VALIDATION_PATTERNS.PHONE.test(cleaned)) {
            throw new Error('Invalid phone number format');
        }
        
        return cleaned;
    },
    
    // Validate date
    validateDate: (input, allowPast = false) => {
        if (!input || typeof input !== 'string') {
            throw new Error('Date is required');
        }
        
        const trimmed = input.trim();
        
        if (!VALIDATION_PATTERNS.DATE.test(trimmed)) {
            throw new Error('Date must be in YYYY-MM-DD format');
        }
        
        const date = new Date(trimmed);
        if (isNaN(date.getTime())) {
            throw new Error('Invalid date');
        }
        
        if (!allowPast) {
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            if (date < today) {
                throw new Error('Date cannot be in the past');
            }
        }
        
        return trimmed;
    },
    
    // Validate time
    validateTime: (input) => {
        if (!input || typeof input !== 'string') {
            throw new Error('Time is required');
        }
        
        const trimmed = input.trim();
        
        if (!VALIDATION_PATTERNS.TIME.test(trimmed)) {
            throw new Error('Time must be in HH:MM format');
        }
        
        return trimmed;
    },
    
    // Validate and clean array
    cleanArray: (input, maxLength = 100, itemValidator = null) => {
        if (!Array.isArray(input)) {
            throw new Error('Value must be an array');
        }
        
        if (input.length > maxLength) {
            throw new Error(`Array must not contain more than ${maxLength} items`);
        }
        
        if (itemValidator) {
            return input.map((item, index) => {
                try {
                    return itemValidator(item);
                } catch (error) {
                    throw new Error(`Item ${index}: ${error.message}`);
                }
            });
        }
        
        return input;
    },
    
    // Validate and parse JSON
    validateJSON: (input, maxSize = 10000) => {
        if (!input || typeof input !== 'string') {
            throw new Error('JSON is required');
        }
        
        if (input.length > maxSize) {
            throw new Error(`JSON must not exceed ${maxSize} characters`);
        }
        
        try {
            const parsed = JSON.parse(input);
            return parsed;
        } catch (error) {
            throw new Error(`Invalid JSON: ${error.message}`);
        }
    },
    
    // Validate file upload metadata
    validateFileUpload: (file, allowedTypes = [], maxSize = VALIDATION_LIMITS.FILE_SIZE_MEDIUM.max) => {
        if (!file) {
            throw new Error('File is required');
        }
        
        if (file.size > maxSize) {
            const maxSizeMB = Math.round(maxSize / 1024 / 1024 * 100) / 100;
            throw new Error(`File size must not exceed ${maxSizeMB}MB`);
        }
        
        if (allowedTypes.length > 0 && !allowedTypes.includes(file.mimetype)) {
            throw new Error(`File type must be one of: ${allowedTypes.join(', ')}`);
        }
        
        // Check for suspicious file names
        if (VALIDATION_PATTERNS.PATH_TRAVERSAL.test(file.originalname)) {
            throw new Error('Invalid file name');
        }
        
        return {
            originalName: sanitize.cleanText(file.originalname, 255),
            mimeType: file.mimetype,
            size: file.size
        };
    }
};

// Additional validation utilities for business logic
const businessValidation = {
    // Validate task ownership before operations
    validateTaskOwnership: async (taskId, userId, operation) => {
        if (!taskId || !userId) {
            throw new Error('Task ID and User ID are required');
        }
        
        // This will be used in routes to check ownership
        // Implementation depends on the specific operation
        return true;
    },

    // Validate user role for specific operations
    validateUserRole: (userRole, allowedRoles, operation) => {
        if (!userRole || !allowedRoles.includes(userRole)) {
            throw new Error(`Operation '${operation}' not allowed for role '${userRole}'`);
        }
        return true;
    },
    
    // Validate password strength beyond regex
    validatePasswordStrength: (password, username = '') => {
        if (!password || typeof password !== 'string') {
            throw new Error('Password is required');
        }
        
        // Check minimum requirements (relaxed)
        if (password.length < 6) {
            throw new Error('Password must be at least 6 characters long');
        }
        
        if (password.length > 128) {
            throw new Error('Password must not exceed 128 characters');
        }
        
        // Check for basic character requirements (relaxed)
        if (!/[a-zA-Z]/.test(password)) {
            throw new Error('Password must contain at least one letter');
        }
        
        if (!/\d/.test(password)) {
            throw new Error('Password must contain at least one number');
        }
        
        // Check for common weak patterns (keep this for security)
        const commonPasswords = [
            'password', '12345678', 'qwerty123', 'admin123', 'password123',
            'letmein', 'welcome', 'monkey', '1234567890', 'password1',
            'abc123', 'qwerty', '123456789', 'welcome123', 'admin',
            'root', 'toor', 'pass', 'test', 'guest', 'user'
        ];
        
        const lowerPassword = password.toLowerCase();
        const lowerUsername = username.toLowerCase();
        
        if (commonPasswords.some(common => lowerPassword.includes(common))) {
            throw new Error('Password contains common patterns and has been rejected');
        }
        
        // Check if password contains username
        if (username && lowerPassword.includes(lowerUsername)) {
            throw new Error('Password cannot contain the username');
        }
        
        // Check for keyboard patterns
        const keyboardPatterns = [
            'qwerty', 'asdf', 'zxcv', '1234', 'abcd', '!@#$'
        ];
        
        if (keyboardPatterns.some(pattern => lowerPassword.includes(pattern))) {
            throw new Error('Password contains common keyboard patterns');
        }
        
        // Check for repeated characters
        if (/(.)\1{3,}/.test(password)) {
            throw new Error('Password cannot contain more than 3 consecutive identical characters');
        }
        
        return true;
    },
    
    // Validate email uniqueness (placeholder for future implementation)
    validateEmailUniqueness: async (email, excludeUserId = null) => {
        // This would check database for email uniqueness
        // Implementation would depend on database structure
        return true;
    },
    
    // Validate username uniqueness (placeholder for future implementation)
    validateUsernameUniqueness: async (username, excludeUserId = null) => {
        // This would check database for username uniqueness
        // Implementation would depend on database structure
        return true;
    },
    
    // Validate task assignment business rules
    validateTaskAssignment: (assignerRole, assigneeRole, taskData) => {
        // Only Project Managers can assign tasks
        if (assignerRole !== 'Project Manager') {
            throw new Error('Only Project Managers can assign tasks');
        }
        
        // Can only assign to Employees
        if (assigneeRole !== 'Employee') {
            throw new Error('Tasks can only be assigned to Employees');
        }
        
        // Validate task priority
        const validPriorities = ['Low', 'Medium', 'High'];
        if (!validPriorities.includes(taskData.priority)) {
            throw new Error('Invalid task priority');
        }
        
        return true;
    },
    
    // Validate rate limiting parameters
    validateRateLimit: (req, maxAttempts, windowMs, operation) => {
        const key = `${req.ip}:${operation}`;
        // This would integrate with rate limiting store
        // Implementation would depend on rate limiting implementation
        return true;
    },
    
    // Validate file upload business rules
    validateFileUploadRules: (userRole, fileType, fileSize) => {
        // Define role-based file upload permissions
        const permissions = {
            'Administrator': {
                allowedTypes: ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain', 'application/json'],
                maxSize: VALIDATION_LIMITS.FILE_SIZE_LARGE.max
            },
            'Project Manager': {
                allowedTypes: ['image/jpeg', 'image/png', 'application/pdf', 'text/plain'],
                maxSize: VALIDATION_LIMITS.FILE_SIZE_MEDIUM.max
            },
            'Employee': {
                allowedTypes: ['image/jpeg', 'image/png', 'text/plain'],
                maxSize: VALIDATION_LIMITS.FILE_SIZE_SMALL.max
            }
        };
        
        const userPermissions = permissions[userRole];
        if (!userPermissions) {
            throw new Error('Invalid user role for file upload');
        }
        
        if (!userPermissions.allowedTypes.includes(fileType)) {
            throw new Error(`File type ${fileType} not allowed for ${userRole}`);
        }
        
        if (fileSize > userPermissions.maxSize) {
            const maxSizeMB = Math.round(userPermissions.maxSize / 1024 / 1024 * 100) / 100;
            throw new Error(`File size exceeds ${maxSizeMB}MB limit for ${userRole}`);
        }
        
        return true;
    }
};

module.exports = {
    validationRules,
    validationSets,
    handleValidationErrors,
    validateRequest,
    injectValidationData,
    sanitize,
    businessValidation,
    strictValidation,
    VALIDATION_PATTERNS,
    VALIDATION_LIMITS
};
