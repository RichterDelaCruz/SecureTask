const { body, validationResult } = require('express-validator');

// Common validation rules
const validationRules = {
    username: body('username')
        .isLength({ min: 3, max: 30 })
        .withMessage('Username must be between 3 and 30 characters')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Username can only contain letters, numbers, and underscores'),

    password: body('password')
        .isLength({ min: 8, max: 128 })
        .withMessage('Password must be between 8 and 128 characters')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),

    confirmPassword: body('confirmPassword')
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Passwords do not match');
            }
            return true;
        }),

    currentPassword: body('currentPassword')
        .notEmpty()
        .withMessage('Current password is required'),

    taskTitle: body('title')
        .isLength({ min: 1, max: 100 })
        .withMessage('Task title must be between 1 and 100 characters')
        .trim(),

    taskDescription: body('description')
        .isLength({ max: 500 })
        .withMessage('Task description cannot exceed 500 characters')
        .trim(),

    assignedTo: body('assignedTo')
        .isInt({ min: 1 })
        .withMessage('Please select a valid employee')
};

// Validation rule sets for different forms
const validationSets = {
    registration: [
        validationRules.username,
        validationRules.password,
        validationRules.confirmPassword
    ],

    login: [
        body('username').notEmpty().withMessage('Username is required'),
        body('password').notEmpty().withMessage('Password is required')
    ],

    changePassword: [
        validationRules.currentPassword,
        validationRules.password,
        validationRules.confirmPassword
    ],

    createTask: [
        validationRules.taskTitle,
        validationRules.taskDescription,
        validationRules.assignedTo
    ],

    createManager: [
        validationRules.username,
        validationRules.password
    ]
};

// Middleware to handle validation errors
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // Store errors in session to display after redirect
        req.session.validationErrors = errors.array();
        req.session.formData = req.body;
        
        // Determine redirect location based on the original URL
        const referer = req.get('Referer') || '/';
        return res.redirect(referer);
    }
    next();
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

// Sanitization functions (rejection-based approach)
const sanitize = {
    // Reject input containing potentially dangerous characters
    rejectDangerousChars: (input) => {
        const dangerousChars = /<script|javascript:|data:|vbscript:|onload|onerror|onclick/i;
        if (dangerousChars.test(input)) {
            throw new Error('Input contains potentially dangerous content');
        }
        return input.trim();
    },

    // Validate and clean text input
    cleanText: (input, maxLength = 500) => {
        if (!input || typeof input !== 'string') {
            return '';
        }
        
        input = input.trim();
        
        if (input.length > maxLength) {
            throw new Error(`Input exceeds maximum length of ${maxLength} characters`);
        }
        
        return sanitize.rejectDangerousChars(input);
    }
};

module.exports = {
    validationRules,
    validationSets,
    handleValidationErrors,
    injectValidationData,
    sanitize
};
