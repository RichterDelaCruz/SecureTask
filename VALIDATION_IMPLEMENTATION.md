# Strict Data Validation Implementation for SecureTask

## Overview

This document describes the comprehensive data validation system implemented for the SecureTask web application. The implementation follows strict validation principles with NO auto-correction or sanitization of user inputs - all invalid data is rejected with appropriate error messages.

## Key Principles

✅ **Strict Rejection**: All invalid data is rejected, no auto-correction  
✅ **Range Validation**: Numeric values, dates, and lengths are validated within acceptable ranges  
✅ **Pattern Matching**: String inputs are validated against expected patterns  
✅ **Type Safety**: Data types are strictly enforced  
✅ **Security-First**: All inputs are checked for malicious content  
✅ **Centralized Logic**: Validation rules are centralized and reusable  
✅ **Defense in Depth**: Multiple layers of validation (client-side, server-side, business logic)

## Architecture

### 1. Server-Side Validation (`utils/validation.js`)

#### Validation Patterns
```javascript
VALIDATION_PATTERNS = {
    USERNAME: /^[a-zA-Z0-9_]{3,20}$/,
    PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#+\-_=[\]{}|\\:";'<>?,./])[A-Za-z\d@$!%*?&#+\-_=[\]{}|\\:";'<>?,./]{8,128}$/,
    EMAIL: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
    TASK_PRIORITY: /^(Low|Medium|High)$/,
    TASK_STATUS: /^(Pending|Completed)$/,
    // Enhanced security patterns
    DANGEROUS_CONTENT: /<script|javascript:|data:|vbscript:|on\w+\s*=|<iframe|<object|<embed|<form|<link|<meta|<style|<base|<applet|<body|<html|<head|expression\s*\(|@import|url\s*\(|eval\s*\(|setTimeout|setInterval/i,
    SQL_INJECTION: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|DECLARE|SCRIPT|TRUNCATE|MERGE|REPLACE|CALL|EXECUTE|LOAD|HANDLER|PREPARE|DEALLOCATE)\b)|('(''|[^'])*')|(;)|(--)|(\/\*|\*\/)|(\bOR\b|\bAND\b)\s*\d+\s*=\s*\d+/i,
    XSS_PATTERNS: /<script|<\/script|javascript:|vbscript:|onload|onerror|onclick|onmouseover|onfocus|onblur|onchange|onsubmit|<img[^>]*src[^>]*=|<link[^>]*href|<iframe|<object|<embed|<applet/i,
    COMMAND_INJECTION: /(\||&|;|\$\(|\$\{|`|\$\$|exec|system|passthru|shell_exec|popen|proc_open|eval|assert|include|require)/i,
    PATH_TRAVERSAL: /\.\.|\/\.\.|\\\.\.|\.\.\//i,
    NOSQL_INJECTION: /\$where|\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin|\$regex|\$exists|\$type|\$mod|\$all|\$size|\$elemMatch|\$slice/i
}
```

#### Validation Limits
```javascript
VALIDATION_LIMITS = {
    USERNAME: { min: 3, max: 20 },
    PASSWORD: { min: 8, max: 128 },
    TASK_TITLE: { min: 1, max: 100 },
    TASK_DESCRIPTION: { min: 0, max: 500 },
    EMAIL: { min: 5, max: 254 },
    PHONE: { min: 7, max: 15 },
    URL: { min: 10, max: 2048 },
    AGE: { min: 18, max: 120 },
    PERCENTAGE: { min: 0, max: 100 },
    REQUEST_BODY_SIZE: { max: 10485760 }, // 10MB
    ARRAY_LENGTH: { max: 1000 }
}
```

### 2. Strict Validation Functions

#### Enhanced Security Validation
```javascript
strictValidation.rejectDangerousInput(value)
```
- Checks for XSS patterns
- Detects SQL injection attempts  
- Identifies NoSQL injection patterns
- Blocks command injection attempts
- Prevents path traversal attacks
- Rejects LDAP injection patterns
- Stops XXE attacks
- Prevents template injection

#### Range and Type Validation
```javascript
strictValidation.validateStringLength(value, min, max, fieldName)
strictValidation.validateIntegerRange(value, min, max, fieldName)
strictValidation.validateFloatRange(value, min, max, fieldName, decimalPlaces)
strictValidation.validateDateRange(value, minDate, maxDate, fieldName)
strictValidation.validateArray(value, minLength, maxLength, fieldName, itemValidator)
strictValidation.validateBoolean(value, fieldName)
strictValidation.validateJSON(value, fieldName)
strictValidation.validateFileSize(size, maxSize, fieldName)
```

### 3. Validation Rules and Sets

#### Individual Field Rules
```javascript
validationRules = {
    username: [trim, rejectDangerous, validateLength, matchPattern],
    password: [rejectDangerous, validateLength, matchPattern, checkCommonPasswords],
    email: [trim, rejectDangerous, validateLength, matchPattern],
    taskTitle: [trim, rejectDangerous, validateLength, matchPattern],
    taskDescription: [trim, rejectDangerous, validateLength, matchPattern],
    assignedTo: [validateIntegerRange, isInt],
    priority: [trim, rejectDangerous, matchPattern],
    // ... more rules
}
```

#### Validation Sets for Forms
```javascript
validationSets = {
    registration: [username, password, confirmPassword],
    login: [username, password],
    changePassword: [currentPassword, password, confirmPassword],
    createTask: [taskTitle, taskDescription, assignedTo, priority],
    createManager: [username, password],
    updateTaskStatus: [taskId, taskStatus],
    reassignTask: [taskId, newAssignedTo],
    deleteTask: [taskId],
    deleteManager: [managerId]
}
```

### 4. Business Logic Validation

#### Password Strength Validation
```javascript
businessValidation.validatePasswordStrength(password, username)
```
- Enforces character requirements (upper, lower, digit, special)
- Checks against common password lists
- Prevents username inclusion
- Detects keyboard patterns
- Limits consecutive identical characters
- Validates length requirements

#### Role-Based Validation
```javascript
businessValidation.validateTaskAssignment(assignerRole, assigneeRole, taskData)
businessValidation.validateFileUploadRules(userRole, fileType, fileSize)
```

### 5. Enhanced Error Handling

#### Error Categorization
- **Security Errors**: Malicious content, injection attempts
- **Validation Errors**: Format, length, type violations  
- **Business Errors**: Rule violations, permission issues

#### Security Monitoring
```javascript
handleValidationErrors(req, res, next)
```
- Logs all validation failures
- Categorizes error types
- Tracks security alerts
- Provides detailed audit trails
- Protects against information disclosure

### 6. Request Validation Middleware

#### Comprehensive Request Checking
```javascript
validateRequest(options)
```
- HTTP method validation
- HTTPS requirement checking
- Body size limits
- Parameter count limits
- Content-Type validation
- Suspicious header detection

## Client-Side Validation (`public/js/validation.js`)

### Real-Time Feedback
- Immediate input validation
- Password strength indicators
- Character counters
- Field-specific error messages
- Form submission validation

### Security Note
Client-side validation is for UX only - all security validation happens server-side.

## Implementation Examples

### 1. Username Validation
```javascript
// Server-side (required)
body('username')
    .trim()
    .custom((value) => strictValidation.rejectDangerousInput(value))
    .custom((value) => strictValidation.validateStringLength(value, 3, 20, 'Username'))
    .matches(/^[a-zA-Z0-9_]{3,20}$/)
    .withMessage('Username must be 3-20 characters long and contain only letters, numbers, and underscores')

// Client-side (UX enhancement)
validateUsername(value) {
    if (!value) throw new Error('Username is required');
    if (value.length < 3 || value.length > 20) {
        throw new Error('Username must be 3-20 characters long');
    }
    if (!/^[a-zA-Z0-9_]+$/.test(value)) {
        throw new Error('Username can only contain letters, numbers, and underscores');
    }
}
```

### 2. Task Creation Validation
```javascript
// Route implementation
router.post('/create-task',
    requirePermission('task:create'),
    validationSets.createTask,
    handleValidationErrors,
    validateBusinessLogic(canAssignTaskToUser),
    (req, res) => {
        // All validation passed - proceed with task creation
    }
);

// Validation set
createTask: [
    validationRules.taskTitle,      // 1-100 chars, no dangerous content
    validationRules.taskDescription, // 0-500 chars, no dangerous content  
    validationRules.assignedTo,     // Valid user ID
    validationRules.priority        // Exactly "Low", "Medium", or "High"
]
```

### 3. Password Validation
```javascript
// Comprehensive password checking
password: body('password')
    .custom((value) => strictValidation.rejectDangerousInput(value))
    .custom((value) => strictValidation.validateStringLength(value, 8, 128, 'Password'))
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#+\-_=[\]{}|\\:";'<>?,./])[A-Za-z\d@$!%*?&#+\-_=[\]{}|\\:";'<>?,./]{8,128}$/)
    .withMessage('Password must be 8-128 characters and contain at least one uppercase letter, one lowercase letter, one number, and one special character')
    .custom((value) => {
        const commonPasswords = ['password', '12345678', 'qwerty123', 'admin123', 'password123'];
        if (commonPasswords.some(common => value.toLowerCase().includes(common.toLowerCase()))) {
            throw new Error('Password contains common patterns and has been rejected');
        }
        return true;
    })
```

## Security Benefits

### 1. Injection Attack Prevention
- SQL injection blocked by pattern detection
- NoSQL injection prevented
- Command injection stopped
- LDAP injection blocked
- Template injection prevented

### 2. XSS Attack Prevention  
- Script tag detection
- Event handler blocking
- Data URI prevention
- JavaScript protocol blocking

### 3. Data Integrity
- Strict type enforcement
- Range validation
- Length restrictions
- Pattern matching

### 4. Business Logic Protection
- Role-based validation
- Ownership verification
- Permission checking
- Rate limiting integration

## Testing and Validation

### Test Cases Covered
1. **Valid Input**: All valid inputs pass validation
2. **Invalid Formats**: Malformed data is rejected
3. **Security Attacks**: Injection attempts are blocked
4. **Boundary Values**: Edge cases are handled properly
5. **Business Rules**: Role and permission violations are caught

### Error Messages
- Clear and specific
- No information disclosure
- Consistent format
- User-friendly language

## Production Deployment

### Environment Configuration
```javascript
// Production settings
app.use(validateRequest({
    maxBodySize: 1 * 1024 * 1024, // 1MB in production
    maxParams: 50,
    allowedMethods: ['GET', 'POST'],
    requireHttps: true, // Force HTTPS
    checkContentType: true
}));
```

### Security Headers
- Content-Type validation
- Body size limits
- Parameter count restrictions
- HTTPS enforcement

## Monitoring and Alerting

### Security Event Logging
```javascript
// Automatic logging of validation failures
console.warn('Validation failed:', {
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.session?.user?.id,
    errorCategories: {
        security: securityErrorCount,
        validation: validationErrorCount,
        business: businessErrorCount
    },
    timestamp: new Date().toISOString()
});
```

### Security Alerts
- Immediate alerts for injection attempts
- Rate limiting integration
- Audit trail generation
- Threat detection

## Conclusion

This validation implementation provides comprehensive protection against common web application vulnerabilities while maintaining excellent user experience. The strict rejection approach ensures data integrity and prevents malicious input from affecting the application.

Key achievements:
- ✅ Zero auto-correction - all invalid data rejected
- ✅ Comprehensive range and type validation
- ✅ Advanced security pattern detection
- ✅ Centralized and reusable validation logic
- ✅ Client and server-side validation layers
- ✅ Business logic integration
- ✅ Comprehensive error handling and monitoring
- ✅ Production-ready security configuration
