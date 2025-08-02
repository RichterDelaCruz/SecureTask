const { securityLogger } = require('../utils/logger');
const { db, dbHelpers } = require('../database/init');
const { sanitize, VALIDATION_LIMITS } = require('../utils/validation');

// Centralized permissions mapping
const PERMISSIONS = {
    'Administrator': {
        // Admin permissions
        'admin:view-logs': true,
        'admin:manage-managers': true,
        'admin:view-system-stats': true,
        // Account permissions (all users)
        'account:change-password': true,
        'account:view-profile': true
    },
    'Project Manager': {
        // Task management permissions
        'task:create': true,
        'task:view-created': true,
        'task:edit-created': true,
        'task:delete-created': true,
        'task:reassign-created': true,
        // View permissions
        'user:view-employees': true,
        // Account permissions (all users)
        'account:change-password': true,
        'account:view-profile': true
    },
    'Employee': {
        // Task permissions (limited to assigned tasks)
        'task:view-assigned': true,
        'task:update-status-assigned': true,
        // Account permissions (all users)
        'account:change-password': true,
        'account:view-profile': true
    }
};

// Enhanced security headers middleware
const addSecurityHeaders = (req, res, next) => {
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // XSS protection
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Referrer policy for privacy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    next();
};

// Permission checking function
const hasPermission = (userRole, permission) => {
    return PERMISSIONS[userRole] && PERMISSIONS[userRole][permission] === true;
};

// Enhanced authorization middleware with permission-based checks
const requirePermission = (permission) => {
    return (req, res, next) => {
        // Fail securely - require authentication first
        if (!req.session.user) {
            securityLogger.warn('Unauthenticated access attempt', {
                permission: permission,
                url: req.url,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            return res.redirect('/login');
        }

        const user = req.session.user;

        // Check permission
        if (!hasPermission(user.role, permission)) {
            securityLogger.warn('Access denied - insufficient permissions', {
                username: user.username,
                role: user.role,
                permission: permission,
                url: req.url,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            
            return res.status(403).render('errors/403', {
                message: 'Access denied. You do not have permission to perform this action.',
                user: user
            });
        }

        next();
    };
};

// Resource ownership validation middleware
const requireResourceOwnership = (resourceType, getResourceOwner) => {
    return async (req, res, next) => {
        // Fail securely - require authentication first
        if (!req.session.user) {
            securityLogger.warn('Unauthenticated resource access attempt', {
                resourceType: resourceType,
                url: req.url,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            return res.redirect('/login');
        }

        const user = req.session.user;

        try {
            const ownerId = await getResourceOwner(req);
            
            // Allow if user owns the resource or has admin privileges
            if (ownerId !== user.id && user.role !== 'Administrator') {
                securityLogger.warn('Access denied - resource ownership violation', {
                    username: user.username,
                    role: user.role,
                    resourceType: resourceType,
                    resourceOwnerId: ownerId,
                    requestingUserId: user.id,
                    url: req.url,
                    method: req.method,
                    ip: req.ip,
                    userAgent: req.get('User-Agent')
                });
                
                return res.status(403).render('errors/403', {
                    message: 'Access denied. You can only access your own resources.',
                    user: user
                });
            }

            next();
        } catch (error) {
            securityLogger.error('Error checking resource ownership', {
                username: user.username,
                resourceType: resourceType,
                error: error.message,
                url: req.url,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date().toISOString()
            });
            
            // Fail securely - create proper error and pass to error handler
            const accessError = new Error('Access denied. Unable to verify resource ownership.');
            accessError.status = 403;
            return next(accessError);
        }
    };
};

// Task ownership helpers with enhanced validation
const getTaskCreatorId = (req) => {
    return new Promise((resolve, reject) => {
        const taskId = req.body.taskId || req.params.taskId;
        
        // Strict validation of task ID
        try {
            const validatedTaskId = sanitize.validateInteger(taskId, VALIDATION_LIMITS.TASK_ID.min, VALIDATION_LIMITS.TASK_ID.max);
            
            db.get(
                "SELECT created_by FROM tasks WHERE id = ?",
                [validatedTaskId],
                (err, row) => {
                    if (err) {
                        securityLogger.error('Database error checking task creator', {
                            taskId: validatedTaskId,
                            error: err.message
                        });
                        reject(err);
                    } else if (!row) {
                        securityLogger.warn('Task not found during ownership check', {
                            taskId: validatedTaskId
                        });
                        reject(new Error('Task not found'));
                    } else {
                        resolve(row.created_by);
                    }
                }
            );
        } catch (validationError) {
            securityLogger.warn('Invalid task ID in ownership check', {
                taskId,
                error: validationError.message
            });
            reject(validationError);
        }
    });
};

const getTaskAssigneeId = (req) => {
    return new Promise((resolve, reject) => {
        const taskId = req.body.taskId || req.params.taskId;
        
        // Strict validation of task ID
        try {
            const validatedTaskId = sanitize.validateInteger(taskId, VALIDATION_LIMITS.TASK_ID.min, VALIDATION_LIMITS.TASK_ID.max);
            
            db.get(
                "SELECT assigned_to FROM tasks WHERE id = ?",
                [validatedTaskId],
                (err, row) => {
                    if (err) {
                        securityLogger.error('Database error checking task assignee', {
                            taskId: validatedTaskId,
                            error: err.message
                        });
                        reject(err);
                    } else if (!row) {
                        securityLogger.warn('Task not found during assignee check', {
                            taskId: validatedTaskId
                        });
                        reject(new Error('Task not found'));
                    } else {
                        resolve(row.assigned_to);
                    }
                }
            );
        } catch (validationError) {
            securityLogger.warn('Invalid task ID in assignee check', {
                taskId,
                error: validationError.message
            });
            reject(validationError);
        }
    });
};

// User ID validation helper with enhanced validation
const validateTargetUserId = (req) => {
    return new Promise((resolve, reject) => {
        const targetUserId = req.body.userId || req.params.userId || req.body.managerId;
        
        try {
            const validatedUserId = sanitize.validateInteger(targetUserId, VALIDATION_LIMITS.USER_ID.min, VALIDATION_LIMITS.USER_ID.max);
            resolve(validatedUserId);
        } catch (validationError) {
            securityLogger.warn('Invalid user ID in validation', {
                targetUserId,
                error: validationError.message
            });
            reject(validationError);
        }
    });
};

// Business logic validation middleware
const validateBusinessLogic = (validationFunction) => {
    return async (req, res, next) => {
        if (!req.session.user) {
            return res.redirect('/login');
        }

        try {
            const isValid = await validationFunction(req, req.session.user);
            if (!isValid) {
                securityLogger.warn('Business logic validation failed', {
                    username: req.session.user.username,
                    url: req.url,
                    method: req.method,
                    ip: req.ip
                });
                
                return res.status(403).render('error', {
                    message: 'Access denied. This action violates business rules.',
                    user: req.session.user
                });
            }
            next();
        } catch (error) {
            securityLogger.error('Business logic validation error', {
                username: req.session.user.username,
                error: error.message,
                url: req.url,
                method: req.method,
                ip: req.ip
            });
            
            return res.status(403).render('error', {
                message: 'Access denied. Unable to validate business rules.',
                user: req.session.user
            });
        }
    };
};

// Specific business logic validators
const canDeleteManager = async (req, user) => {
    return new Promise((resolve, reject) => {
        const managerId = req.body.managerId;
        
        if (!managerId || isNaN(parseInt(managerId))) {
            resolve(false);
            return;
        }

        // Get the target user to validate
        dbHelpers.getUserById(managerId, (err, targetUser) => {
            if (err) {
                reject(err);
                return;
            }

            if (!targetUser) {
                resolve(false);
                return;
            }

            // Only allow deletion of Project Managers
            if (targetUser.role !== 'Project Manager') {
                resolve(false);
                return;
            }

            // Prevent self-deletion
            if (targetUser.id === user.id) {
                resolve(false);
                return;
            }

            resolve(true);
        });
    });
};

const canAssignTaskToUser = async (req, user) => {
    return new Promise((resolve, reject) => {
        const assignedToId = req.body.assignedTo || req.body.newAssignedTo;
        
        if (!assignedToId || isNaN(parseInt(assignedToId))) {
            resolve(false);
            return;
        }

        // Get the target user to validate
        dbHelpers.getUserById(assignedToId, (err, targetUser) => {
            if (err) {
                reject(err);
                return;
            }

            if (!targetUser) {
                resolve(false);
                return;
            }

            // Only allow assignment to Employees
            resolve(targetUser.role === 'Employee');
        });
    });
};

module.exports = {
    PERMISSIONS,
    hasPermission,
    requirePermission,
    requireResourceOwnership,
    getTaskCreatorId,
    getTaskAssigneeId,
    validateTargetUserId,
    validateBusinessLogic,
    canDeleteManager,
    canAssignTaskToUser,
    addSecurityHeaders
};
