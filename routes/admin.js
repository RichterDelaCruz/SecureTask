const express = require('express');
const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');
const { dbHelpers } = require('../database/init');
const { securityLogger } = require('../utils/logger');
const { validationSets, handleValidationErrors, injectValidationData } = require('../utils/validation');
const { privateCache, strictNoCache } = require('../utils/cache-control');

const router = express.Router();

// Apply validation data injection to all routes
router.use(injectValidationData);

// Manager accounts management page
router.get('/managers', privateCache, (req, res) => {
    const user = req.session.user;

    // Get all Project Manager accounts
    dbHelpers.getManagers((err, managers) => {
        if (err) {
            securityLogger.error('Failed to fetch managers list', {
                username: user.username,
                error: err.message
            });
            managers = [];
        }

        const successMessage = req.session.successMessage;
        const validationErrors = req.session.validationErrors;
        const formData = req.session.formData;

        // Clear session messages
        delete req.session.successMessage;
        delete req.session.validationErrors;
        delete req.session.formData;

        res.render('admin/managers', {
            title: 'Manage Project Managers - SecureTask',
            user: user,
            managers: managers,
            successMessage,
            validationErrors: validationErrors || [],
            formData: formData || {}
        });
    });
});

// Create new Project Manager account
router.post('/create-manager',
    strictNoCache,
    validationSets.createManager,
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            // Store errors and form data in session
            req.session.validationErrors = errors.array();
            req.session.formData = {
                username: req.body.username || ''
            };

            securityLogger.warn('Manager creation validation failed', {
                username: req.session.user?.username,
                errors: errors.array().map(e => e.msg),
                attemptedUsername: req.body.username
            });

            return res.redirect('/admin/managers');
        }
        next();
    },
    async (req, res) => {
        try {
            const { username, password } = req.body;
            const user = req.session.user;

            // Additional server-side validation
            if (!username || username.length < 3 || username.length > 30) {
                req.session.validationErrors = [{ msg: 'Username must be between 3 and 30 characters' }];
                req.session.formData = { username: username || '' };
                return res.redirect('/admin/managers');
            }

            if (!password || password.length < 8) {
                req.session.validationErrors = [{ msg: 'Password must be at least 8 characters long' }];
                req.session.formData = { username: username || '' };
                return res.redirect('/admin/managers');
            }

            // Check password complexity
            const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
            if (!passwordRegex.test(password)) {
                req.session.validationErrors = [{
                    msg: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)'
                }];
                req.session.formData = { username: username || '' };
                return res.redirect('/admin/managers');
            }

            // Check if username already exists
            dbHelpers.getUserByUsername(username, async (err, existingUser) => {
                if (err) {
                    securityLogger.error('Database error during manager creation', {
                        username: user.username,
                        error: err.message,
                        newManagerUsername: username
                    });
                    req.session.validationErrors = [{ msg: 'Failed to create manager account. Please try again.' }];
                    req.session.formData = { username: username || '' };
                    return res.redirect('/admin/managers');
                }

                if (existingUser) {
                    securityLogger.warn('Attempt to create manager with existing username', {
                        username: user.username,
                        newManagerUsername: username
                    });
                    req.session.validationErrors = [{ msg: 'Username already exists. Please choose a different username.' }];
                    req.session.formData = { username: username || '' };
                    return res.redirect('/admin/managers');
                }

                try {
                    // Hash password
                    const saltRounds = 12;
                    const passwordHash = await bcrypt.hash(password, saltRounds);

                    // Create new Project Manager user
                    dbHelpers.createUser(username, passwordHash, 'Project Manager', function (err) {
                        if (err) {
                            securityLogger.error('Failed to create manager account', {
                                username: user.username,
                                error: err.message,
                                newManagerUsername: username
                            });
                            req.session.validationErrors = [{ msg: 'Failed to create manager account. Please try again.' }];
                            req.session.formData = { username: username || '' };
                            return res.redirect('/admin/managers');
                        }

                        securityLogger.info('New Project Manager account created', {
                            username: user.username,
                            newManagerUsername: username,
                            newManagerId: this.lastID
                        });

                        req.session.successMessage = 'Project Manager account created successfully!';
                        res.redirect('/admin/managers');
                    });
                } catch (hashError) {
                    securityLogger.error('Password hashing failed during manager creation', {
                        username: user.username,
                        error: hashError.message,
                        newManagerUsername: username
                    });
                    req.session.validationErrors = [{ msg: 'Failed to create manager account. Please try again.' }];
                    req.session.formData = { username: username || '' };
                    res.redirect('/admin/managers');
                }
            });
        } catch (error) {
            securityLogger.error('Unexpected error during manager creation', {
                username: req.session.user.username,
                error: error.message
            });
            req.session.validationErrors = [{ msg: 'Failed to create manager account. Please try again.' }];
            req.session.formData = { username: req.body.username || '' };
            res.redirect('/admin/managers');
        }
    }
);

// Delete Project Manager account
router.post('/delete-manager', strictNoCache, (req, res) => {
    const { managerId } = req.body;
    const user = req.session.user;

    if (!managerId || isNaN(parseInt(managerId))) {
        securityLogger.warn('Invalid manager deletion attempt', {
            username: user.username,
            managerId
        });
        req.session.validationErrors = [{ msg: 'Invalid manager ID.' }];
        return res.redirect('/admin/managers');
    }

    // First, get the manager details for logging
    dbHelpers.getUserById(managerId, (err, manager) => {
        if (err) {
            securityLogger.error('Database error checking manager for deletion', {
                username: user.username,
                error: err.message,
                managerId
            });
            req.session.validationErrors = [{ msg: 'Failed to delete manager account. Please try again.' }];
            return res.redirect('/admin/managers');
        }

        if (!manager || manager.role !== 'Project Manager') {
            securityLogger.warn('Attempt to delete non-existent or invalid manager', {
                username: user.username,
                managerId,
                managerRole: manager?.role
            });
            req.session.validationErrors = [{ msg: 'Manager account not found.' }];
            return res.redirect('/admin/managers');
        }

        // Prevent deletion of the last administrator (safety check)
        if (manager.role === 'Administrator') {
            securityLogger.warn('Attempt to delete administrator account via manager deletion', {
                username: user.username,
                targetUsername: manager.username,
                managerId
            });
            req.session.validationErrors = [{ msg: 'Cannot delete administrator accounts through this interface.' }];
            return res.redirect('/admin/managers');
        }

        // Delete the manager account
        dbHelpers.deleteUser(managerId, function (err) {
            if (err) {
                securityLogger.error('Failed to delete manager account', {
                    username: user.username,
                    error: err.message,
                    managerId,
                    targetUsername: manager.username
                });
                req.session.validationErrors = [{ msg: 'Failed to delete manager account. Please try again.' }];
                return res.redirect('/admin/managers');
            }

            if (this.changes === 0) {
                securityLogger.warn('Manager deletion had no effect', {
                    username: user.username,
                    managerId,
                    targetUsername: manager.username
                });
                req.session.validationErrors = [{ msg: 'Manager account not found.' }];
                return res.redirect('/admin/managers');
            }

            securityLogger.info('Project Manager account deleted', {
                username: user.username,
                deletedManagerUsername: manager.username,
                managerId
            });

            req.session.successMessage = 'Project Manager account deleted successfully!';
            res.redirect('/admin/managers');
        });
    });
});

// System logs viewer page
router.get('/logs', (req, res) => {
    const user = req.session.user;

    // Get system logs
    dbHelpers.getLogs((err, logs) => {
        if (err) {
            securityLogger.error('Failed to fetch system logs', {
                username: user.username,
                error: err.message
            });
            logs = [];
        }

        // Parse additional_data JSON for better display
        const parsedLogs = logs.map(log => {
            try {
                log.additional_data_parsed = log.additional_data ? JSON.parse(log.additional_data) : {};
            } catch (parseError) {
                log.additional_data_parsed = {};
            }
            return log;
        });

        securityLogger.info('System logs accessed', {
            username: user.username,
            logCount: logs.length
        });

        res.render('admin/logs', {
            title: 'System Logs - SecureTask',
            user: user,
            logs: parsedLogs
        });
    });
});

module.exports = router;
