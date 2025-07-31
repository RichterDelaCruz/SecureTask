const express = require('express');
const bcrypt = require('bcrypt');
const { dbHelpers } = require('../database/init');
const { securityLogger } = require('../utils/logger');
const { validationSets, handleValidationErrors, injectValidationData } = require('../utils/validation');

const router = express.Router();

// Apply validation data injection to all routes
router.use(injectValidationData);

// Manager accounts management page
router.get('/managers', (req, res) => {
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
        delete req.session.successMessage;

        res.render('admin/managers', {
            title: 'Manage Project Managers - SecureTask',
            user: user,
            managers: managers,
            successMessage
        });
    });
});

// Create new Project Manager account
router.post('/create-manager',
    validationSets.createManager,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { username, password } = req.body;
            const user = req.session.user;

            // Check if username already exists
            dbHelpers.getUserByUsername(username, async (err, existingUser) => {
                if (err) {
                    securityLogger.error('Database error during manager creation', {
                        username: user.username,
                        error: err.message,
                        newManagerUsername: username
                    });
                    req.session.validationErrors = [{ msg: 'Failed to create manager account. Please try again.' }];
                    return res.redirect('/admin/managers');
                }

                if (existingUser) {
                    securityLogger.warn('Attempt to create manager with existing username', {
                        username: user.username,
                        newManagerUsername: username
                    });
                    req.session.validationErrors = [{ msg: 'Username already exists' }];
                    return res.redirect('/admin/managers');
                }

                try {
                    // Hash password
                    const saltRounds = 12;
                    const passwordHash = await bcrypt.hash(password, saltRounds);

                    // Create new Project Manager user
                    dbHelpers.createUser(username, passwordHash, 'Project Manager', function(err) {
                        if (err) {
                            securityLogger.error('Failed to create manager account', {
                                username: user.username,
                                error: err.message,
                                newManagerUsername: username
                            });
                            req.session.validationErrors = [{ msg: 'Failed to create manager account. Please try again.' }];
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
                    res.redirect('/admin/managers');
                }
            });
        } catch (error) {
            securityLogger.error('Unexpected error during manager creation', {
                username: req.session.user.username,
                error: error.message
            });
            req.session.validationErrors = [{ msg: 'Failed to create manager account. Please try again.' }];
            res.redirect('/admin/managers');
        }
    }
);

// Delete Project Manager account
router.post('/delete-manager', (req, res) => {
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
        dbHelpers.deleteUser(managerId, function(err) {
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
