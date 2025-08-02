const express = require('express');
const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');
const { dbHelpers } = require('../database/init');
const { securityLogger } = require('../utils/logger');
const { validationSets, handleValidationErrors, injectValidationData } = require('../utils/validation');
const { requirePermission } = require('../middleware/authorization');
const { sensitiveOperationLimiter } = require('../middleware/authz-audit');
const { asyncErrorHandler } = require('../middleware/error-handler');

const router = express.Router();

// Helper function to save session and redirect
function saveSessionAndRedirect(req, res, redirectUrl, callback) {
    req.session.save((err) => {
        if (err) {
            console.log('Session save error:', err);
        } else {
            console.log('Session saved successfully');
        }
        if (callback) callback();
        res.redirect(redirectUrl);
    });
}

// Remove injectValidationData to prevent session clearing
// router.use(injectValidationData);

// Change password page
router.get('/change-password', 
    requirePermission('account:view-profile'),
    (req, res) => {
    const user = req.session.user;
    const successMessage = req.session.successMessage;
    let validationErrors = req.session.validationErrors;
    
    // If we have the errors query param but no validation errors in session,
    // try reloading session data
    if (req.query.errors === '1' && !validationErrors) {
        req.session.reload((reloadErr) => {
            if (!reloadErr) {
                validationErrors = req.session.validationErrors;
            }
            
            // Clean up session messages after retrieving them
            delete req.session.successMessage;
            delete req.session.validationErrors;
            delete req.session.hasValidationErrors;

            res.render('account/change-password', {
                title: 'Change Password - SecureTask',
                user: user,
                successMessage,
                validationErrors
            });
        });
        return;
    }
    
    // Clean up session messages after retrieving them
    delete req.session.successMessage;
    delete req.session.validationErrors;
    delete req.session.hasValidationErrors;

    res.render('account/change-password', {
        title: 'Change Password - SecureTask',
        user: user,
        successMessage,
        validationErrors
    });
});

// Change password form handler
router.post('/change-password',
    requirePermission('account:change-password'),
    sensitiveOperationLimiter('password-change', 5, 30 * 60 * 1000), // 5 attempts per 30 minutes
    validationSets.changePassword,
    asyncErrorHandler(async (req, res) => {
        // Check for validation errors first
        const errors = validationResult(req);
        
        if (!errors.isEmpty()) {
            // Convert specific validation errors to generic messages for security
            const errorsByType = {};
            
            errors.array().forEach(error => {
                if (error.path === 'password' || error.path === 'currentPassword' || error.path === 'confirmPassword') {
                    errorsByType.password = 'Password requirements not met. Please check your password and try again.';
                } else {
                    errorsByType.general = 'Invalid input. Please check your data and try again.';
                }
            });
            
            // Convert to array of unique messages
            const genericErrors = Object.values(errorsByType).map(msg => ({ msg }));
            
            req.session.validationErrors = genericErrors;
            req.session.hasValidationErrors = true;
            
            return req.session.save((err) => {
                if (err) {
                    return res.redirect('/account/change-password?errors=1');
                }
                res.redirect('/account/change-password?errors=1');
            });
        }

        try {
            const { currentPassword, password } = req.body;
            const user = req.session.user;

            // Get current user data
            dbHelpers.getUserById(user.id, async (err, userData) => {
                if (err) {
                    securityLogger.error('Database error during password change', {
                        username: user.username,
                        error: err.message
                    });
                    req.session.validationErrors = [{ msg: 'Password change failed. Please try again.' }];
                    return res.redirect('/account/change-password');
                }

                if (!userData) {
                    securityLogger.error('User not found during password change', {
                        username: user.username,
                        userId: user.id
                    });
                    req.session.validationErrors = [{ msg: 'Password change failed. Please try again.' }];
                    return res.redirect('/account/change-password');
                }

                try {
                    // Verify current password
                    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, userData.password_hash);

                    if (!isCurrentPasswordValid) {
                        securityLogger.warn('Invalid current password during password change', {
                            username: user.username,
                            ip: req.ip,
                            userAgent: req.get('User-Agent')
                        });
                        req.session.validationErrors = [{ msg: 'Current password is incorrect.' }];
                        return saveSessionAndRedirect(req, res, '/account/change-password');
                    }

                    // Check if new password is different from current
                    const isSamePassword = await bcrypt.compare(password, userData.password_hash);
                    if (isSamePassword) {
                        securityLogger.warn('Attempt to change password to same password', {
                            username: user.username
                        });
                        req.session.validationErrors = [{ msg: 'New password must be different from current password.' }];
                        return saveSessionAndRedirect(req, res, '/account/change-password');
                    }

                    // Hash new password
                    const saltRounds = 12;
                    const newPasswordHash = await bcrypt.hash(password, saltRounds);

                    // Update password in database
                    dbHelpers.updateUserPassword(user.id, newPasswordHash, function(err) {
                        if (err) {
                            securityLogger.error('Failed to update password in database', {
                                username: user.username,
                                error: err.message
                            });
                            req.session.validationErrors = [{ msg: 'Password change failed. Please try again.' }];
                            return res.redirect('/account/change-password');
                        }

                        securityLogger.info('Password changed successfully', {
                            username: user.username,
                            ip: req.ip,
                            userAgent: req.get('User-Agent')
                        });

                        req.session.successMessage = 'Password changed successfully!';
                        res.redirect('/account/change-password');
                    });

                } catch (compareError) {
                    securityLogger.error('Password comparison failed during password change', {
                        username: user.username,
                        error: compareError.message
                    });
                    req.session.validationErrors = [{ msg: 'Password change failed. Please try again.' }];
                    res.redirect('/account/change-password');
                }
            });

        } catch (error) {
            securityLogger.error('Unexpected error during password change', {
                username: req.session.user.username,
                error: error.message
            });
            req.session.validationErrors = [{ msg: 'Password change failed. Please try again.' }];
            res.redirect('/account/change-password');
        }
    })
);

module.exports = router;
