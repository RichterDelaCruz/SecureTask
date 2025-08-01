const express = require('express');
const bcrypt = require('bcrypt');
const { dbHelpers } = require('../database/init');
const { securityLogger } = require('../utils/logger');
const { validationSets, handleValidationErrors, injectValidationData } = require('../utils/validation');

const { requireFreshLogin } = require('../middleware/freshLogin');

const router = express.Router();

// Apply validation data injection to all routes
router.use(injectValidationData);

// Change password page
router.get('/change-password', requireFreshLogin(15), (req, res) => {
    const user = req.session.user;
    const successMessage = req.session.successMessage;
    delete req.session.successMessage;

    res.render('account/change-password', {
        title: 'Change Password - SecureTask',
        user: user,
        successMessage
    });
});

// Change password form handler
router.post('/change-password',
    requireFreshLogin(15),
    validationSets.changePassword,
    handleValidationErrors,
    async (req, res) => {
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
                        return res.redirect('/account/change-password');
                    }

                    // Check if new password is different from current
                    const isSamePassword = await bcrypt.compare(password, userData.password_hash);
                    if (isSamePassword) {
                        securityLogger.warn('Attempt to change password to same password', {
                            username: user.username
                        });
                        req.session.validationErrors = [{ msg: 'New password must be different from current password.' }];
                        return res.redirect('/account/change-password');
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
    }
);

module.exports = router;
