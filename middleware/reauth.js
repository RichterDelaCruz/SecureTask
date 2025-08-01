const bcrypt = require('bcrypt');
const { dbHelpers } = require('../database/init');
const { securityLogger } = require('../utils/logger');

// Middleware to require re-authentication for critical actions
const requireReauth = (req, res, next) => {
    // Fail securely - require authentication first
    if (!req.session.user) {
        securityLogger.warn('Unauthenticated access attempt to protected action', {
            url: req.url,
            method: req.method,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            timestamp: new Date().toISOString()
        });
        return res.redirect('/login');
    }

    // Check if user has been re-authenticated recently (within 5 minutes)
    const reauthTime = req.session.reauthTime;
    const now = Date.now();
    
    if (reauthTime && (now - reauthTime) < 5 * 60 * 1000) {
        // User is recently re-authenticated, proceed
        securityLogger.debug('User has valid re-authentication token', {
            username: req.session.user.username,
            reauthAge: now - reauthTime,
            action: req.originalUrl,
            ip: req.ip,
            timestamp: new Date().toISOString()
        });
        return next();
    }

    // Check if this is a re-authentication attempt
    if (req.method === 'POST' && req.body.confirmPassword) {
        const { confirmPassword } = req.body;
        const user = req.session.user;

        // Validate input
        if (!confirmPassword || typeof confirmPassword !== 'string') {
            securityLogger.warn('Invalid re-authentication attempt - missing password', {
                username: user.username,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                action: req.originalUrl,
                timestamp: new Date().toISOString()
            });
            req.session.validationErrors = [{ msg: 'Password is required for this action.' }];
            return res.redirect(req.originalUrl);
        }

        // Verify the current password
        dbHelpers.getUserById(user.id, async (err, userData) => {
            if (err) {
                securityLogger.error('Database error during re-authentication', {
                    username: user.username,
                    error: err.message,
                    action: req.originalUrl,
                    ip: req.ip,
                    timestamp: new Date().toISOString()
                });
                req.session.validationErrors = [{ msg: 'Authentication failed. Please try again.' }];
                return res.redirect(req.originalUrl);
            }

            if (!userData) {
                securityLogger.error('User not found during re-authentication', {
                    username: user.username,
                    userId: user.id,
                    action: req.originalUrl,
                    ip: req.ip,
                    timestamp: new Date().toISOString()
                });
                req.session.validationErrors = [{ msg: 'Authentication failed. Please try again.' }];
                return res.redirect(req.originalUrl);
            }

            // Check if account is locked
            if (userData.locked_until && new Date() < new Date(userData.locked_until)) {
                securityLogger.warn('Re-authentication attempt on locked account', {
                    username: user.username,
                    lockedUntil: userData.locked_until,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    action: req.originalUrl,
                    timestamp: new Date().toISOString()
                });
                req.session.validationErrors = [{ msg: 'Account is temporarily locked. Please try again later.' }];
                return res.redirect(req.originalUrl);
            }

            try {
                const isPasswordValid = await bcrypt.compare(confirmPassword, userData.password_hash);

                if (!isPasswordValid) {
                    securityLogger.warn('Invalid password during re-authentication', {
                        username: user.username,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        action: req.originalUrl,
                        timestamp: new Date().toISOString()
                    });
                    req.session.validationErrors = [{ msg: 'Invalid password. Please enter your current password to confirm this action.' }];
                    return res.redirect(req.originalUrl);
                }

                // Set re-authentication timestamp
                req.session.reauthTime = now;

                securityLogger.info('User re-authenticated for critical action', {
                    username: user.username,
                    action: req.originalUrl,
                    ip: req.ip,
                    timestamp: new Date().toISOString()
                });

                // Continue with the original request
                next();

            } catch (compareError) {
                securityLogger.error('Password comparison failed during re-authentication', {
                    username: user.username,
                    error: compareError.message,
                    action: req.originalUrl,
                    ip: req.ip,
                    timestamp: new Date().toISOString()
                });
                req.session.validationErrors = [{ msg: 'Authentication failed. Please try again.' }];
                res.redirect(req.originalUrl);
            }
        });
    } else {
        // Show re-authentication form
        securityLogger.info('Re-authentication required for critical action', {
            username: req.session.user.username,
            action: req.originalUrl,
            ip: req.ip,
            timestamp: new Date().toISOString()
        });
        req.session.requireReauth = true;
        res.redirect(req.originalUrl);
    }
};

module.exports = {
    requireReauth
};
