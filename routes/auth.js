const express = require('express');
const bcrypt = require('bcrypt');
const { dbHelpers } = require('../database/init');
const { securityLogger } = require('../utils/logger');
const { validationSets, handleValidationErrors, injectValidationData } = require('../utils/validation');
const { redirectIfAuthenticated } = require('../middleware/auth');
const { asyncErrorHandler } = require('../middleware/error-handler');
const {
    logAuthenticationEvent,
    logSystemEvent,
    SECURITY_EVENTS,
    RISK_LEVELS
} = require('../utils/security-logger');

const router = express.Router();

// Apply validation data injection to all routes
router.use(injectValidationData);

// Home route - redirect to dashboard if authenticated, otherwise to login
router.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

// Registration page
router.get('/register', redirectIfAuthenticated, (req, res) => {
    res.render('register', {
        title: 'Register - SecureTask',
        user: null
    });
});

// Registration form handler
router.post('/register',
    redirectIfAuthenticated,
    validationSets.registration,
    handleValidationErrors,
    asyncErrorHandler(async (req, res) => {
        try {
            const { username, password } = req.body;

            // Check if username already exists
            dbHelpers.getUserByUsername(username, async (err, existingUser) => {
                if (err) {
                    securityLogger.error('Database error during registration', {
                        error: err.message,
                        ip: req.ip
                    });
                    req.session.validationErrors = [{ msg: 'Registration failed. Please try again.' }];
                    return res.redirect('/register');
                }

                if (existingUser) {
                    securityLogger.warn('Registration attempt with existing username', {
                        username,
                        ip: req.ip,
                        userAgent: req.get('User-Agent')
                    });
                    req.session.validationErrors = [{ msg: 'Username already exists' }];
                    return res.redirect('/register');
                }

                try {
                    // Hash password
                    const saltRounds = 12;
                    const passwordHash = await bcrypt.hash(password, saltRounds);

                    // Create new user with Employee role
                    dbHelpers.createUser(username, passwordHash, 'Employee', function (err) {
                        if (err) {
                            logAuthenticationEvent(SECURITY_EVENTS.REGISTRATION_FAILURE, req, false, {
                                username,
                                error: err.message
                            });
                            req.session.validationErrors = [{ msg: 'Registration failed. Please try again.' }];
                            return res.redirect('/register');
                        }

                        logAuthenticationEvent(SECURITY_EVENTS.REGISTRATION_SUCCESS, req, true, {
                            username,
                            role: 'Employee'
                        });

                        req.session.successMessage = 'Registration successful! Please log in.';
                        res.redirect('/login');
                    });
                } catch (hashError) {
                    securityLogger.error('Password hashing failed during registration', {
                        username,
                        error: hashError.message,
                        ip: req.ip
                    });
                    req.session.validationErrors = [{ msg: 'Registration failed. Please try again.' }];
                    res.redirect('/register');
                }
            });
        } catch (error) {
            securityLogger.error('Unexpected error during registration', {
                error: error.message,
                ip: req.ip
            });
            req.session.validationErrors = [{ msg: 'Registration failed. Please try again.' }];
            res.redirect('/register');
        }
    })
);

// Login page
router.get('/login', redirectIfAuthenticated, (req, res) => {
    const successMessage = req.session.successMessage;
    delete req.session.successMessage;

    res.render('login', {
        title: 'Login - SecureTask',
        user: null,
        successMessage
    });
});

// Login form handler
router.post('/login',
    redirectIfAuthenticated,
    validationSets.login,
    handleValidationErrors,
    asyncErrorHandler(async (req, res) => {
        const { username, password } = req.body;

        dbHelpers.getUserByUsername(username, async (err, user) => {
            if (err) {
                securityLogger.error('Database error during login', {
                    username,
                    error: err.message,
                    ip: req.ip
                });
                req.session.validationErrors = [{ msg: 'Login failed. Please check your credentials.' }];
                return res.redirect('/login');
            }

            // Generic error message for security
            const genericError = 'Invalid username or password';

            if (!user) {
                logAuthenticationEvent(SECURITY_EVENTS.LOGIN_FAILURE, req, false, {
                    username,
                    reason: 'non_existent_username'
                });
                req.session.validationErrors = [{ msg: genericError }];
                return res.redirect('/login');
            }

            // Check if account is locked
            if (user.locked_until && new Date() < new Date(user.locked_until)) {
                logAuthenticationEvent(SECURITY_EVENTS.LOGIN_LOCKED_ACCOUNT, req, false, {
                    username,
                    lockedUntil: user.locked_until
                });
                req.session.validationErrors = [{ msg: 'Account is temporarily locked due to multiple failed attempts. Please try again later.' }];
                return res.redirect('/login');
            }

            try {
                // Verify password
                const isPasswordValid = await bcrypt.compare(password, user.password_hash);

                if (!isPasswordValid) {
                    // Update last failed login attempt before incrementing failed attempts
                    dbHelpers.updateLastFailedLogin(username, req.ip, (updateErr) => {
                        if (updateErr) {
                            securityLogger.error('Failed to update last failed login', {
                                username,
                                error: updateErr.message
                            });
                        }
                    });

                    // Increment failed attempts
                    const newFailedAttempts = user.failed_attempts + 1;
                    let lockedUntil = null;

                    // Lock account after 5 failed attempts for 15 minutes
                    if (newFailedAttempts >= 5) {
                        lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
                    }

                    dbHelpers.updateFailedAttempts(username, newFailedAttempts, lockedUntil, (updateErr) => {
                        if (updateErr) {
                            securityLogger.error('Failed to update failed login attempts', {
                                username,
                                error: updateErr.message
                            });
                        }
                    });

                    logAuthenticationEvent(SECURITY_EVENTS.LOGIN_FAILURE, req, false, {
                        username,
                        failedAttempts: newFailedAttempts,
                        reason: 'invalid_password'
                    });

                    req.session.validationErrors = [{ msg: genericError }];
                    return res.redirect('/login');
                }

                // Store last login info for display before updating it
                const lastLoginInfo = {
                    lastLoginAt: user.last_login_at,
                    lastLoginIp: user.last_login_ip,
                    lastFailedLoginAt: user.last_failed_login_at,
                    lastFailedLoginIp: user.last_failed_login_ip
                };

                // Reset failed attempts on successful login
                if (user.failed_attempts > 0) {
                    dbHelpers.updateFailedAttempts(username, 0, null, (updateErr) => {
                        if (updateErr) {
                            securityLogger.error('Failed to reset failed login attempts', {
                                username,
                                error: updateErr.message
                            });
                        }
                    });
                }

                // Update last successful login information
                dbHelpers.updateLastLogin(username, req.ip, (updateErr) => {
                    if (updateErr) {
                        securityLogger.error('Failed to update last successful login', {
                            username,
                            error: updateErr.message
                        });
                    }
                });

                // Create session
                req.session.user = {
                    id: user.id,
                    username: user.username,
                    role: user.role
                };

                // Store last login info in session for display on dashboard
                req.session.lastLoginInfo = lastLoginInfo;

                logAuthenticationEvent(SECURITY_EVENTS.LOGIN_SUCCESS, req, true, {
                    username,
                    role: user.role
                });

                res.redirect('/dashboard');

            } catch (compareError) {
                securityLogger.error('Password comparison failed during login', {
                    username,
                    error: compareError.message,
                    ip: req.ip
                });
                req.session.validationErrors = [{ msg: genericError }];
                res.redirect('/login');
            }
        });
    })
);

module.exports = router;
