const express = require('express');
const bcrypt = require('bcrypt');
const { dbHelpers } = require('../database/init');
const { securityLogger } = require('../utils/logger');
const { validationSets, handleValidationErrors, injectValidationData } = require('../utils/validation');
const { redirectIfAuthenticated } = require('../middleware/auth');

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
    async (req, res) => {
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
                    dbHelpers.createUser(username, passwordHash, 'Employee', function(err) {
                        if (err) {
                            securityLogger.error('Failed to create user account', { 
                                username, 
                                error: err.message, 
                                ip: req.ip 
                            });
                            req.session.validationErrors = [{ msg: 'Registration failed. Please try again.' }];
                            return res.redirect('/register');
                        }

                        securityLogger.info('New user account created', { 
                            username, 
                            role: 'Employee', 
                            ip: req.ip,
                            userAgent: req.get('User-Agent')
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
    }
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
    (req, res) => {
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
                securityLogger.warn('Login attempt with non-existent username', { 
                    username, 
                    ip: req.ip,
                    userAgent: req.get('User-Agent')
                });
                req.session.validationErrors = [{ msg: genericError }];
                return res.redirect('/login');
            }

            // Check if account is locked
            if (user.locked_until && new Date() < new Date(user.locked_until)) {
                securityLogger.warn('Login attempt on locked account', { 
                    username, 
                    ip: req.ip,
                    userAgent: req.get('User-Agent')
                });
                req.session.validationErrors = [{ msg: 'Account is temporarily locked due to multiple failed attempts. Please try again later.' }];
                return res.redirect('/login');
            }

            try {
                // Verify password
                const isPasswordValid = await bcrypt.compare(password, user.password_hash);

                if (!isPasswordValid) {
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

                    securityLogger.warn('Failed login attempt', { 
                        username, 
                        failedAttempts: newFailedAttempts,
                        ip: req.ip,
                        userAgent: req.get('User-Agent')
                    });

                    req.session.validationErrors = [{ msg: genericError }];
                    return res.redirect('/login');
                }

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

                // Create session
                req.session.user = {
                    id: user.id,
                    username: user.username,
                    role: user.role
                };
                
                req.session.lastAuthenticatedAt = Date.now();

                securityLogger.info('Successful login', { 
                    username, 
                    role: user.role, 
                    ip: req.ip,
                    userAgent: req.get('User-Agent')
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
    }
);

module.exports = router;
