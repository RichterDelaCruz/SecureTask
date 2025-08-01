const express = require('express');
const crypto = require('crypto');
const { dbHelpers } = require('../database/init');
const router = express.Router();

// Show forgot password form
router.get('/forgot-password', (req, res) => {
  res.render('auth/forgot-password', {
    title: 'Forgot Password',
    csrfToken: req.csrfToken()
  });
});

// Handle forgot password form
router.post('/forgot-password', async (req, res) => {
  const { username } = req.body;

  dbHelpers.getUserByUsername(username, async (err, user) => {
    if (err || !user) {
      return res.render('auth/forgot-password', {
        title: 'Forgot Password',
        error: 'No user found with that username.',
        csrfToken: req.csrfToken()
      });
    }

    // Generate secure random token
    const token = crypto.randomBytes(32).toString('hex');
    const expiry = Date.now() + 15 * 60 * 1000; // 15 minutes from now

    // Save to DB
    db.run(
      'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
      [token, expiry, user.id],
      () => {
        // Simulate email by showing token onscreen
        res.render('auth/token-sent', {
          title: 'Reset Link Sent',
          token, // Show for now — replace with email in production
          username
        });
      }
    );
  });
});
