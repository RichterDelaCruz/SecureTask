router.get('/re-auth', (req, res) => {
  res.render('reauth', { title: 'Re-authenticate', csrfToken: req.csrfToken() });
});

router.post('/re-auth', async (req, res) => {
  const { username, password } = req.body;

  const user = await dbHelpers.getUserByUsername(username);
  if (!user) {
    req.flash('error', 'Invalid credentials');
    return res.redirect('/re-auth');
  }

  const passwordMatch = await bcrypt.compare(password, user.password_hash);
  if (!passwordMatch) {
    req.flash('error', 'Invalid credentials');
    return res.redirect('/re-auth');
  }

  // Update last authenticated time
  req.session.lastAuthenticatedAt = Date.now();

  // Redirect to original protected page
  const redirectTo = req.session.returnTo || '/dashboard';
  delete req.session.returnTo;
  res.redirect(redirectTo);
});

// Show reset password form
router.get('/reset-password/:token', (req, res) => {
  const token = req.params.token;

  dbHelpers.getUserByResetToken(token, (err, user) => {
    if (err || !user || Date.now() > user.reset_token_expiry) {
      return res.status(400).render('error', {
        message: 'Invalid or expired reset token.',
        user: null
      });
    }

    res.render('auth/reset-password', {
      title: 'Reset Password',
      token,
      csrfToken: req.csrfToken()
    });
  });
});

const bcrypt = require('bcrypt');

// Handle password reset submission
router.post('/reset-password/:token', async (req, res) => {
  const token = req.params.token;
  const { password } = req.body;

  dbHelpers.getUserByResetToken(token, async (err, user) => {
    if (err || !user || Date.now() > user.reset_token_expiry) {
      return res.status(400).render('error', {
        message: 'Invalid or expired reset token.',
        user: null
      });
    }

    // Hash new password
    const newHash = await bcrypt.hash(password, 12);

    // Update password and clear token
    db.run(
      `UPDATE users
       SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [newHash, user.id],
      () => {
        res.render('auth/reset-success', {
          title: 'Password Reset',
          message: 'Your password has been reset successfully. You can now log in.'
        });
      }
    );
  });
});
