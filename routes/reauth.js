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

  // ✅ Update last authenticated time
  req.session.lastAuthenticatedAt = Date.now();

  // Redirect to original protected page
  const redirectTo = req.session.returnTo || '/dashboard';
  delete req.session.returnTo;
  res.redirect(redirectTo);
});
