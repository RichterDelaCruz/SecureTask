module.exports.requireFreshLogin = function (minutes = 15) {
  return (req, res, next) => {
    const lastLogin = req.session.lastAuthenticatedAt;
    const now = Date.now();
    const age = now - lastLogin;

    const maxAge = minutes * 60 * 1000;

    if (age > maxAge) {
      // Old session! Force re-login.
      req.session.returnTo = req.originalUrl;
      req.flash('error', 'Please re-authenticate to continue.');
      return res.redirect('/re-auth');
    }

    next();
  };
};
