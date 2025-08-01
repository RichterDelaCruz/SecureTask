const SESSION_IDLE_TIMEOUT = 1000 * 60 * 30; // 30 minutes

const checkSessionTimeout = (req, res, next) => {
    if (req.session.user) {
        const now = Date.now();
        const last = req.session.lastActivityAt || now;
        const elapsed = now - last;

        if (elapsed > SESSION_IDLE_TIMEOUT) {
            // Session expired due to inactivity
            req.session.destroy(() => {
                res.redirect('/login');
            });
        } else {
            req.session.lastActivityAt = now;
            next();
        }
    } else {
        next();
    }
};

module.exports = checkSessionTimeout;
