/**
 * Cache Control Utilities for SecureTask
 * Provides middleware functions for different cache control policies
 */

/**
 * Strict no-cache policy for sensitive operations
 * Use for authentication, authorization, and data modification operations
 */
const strictNoCache = (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    res.setHeader('Vary', 'Authorization, Cookie');
    next();
};

/**
 * Limited cache policy for public content
 * Use for login/register pages that should have minimal caching
 */
const limitedCache = (req, res, next) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
};

/**
 * Private cache policy for user-specific content
 * Use for dashboard and user-specific pages
 */
const privateCache = (req, res, next) => {
    res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Vary', 'Authorization, Cookie');
    next();
};

/**
 * Static asset cache policy
 * Use for CSS, JS, images, and other static assets
 */
const staticAssetCache = (maxAge = 86400) => { // Default: 24 hours
    return (req, res, next) => {
        if (process.env.NODE_ENV === 'production') {
            res.setHeader('Cache-Control', `public, max-age=${maxAge}, immutable`);
            res.setHeader('Expires', new Date(Date.now() + maxAge * 1000).toUTCString());
        } else {
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Expires', '0');
        }
        next();
    };
};

/**
 * API response cache policy
 * Use for API endpoints that return dynamic data
 */
const apiNoCache = (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Vary', 'Authorization, Accept');

    // Ensure JSON responses include proper headers
    const originalJson = res.json;
    res.json = function (data) {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        return originalJson.call(this, data);
    };

    next();
};

module.exports = {
    strictNoCache,
    limitedCache,
    privateCache,
    staticAssetCache,
    apiNoCache
};
