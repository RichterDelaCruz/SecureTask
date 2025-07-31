const winston = require('winston');

// Create logger configuration
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'securetask' },
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ],
});

// Database helpers reference (set after database initialization)
let dbHelpers = null;

// Function to set database helpers after initialization
const setDbHelpers = (helpers) => {
    dbHelpers = helpers;
};

// Security-specific logger that also writes to database
const securityLogger = {
    info: (message, meta = {}) => {
        logger.info(message, meta);
        if (dbHelpers) {
            dbHelpers.insertLog(
                'INFO',
                message,
                meta.username || null,
                meta.ip || null,
                meta.userAgent || null,
                JSON.stringify(meta)
            );
        }
    },

    warn: (message, meta = {}) => {
        logger.warn(message, meta);
        if (dbHelpers) {
            dbHelpers.insertLog(
                'WARN',
                message,
                meta.username || null,
                meta.ip || null,
                meta.userAgent || null,
                JSON.stringify(meta)
            );
        }
    },

    error: (message, meta = {}) => {
        logger.error(message, meta);
        if (dbHelpers) {
            dbHelpers.insertLog(
                'ERROR',
                message,
                meta.username || null,
                meta.ip || null,
                meta.userAgent || null,
                JSON.stringify(meta)
            );
        }
    }
};

module.exports = { logger, securityLogger, setDbHelpers };
