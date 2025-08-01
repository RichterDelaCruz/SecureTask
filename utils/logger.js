const winston = require('winston');

// Performance monitoring for logging
const logMetrics = {
    totalLogs: 0,
    errorLogs: 0,
    warnLogs: 0,
    infoLogs: 0,
    lastLogTime: Date.now(),
    avgLogTime: 0
};

// Async queue for database logging to prevent performance impact
const dbLogQueue = [];
let isProcessingQueue = false;

// Process database logging queue asynchronously
const processDatabaseLogQueue = async () => {
    if (isProcessingQueue || dbLogQueue.length === 0) {
        return;
    }
    
    isProcessingQueue = true;
    
    try {
        while (dbLogQueue.length > 0) {
            const logEntry = dbLogQueue.shift();
            if (dbHelpers && dbHelpers.insertLog) {
                try {
                    await new Promise((resolve, reject) => {
                        dbHelpers.insertLog(
                            logEntry.level,
                            logEntry.message,
                            logEntry.username,
                            logEntry.ip,
                            logEntry.userAgent,
                            logEntry.additionalData,
                            (err) => {
                                if (err) reject(err);
                                else resolve();
                            }
                        );
                    });
                } catch (dbError) {
                    // If database logging fails, log to file only
                    console.error('Database logging failed:', dbError.message);
                }
            }
        }
    } catch (error) {
        console.error('Error processing database log queue:', error.message);
    } finally {
        isProcessingQueue = false;
        
        // Schedule next processing if queue has items
        if (dbLogQueue.length > 0) {
            setTimeout(processDatabaseLogQueue, 100);
        }
    }
};

// Enhanced Winston logger configuration with rotation
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss.SSS'
        }),
        winston.format.errors({ stack: true }),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
            // Sanitize sensitive data in logs
            const sanitizedMeta = sanitizeMeta(meta);
            return `${timestamp} [${level.toUpperCase()}]: ${message} ${Object.keys(sanitizedMeta).length ? JSON.stringify(sanitizedMeta) : ''}`;
        })
    ),
    defaultMeta: { 
        service: 'securetask',
        pid: process.pid,
        hostname: require('os').hostname()
    },
    transports: [
        // Error logs (with rotation)
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error',
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: 10,
            tailable: true,
            zippedArchive: true
        }),
        
        // Combined logs (with rotation)
        new winston.transports.File({ 
            filename: 'logs/combined.log',
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: 10,
            tailable: true,
            zippedArchive: true
        }),
        
        // Console output for development
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            ),
            silent: process.env.NODE_ENV === 'production'
        })
    ],
    
    // Handle logging exceptions
    exceptionHandlers: [
        new winston.transports.File({ filename: 'logs/exceptions.log' })
    ],
    
    // Handle logging rejections
    rejectionHandlers: [
        new winston.transports.File({ filename: 'logs/rejections.log' })
    ]
});

// Sanitize sensitive data from log metadata
const sanitizeMeta = (meta) => {
    const sanitized = { ...meta };
    
    // Remove or redact sensitive fields
    const sensitiveFields = [
        'password', 'token', 'secret', 'key', 'authorization',
        'cookie', 'session', 'confirmPassword', 'currentPassword',
        'passwordHash', 'newPassword'
    ];
    
    const redactObject = (obj, depth = 0) => {
        if (depth > 3 || !obj || typeof obj !== 'object') return obj;
        
        const result = Array.isArray(obj) ? [] : {};
        
        for (const [key, value] of Object.entries(obj)) {
            const keyLower = key.toLowerCase();
            if (sensitiveFields.some(field => keyLower.includes(field))) {
                result[key] = '[REDACTED]';
            } else if (typeof value === 'object' && value !== null) {
                result[key] = redactObject(value, depth + 1);
            } else {
                result[key] = value;
            }
        }
        
        return result;
    };
    
    return redactObject(sanitized);
};

// Queue database log entry for async processing
const queueDatabaseLog = (level, message, username, ip, userAgent, additionalData) => {
    dbLogQueue.push({
        level: level.toUpperCase(),
        message,
        username: username || null,
        ip: ip || null,
        userAgent: userAgent || null,
        additionalData: typeof additionalData === 'object' ? JSON.stringify(additionalData) : additionalData
    });
    
    // Process queue if not already processing
    if (!isProcessingQueue) {
        setImmediate(processDatabaseLogQueue);
    }
};

// Track logging performance
const trackLogPerformance = (level) => {
    const now = Date.now();
    logMetrics.totalLogs++;
    logMetrics.lastLogTime = now;
    
    switch (level.toLowerCase()) {
        case 'error':
            logMetrics.errorLogs++;
            break;
        case 'warn':
            logMetrics.warnLogs++;
            break;
        case 'info':
            logMetrics.infoLogs++;
            break;
    }
    
    // Update average log time (simple moving average)
    if (logMetrics.totalLogs > 1) {
        logMetrics.avgLogTime = (logMetrics.avgLogTime + (now - logMetrics.lastLogTime)) / 2;
    }
};

// Database helpers reference (set after database initialization)
let dbHelpers = null;

// Function to set database helpers after initialization
const setDbHelpers = (helpers) => {
    dbHelpers = helpers;
};

// Security-specific logger that also writes to database asynchronously
const securityLogger = {
    info: (message, meta = {}) => {
        const startTime = process.hrtime.bigint();
        
        try {
            // Log to Winston (file/console)
            logger.info(message, meta);
            
            // Queue for async database logging
            queueDatabaseLog('INFO', message, meta.username, meta.ip, meta.userAgent, meta);
            
            // Track performance
            trackLogPerformance('info');
        } catch (error) {
            console.error('Logging failed:', error.message);
        }
    },

    warn: (message, meta = {}) => {
        const startTime = process.hrtime.bigint();
        
        try {
            // Log to Winston (file/console)
            logger.warn(message, meta);
            
            // Queue for async database logging
            queueDatabaseLog('WARN', message, meta.username, meta.ip, meta.userAgent, meta);
            
            // Track performance
            trackLogPerformance('warn');
        } catch (error) {
            console.error('Logging failed:', error.message);
        }
    },

    error: (message, meta = {}) => {
        const startTime = process.hrtime.bigint();
        
        try {
            // Log to Winston (file/console)
            logger.error(message, meta);
            
            // Queue for async database logging
            queueDatabaseLog('ERROR', message, meta.username, meta.ip, meta.userAgent, meta);
            
            // Track performance
            trackLogPerformance('error');
        } catch (error) {
            console.error('Logging failed:', error.message);
        }
    },
    
    // Get logging performance metrics
    getMetrics: () => ({ ...logMetrics }),
    
    // Get queue status
    getQueueStatus: () => ({
        queueLength: dbLogQueue.length,
        isProcessing: isProcessingQueue
    })
};

module.exports = { 
    logger, 
    securityLogger, 
    setDbHelpers, 
    sanitizeMeta,
    processDatabaseLogQueue 
};
