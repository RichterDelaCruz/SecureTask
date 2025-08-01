const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const dbPath = path.join(__dirname, 'securetask.db');
const db = new sqlite3.Database(dbPath);

// Initialize database schema
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('Administrator', 'Project Manager', 'Employee')),
        failed_attempts INTEGER DEFAULT 0,
        locked_until DATETIME NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tasks table
    db.run(`CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        priority TEXT DEFAULT 'Medium' CHECK (priority IN ('Low', 'Medium', 'High')),
        status TEXT DEFAULT 'Pending' CHECK (status IN ('Pending', 'Completed')),
        created_by INTEGER NOT NULL,
        assigned_to INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users (id),
        FOREIGN KEY (assigned_to) REFERENCES users (id)
    )`);

    // System logs table
    db.run(`CREATE TABLE IF NOT EXISTS system_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        username TEXT,
        ip_address TEXT,
        user_agent TEXT,
        additional_data TEXT
    )`);

    // Create default administrator account if it doesn't exist
    db.get("SELECT COUNT(*) as count FROM users WHERE role = 'Administrator'", (err, row) => {
        if (err) {
            console.error('Database error checking for admin user:', err.message);
            return;
        }

        if (row.count === 0) {
            const defaultAdminPassword = 'Admin123!'; // Should be changed on first login
            bcrypt.hash(defaultAdminPassword, 12, (err, hash) => {
                if (err) {
                    console.error('Error hashing default admin password:', err.message);
                    return;
                }

                db.run(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    ['admin', hash, 'Administrator'],
                    function(err) {
                        if (err) {
                            console.error('Error creating default admin user:', err.message);
                        } else {
                            console.log('Default administrator account created with username: admin, password: Admin123!');
                            console.log('IMPORTANT: Change the default password immediately after first login!');
                        }
                    }
                );
            });
        }
    });
});

// Database helper functions
const dbHelpers = {
    // User operations
    createUser: (username, passwordHash, role, callback) => {
        db.run(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            [username, passwordHash, role],
            callback
        );
    },

    getUserByUsername: (username, callback) => {
        db.get(
            "SELECT * FROM users WHERE username = ?",
            [username],
            callback
        );
    },

    getUserById: (id, callback) => {
        db.get(
            "SELECT * FROM users WHERE id = ?",
            [id],
            callback
        );
    },

    updateUserPassword: (userId, newPasswordHash, callback) => {
        db.run(
            "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            [newPasswordHash, userId],
            callback
        );
    },

    updateFailedAttempts: (username, attempts, lockedUntil, callback) => {
        db.run(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
            [attempts, lockedUntil, username],
            callback
        );
    },

    getEmployees: (callback) => {
        db.all(
            "SELECT id, username FROM users WHERE role = 'Employee' ORDER BY username",
            callback
        );
    },

    getManagers: (callback) => {
        db.all(
            "SELECT id, username, created_at FROM users WHERE role = 'Project Manager' ORDER BY username",
            callback
        );
    },

    deleteUser: (userId, callback) => {
        db.run(
            "DELETE FROM users WHERE id = ?",
            [userId],
            callback
        );
    },

    // Task operations
    createTask: (title, description, priority, createdBy, assignedTo, callback) => {
        db.run(
            "INSERT INTO tasks (title, description, priority, created_by, assigned_to) VALUES (?, ?, ?, ?, ?)",
            [title, description, priority, createdBy, assignedTo],
            callback
        );
    },

    getTasksByCreator: (creatorId, callback) => {
        db.all(`
            SELECT t.*, u.username as assigned_to_username 
            FROM tasks t 
            JOIN users u ON t.assigned_to = u.id 
            WHERE t.created_by = ? 
            ORDER BY t.created_at DESC
        `, [creatorId], callback);
    },

    getTasksByAssignee: (assigneeId, callback) => {
        db.all(`
            SELECT t.*, u.username as created_by_username 
            FROM tasks t 
            JOIN users u ON t.created_by = u.id 
            WHERE t.assigned_to = ? 
            ORDER BY t.created_at DESC
        `, [assigneeId], callback);
    },

    updateTaskStatus: (taskId, status, assigneeId, callback) => {
        db.run(
            "UPDATE tasks SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND assigned_to = ?",
            [status, taskId, assigneeId],
            callback
        );
    },

    reassignTask: (taskId, newAssigneeId, creatorId, callback) => {
        db.run(
            "UPDATE tasks SET assigned_to = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND created_by = ?",
            [newAssigneeId, taskId, creatorId],
            callback
        );
    },

    deleteTask: (taskId, creatorId, callback) => {
        db.run(
            "DELETE FROM tasks WHERE id = ? AND created_by = ?",
            [taskId, creatorId],
            callback
        );
    },

    // Logging operations
    insertLog: (level, message, username, ipAddress, userAgent, additionalData, callback) => {
        db.run(
            "INSERT INTO system_logs (level, message, username, ip_address, user_agent, additional_data) VALUES (?, ?, ?, ?, ?, ?)",
            [level, message, username, ipAddress, userAgent, additionalData],
            callback || (() => {})
        );
    },

    getLogs: (callback) => {
        db.all(
            "SELECT * FROM system_logs ORDER BY timestamp DESC LIMIT 1000",
            callback
        );
    },

    // Statistics operations
    getUserCounts: (callback) => {
        db.all(`
            SELECT 
                role,
                COUNT(*) as count
            FROM users 
            GROUP BY role
        `, callback);
    },

    getTotalTaskCount: (callback) => {
        db.get(
            "SELECT COUNT(*) as count FROM tasks",
            callback
        );
    }
};

module.exports = { db, dbHelpers };
