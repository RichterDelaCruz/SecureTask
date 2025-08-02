const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const dbPath = path.join(__dirname, 'database', 'securetask.db');
const db = new sqlite3.Database(dbPath);

const newPassword = 'Admin123!';

console.log('Resetting admin password...');

// Hash the new password
bcrypt.hash(newPassword, 12, (err, hash) => {
    if (err) {
        console.error('Error hashing password:', err.message);
        process.exit(1);
    }

    // Update the admin user's password
    db.run(
        "UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE username = 'admin'",
        [hash],
        function(err) {
            if (err) {
                console.error('Error updating admin password:', err.message);
                process.exit(1);
            }
            
            if (this.changes === 0) {
                console.log('No admin user found to update');
            } else {
                console.log('Admin password successfully reset to: Admin123!');
                console.log('Username: admin');
                console.log('Password: Admin123!');
                console.log('Account unlocked and failed attempts reset to 0');
            }
            
            db.close();
        }
    );
});
