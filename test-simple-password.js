const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const dbPath = path.join(__dirname, 'database', 'securetask.db');
const db = new sqlite3.Database(dbPath);

// Test with a simpler password that meets the new requirements
const newPassword = 'admin123'; // 8 chars, has letters and numbers

console.log('Setting admin password to simpler format (admin123)...');

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
                console.log('Admin password successfully updated to: admin123');
                console.log('Username: admin');
                console.log('Password: admin123');
                console.log('Account unlocked and failed attempts reset to 0');
                console.log('\nThis password meets the new relaxed requirements:');
                console.log('✅ At least 6 characters (8)');
                console.log('✅ Contains letters (admin)');
                console.log('✅ Contains numbers (123)');
            }
            
            db.close();
        }
    );
});
