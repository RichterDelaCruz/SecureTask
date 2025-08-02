const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const dbPath = path.join(__dirname, 'database', 'securetask.db');
const db = new sqlite3.Database(dbPath);

console.log('Setting admin password with current timestamp to test age restriction...\n');

// Hash the password
bcrypt.hash('admin123', 12, (err, hash) => {
    if (err) {
        console.error('Error hashing password:', err.message);
        process.exit(1);
    }

    // Update the admin user's password with current timestamp
    db.run(
        "UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP WHERE username = 'admin'",
        [hash],
        function(err) {
            if (err) {
                console.error('Error updating admin password:', err.message);
                process.exit(1);
            }
            
            console.log('✅ Admin password updated with current timestamp');
            
            // Now check the age restriction
            db.get(
                `SELECT username, password_changed_at, 
                        datetime(password_changed_at, '+1 day') as next_allowed_change,
                        datetime(password_changed_at, '+1 day') <= datetime('now') as can_change
                 FROM users WHERE username = 'admin'`,
                (err, user) => {
                    if (err) {
                        console.error('Error checking user:', err.message);
                        db.close();
                        return;
                    }

                    console.log('\nPassword age status after update:');
                    console.log(`- Password changed at: ${user.password_changed_at}`);
                    console.log(`- Next allowed change: ${user.next_allowed_change}`);
                    console.log(`- Can change password now: ${user.can_change ? 'YES' : 'NO'}`);

                    if (!user.can_change) {
                        const passwordChangedAt = new Date(user.password_changed_at);
                        const nextAllowedChange = new Date(passwordChangedAt.getTime() + 24 * 60 * 60 * 1000);
                        const timeRemaining = Math.ceil((nextAllowedChange - new Date()) / (60 * 60 * 1000));
                        console.log(`- Hours remaining until next change allowed: ${timeRemaining}`);
                        console.log('\n🔒 Password age restriction is ACTIVE and preventing changes');
                    } else {
                        console.log('\n✅ Password can be changed (more than 24 hours old)');
                    }

                    db.close();
                }
            );
        }
    );
});
