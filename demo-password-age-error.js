const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'database', 'securetask.db');
const db = new sqlite3.Database(dbPath);

console.log('🔍 DEMONSTRATING PASSWORD AGE ERROR MESSAGE');
console.log('============================================\n');

// Get the current password status for admin user
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

        console.log('Current Status:');
        console.log(`- Username: ${user.username}`);
        console.log(`- Password changed at: ${user.password_changed_at}`);
        console.log(`- Next allowed change: ${user.next_allowed_change}`);
        console.log(`- Can change now: ${user.can_change ? 'YES' : 'NO'}\n`);

        if (!user.can_change) {
            // Calculate the exact error message that would be shown to the user
            const passwordChangedAt = new Date(user.password_changed_at);
            const nextAllowedChange = new Date(passwordChangedAt.getTime() + 24 * 60 * 60 * 1000);
            const timeRemaining = Math.ceil((nextAllowedChange - new Date()) / (60 * 60 * 1000));
            
            console.log('🚫 PASSWORD CHANGE BLOCKED');
            console.log('==========================');
            console.log('');
            console.log('If the user tries to change their password right now,');
            console.log('they would see this error message on the web page:');
            console.log('');
            console.log('┌─────────────────────────────────────────────────────────┐');
            console.log('│ ⚠️  ERROR                                                │');
            console.log('│                                                         │');
            console.log(`│ Password was changed recently. You must wait at least   │`);
            console.log(`│ 24 hours between password changes. Try again in        │`);
            console.log(`│ ${timeRemaining} hour(s).                                             │`);
            console.log('└─────────────────────────────────────────────────────────┘');
            console.log('');
            console.log('📋 This error message will appear:');
            console.log('   • In a red alert box on the password change form');
            console.log('   • The form will remain visible but not process the change');
            console.log('   • User can see exactly how many hours to wait');
            console.log('   • Security event is logged for audit purposes');
        } else {
            console.log('✅ Password change would be ALLOWED');
            console.log('   (Password is more than 24 hours old)');
        }

        console.log('\n🔒 SECURITY BENEFIT:');
        console.log('This prevents users from rapidly cycling through passwords');
        console.log('to bypass password history restrictions and reuse old passwords.');

        db.close();
    }
);
