#!/usr/bin/env node

/**
 * Test script to demonstrate last login tracking feature
 * This script will show how login attempts are tracked and displayed
 */

const bcrypt = require('bcrypt');
const { dbHelpers } = require('./database/init');

console.log('🔍 Testing Last Login Tracking Feature...');
console.log('=========================================');

// Create a test user if it doesn't exist
const testUsername = 'testuser';
const testPassword = 'TestPassword123!';

async function createTestUser() {
    return new Promise((resolve, reject) => {
        dbHelpers.getUserByUsername(testUsername, async (err, existingUser) => {
            if (err) {
                reject(err);
                return;
            }

            if (existingUser) {
                console.log(`✅ Test user '${testUsername}' already exists`);
                resolve(existingUser);
                return;
            }

            try {
                const passwordHash = await bcrypt.hash(testPassword, 12);
                dbHelpers.createUser(testUsername, passwordHash, 'Employee', function (err) {
                    if (err) {
                        reject(err);
                        return;
                    }
                    console.log(`✅ Created test user '${testUsername}' with password '${testPassword}'`);

                    // Get the created user
                    dbHelpers.getUserByUsername(testUsername, (err, user) => {
                        if (err) {
                            reject(err);
                            return;
                        }
                        resolve(user);
                    });
                });
            } catch (error) {
                reject(error);
            }
        });
    });
}

function simulateFailedLogin(username, ip) {
    return new Promise((resolve, reject) => {
        console.log(`\n🔴 Simulating failed login attempt for '${username}' from IP: ${ip}`);

        dbHelpers.updateLastFailedLogin(username, ip, (err) => {
            if (err) {
                reject(err);
                return;
            }
            console.log(`   ✅ Failed login attempt recorded`);
            resolve();
        });
    });
}

function simulateSuccessfulLogin(username, ip) {
    return new Promise((resolve, reject) => {
        console.log(`\n🟢 Simulating successful login for '${username}' from IP: ${ip}`);

        dbHelpers.updateLastLogin(username, ip, (err) => {
            if (err) {
                reject(err);
                return;
            }
            console.log(`   ✅ Successful login recorded`);
            resolve();
        });
    });
}

function checkUserLoginHistory(username) {
    return new Promise((resolve, reject) => {
        dbHelpers.getUserByUsername(username, (err, user) => {
            if (err) {
                reject(err);
                return;
            }

            console.log(`\n📊 Login History for '${username}':`);
            console.log('================================');

            if (user.last_login_at) {
                console.log(`   Last Successful Login: ${new Date(user.last_login_at).toLocaleString()}`);
                console.log(`   From IP: ${user.last_login_ip || 'Unknown'}`);
            } else {
                console.log('   No successful logins recorded yet');
            }

            if (user.last_failed_login_at) {
                console.log(`   Last Failed Login: ${new Date(user.last_failed_login_at).toLocaleString()}`);
                console.log(`   From IP: ${user.last_failed_login_ip || 'Unknown'}`);
            } else {
                console.log('   No failed login attempts recorded');
            }

            resolve(user);
        });
    });
}

async function runTest() {
    try {
        // Step 1: Create test user
        await createTestUser();

        // Step 2: Check initial state (should have no login history)
        await checkUserLoginHistory(testUsername);

        // Step 3: Simulate some failed login attempts
        await simulateFailedLogin(testUsername, '192.168.1.100');
        await checkUserLoginHistory(testUsername);

        await simulateFailedLogin(testUsername, '192.168.1.101');
        await checkUserLoginHistory(testUsername);

        // Step 4: Simulate successful login
        await simulateSuccessfulLogin(testUsername, '192.168.1.102');
        await checkUserLoginHistory(testUsername);

        // Step 5: Simulate another failed attempt after successful login
        await simulateFailedLogin(testUsername, '10.0.0.1');
        await checkUserLoginHistory(testUsername);

        // Step 6: Another successful login
        await simulateSuccessfulLogin(testUsername, '192.168.1.103');
        await checkUserLoginHistory(testUsername);

        console.log('\n🎉 Test completed successfully!');
        console.log('\n📝 How this works in the application:');
        console.log('=====================================');
        console.log('1. When a user logs in successfully, they will see:');
        console.log('   - Their last successful login date/time and IP');
        console.log('   - Their last failed login attempt (if any)');
        console.log('2. This helps users detect unauthorized access attempts');
        console.log('3. The information is displayed prominently on the dashboard');
        console.log('4. New users will see a welcome message for their first login');

        console.log('\n🚀 To test this feature:');
        console.log('1. Start the server: node server.js');
        console.log('2. Go to http://localhost:3000/login');
        console.log(`3. Try to login with wrong password for '${testUsername}'`);
        console.log(`4. Then login successfully with password: '${testPassword}'`);
        console.log('5. Check the dashboard for the login history display');

    } catch (error) {
        console.error('❌ Test failed:', error.message);
        process.exit(1);
    }
}

// Run the test
runTest();
