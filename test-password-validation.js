#!/usr/bin/env node

const axios = require('axios');

async function testPasswordValidation() {
    console.log('🔐 Testing Password Validation Requirements');
    console.log('==========================================\n');

    const baseURL = 'http://localhost:3000';

    // Test cases for password validation
    const testCases = [
        {
            name: 'Too short (7 characters)',
            password: 'Abc123!',
            confirmPassword: 'Abc123!',
            shouldFail: true,
            expectedError: 'at least 8 characters'
        },
        {
            name: 'No uppercase letter',
            password: 'abcdef123!',
            confirmPassword: 'abcdef123!',
            shouldFail: true,
            expectedError: 'uppercase letter'
        },
        {
            name: 'No lowercase letter',
            password: 'ABCDEF123!',
            confirmPassword: 'ABCDEF123!',
            shouldFail: true,
            expectedError: 'lowercase letter'
        },
        {
            name: 'No number',
            password: 'Abcdefgh!',
            confirmPassword: 'Abcdefgh!',
            shouldFail: true,
            expectedError: 'one number'
        },
        {
            name: 'No special character',
            password: 'Abcdefgh123',
            confirmPassword: 'Abcdefgh123',
            shouldFail: true,
            expectedError: 'special character'
        },
        {
            name: 'Valid password (meets all requirements)',
            password: 'SecurePass123!',
            confirmPassword: 'SecurePass123!',
            shouldFail: false,
            expectedError: null
        }
    ];

    for (let i = 0; i < testCases.length; i++) {
        const testCase = testCases[i];
        console.log(`Test ${i + 1}: ${testCase.name}`);
        console.log(`Password: "${testCase.password}"`);

        try {
            const response = await axios.post(`${baseURL}/register`, {
                username: `testuser${i}`,
                password: testCase.password,
                confirmPassword: testCase.confirmPassword
            }, {
                maxRedirects: 0,
                validateStatus: () => true // Accept all status codes
            });

            if (testCase.shouldFail) {
                if (response.status === 302 && response.headers.location === '/register') {
                    console.log('✅ PASS - Registration rejected as expected');
                } else {
                    console.log('❌ FAIL - Registration should have been rejected');
                }
            } else {
                if (response.status === 302 && response.headers.location === '/login') {
                    console.log('✅ PASS - Valid password accepted');
                } else {
                    console.log('❌ FAIL - Valid password should have been accepted');
                }
            }
        } catch (error) {
            console.log(`❌ ERROR - Network error: ${error.message}`);
        }

        console.log('');
    }

    console.log('\n🔍 Manual Testing Instructions:');
    console.log('==============================');
    console.log('1. Open http://localhost:3000 in your browser');
    console.log('2. Go to Register page');
    console.log('3. Try entering passwords that don\'t meet requirements:');
    console.log('   - Less than 8 characters: "Test1!"');
    console.log('   - No uppercase: "test123!"');
    console.log('   - No lowercase: "TEST123!"');
    console.log('   - No number: "TestPassword!"');
    console.log('   - No special char: "TestPassword123"');
    console.log('4. Try a valid password: "SecurePass123!"');
    console.log('5. Verify error messages appear immediately as you type');
    console.log('6. Verify form submission is blocked for invalid passwords');
}

// Run the tests
testPasswordValidation().catch(console.error);
