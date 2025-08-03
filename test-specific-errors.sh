#!/bin/bash

echo "🔐 Testing Specific Password Validation Error Messages"
echo "===================================================="
echo ""

BASE_URL="http://localhost:3000"

# Function to test password validation and extract error messages
test_password_errors() {
    local name="$1"
    local password="$2"
    local expected_error="$3"
    
    echo "Test: $name"
    echo "Password: \"$password\""
    echo "Expected error: $expected_error"
    
    # Make registration request and capture full response
    response=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=testuser&password=$password&confirmPassword=$password" \
        "$BASE_URL/register" -L)
    
    # Check if the expected error message appears in the response
    if echo "$response" | grep -q "$expected_error"; then
        echo "✅ PASS - Correct error message displayed"
    else
        echo "❌ FAIL - Expected error message not found"
        echo "Response contains: $(echo "$response" | grep -i error | head -1)"
    fi
    echo ""
}

echo "Testing individual password requirements:"
echo "----------------------------------------"

# Test each specific requirement
test_password_errors "Too short" "Test1!" "8 characters"
test_password_errors "No uppercase" "test123!" "uppercase letter"  
test_password_errors "No lowercase" "TEST123!" "lowercase letter"
test_password_errors "No number" "TestPassword!" "one number"
test_password_errors "No special char" "TestPassword123" "special character"

echo ""
echo "🌐 Manual Browser Testing:"
echo "=========================="
echo "1. Open http://localhost:3000 in your browser"
echo "2. Click 'Register'"
echo "3. Try typing these passwords and watch for real-time errors:"
echo ""
echo "❌ Test passwords that should show specific errors:"
echo "   • 'Test1!' → Should show 'must be at least 8 characters'"
echo "   • 'test123!' → Should show 'must contain uppercase letter'"  
echo "   • 'TEST123!' → Should show 'must contain lowercase letter'"
echo "   • 'TestPassword!' → Should show 'must contain one number'"
echo "   • 'TestPassword123' → Should show 'must contain special character'"
echo ""
echo "✅ Valid password that should work:"
echo "   • 'SecurePass123!'"
echo ""
echo "Expected behavior:"
echo "- Error messages appear immediately as you type"
echo "- Each error is specific to what's missing"
echo "- Multiple errors can be shown if multiple requirements are missing"
echo "- Form cannot be submitted until all requirements are met"
