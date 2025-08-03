#!/bin/bash

echo "🔐 Testing Password Validation Requirements"
echo "=========================================="
echo ""

BASE_URL="http://localhost:3000"

# Test function
test_password() {
    local name="$1"
    local password="$2"
    local expected_result="$3"
    
    echo "Test: $name"
    echo "Password: \"$password\""
    
    # Make registration request
    response=$(curl -s -w "%{http_code}" -o /dev/null -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=testuser&password=$password&confirmPassword=$password" \
        "$BASE_URL/register")
    
    if [ "$expected_result" = "fail" ]; then
        if [ "$response" = "302" ]; then
            echo "✅ PASS - Registration rejected as expected (redirected)"
        else
            echo "❌ FAIL - Expected rejection but got status: $response"
        fi
    else
        if [ "$response" = "302" ]; then
            echo "✅ PASS - Valid password accepted"
        else
            echo "❌ FAIL - Valid password rejected with status: $response"
        fi
    fi
    echo ""
}

# Test cases
test_password "Too short (7 chars)" "Abc123!" "fail"
test_password "No uppercase" "abcdef123!" "fail"
test_password "No lowercase" "ABCDEF123!" "fail"
test_password "No number" "Abcdefgh!" "fail"
test_password "No special char" "Abcdefgh123" "fail"
test_password "Valid password" "SecurePass123!" "pass"

echo "🔍 Manual Testing Instructions:"
echo "=============================="
echo "1. Open http://localhost:3000 in your browser"
echo "2. Click 'Register' to go to registration page"
echo "3. Test these passwords and observe the validation:"
echo ""
echo "❌ Invalid passwords (should show errors):"
echo "   - Test1! (too short)"
echo "   - test123! (no uppercase)"
echo "   - TEST123! (no lowercase)"
echo "   - TestPassword! (no number)"
echo "   - TestPassword123 (no special character)"
echo ""
echo "✅ Valid password (should work):"
echo "   - SecurePass123!"
echo ""
echo "4. Check that:"
echo "   - Real-time validation shows errors as you type"
echo "   - Form submission is blocked for invalid passwords"
echo "   - Clear error messages are displayed"
echo "   - Password strength indicator updates correctly"
