#!/bin/bash

echo "🔐 Testing Authentication Redirects for Protected Routes"
echo "======================================================"
echo ""

BASE_URL="http://localhost:3000"

# Function to test that protected routes redirect to login
test_auth_redirect() {
    local route="$1"
    local description="$2"
    
    echo "Testing: $description"
    echo "Route: $route"
    
    # Make request without any session/cookies (simulate incognito/fresh browser)
    response=$(curl -s -w "%{http_code}|%{redirect_url}" -o /dev/null "$BASE_URL$route")
    
    status_code=$(echo "$response" | cut -d'|' -f1)
    redirect_url=$(echo "$response" | cut -d'|' -f2)
    
    if [ "$status_code" = "302" ]; then
        # Get the actual redirect location
        location=$(curl -s -I "$BASE_URL$route" | grep -i "location:" | cut -d' ' -f2 | tr -d '\r')
        
        if [[ "$location" == *"/login"* ]]; then
            echo "✅ PASS - Correctly redirects to login"
        else
            echo "❌ FAIL - Redirects to: $location (expected /login)"
        fi
    else
        echo "❌ FAIL - Status: $status_code (expected 302 redirect)"
    fi
    echo ""
}

echo "Testing protected routes that should redirect to login:"
echo "-----------------------------------------------------"

# Test main protected routes
test_auth_redirect "/dashboard" "Dashboard (main user interface)"
test_auth_redirect "/dashboard/admin" "Admin Dashboard"
test_auth_redirect "/dashboard/manager" "Manager Dashboard"
test_auth_redirect "/dashboard/employee" "Employee Dashboard"

test_auth_redirect "/account/change-password" "Account Settings - Change Password"

test_auth_redirect "/admin/managers" "Admin - Manager Management"
test_auth_redirect "/admin/logs" "Admin - System Logs"

echo "Testing routes that should NOT require authentication:"
echo "---------------------------------------------------"

# Test public routes
echo "Testing: Login page (should be accessible)"
echo "Route: /login"
response=$(curl -s -w "%{http_code}" -o /dev/null "$BASE_URL/login")
if [ "$response" = "200" ]; then
    echo "✅ PASS - Login page accessible without authentication"
else
    echo "❌ FAIL - Login page status: $response (expected 200)"
fi
echo ""

echo "Testing: Register page (should be accessible)"
echo "Route: /register"
response=$(curl -s -w "%{http_code}" -o /dev/null "$BASE_URL/register")
if [ "$response" = "200" ]; then
    echo "✅ PASS - Register page accessible without authentication"
else
    echo "❌ FAIL - Register page status: $response (expected 200)"
fi
echo ""

echo "Testing: Root redirect (should redirect to login when not authenticated)"
echo "Route: /"
location=$(curl -s -I "$BASE_URL/" | grep -i "location:" | cut -d' ' -f2 | tr -d '\r')
if [[ "$location" == *"/login"* ]]; then
    echo "✅ PASS - Root correctly redirects to login"
else
    echo "❌ FAIL - Root redirects to: $location (expected /login)"
fi
echo ""

echo ""
echo "🌐 Manual Incognito Testing Instructions:"
echo "========================================"
echo "1. Open a new incognito/private browsing window"
echo "2. Try accessing these URLs directly:"
echo ""
echo "❌ Protected routes (should redirect to login):"
echo "   • http://localhost:3000/dashboard"
echo "   • http://localhost:3000/account/change-password"
echo "   • http://localhost:3000/admin/managers"
echo "   • http://localhost:3000/admin/logs"
echo ""
echo "✅ Public routes (should work directly):"
echo "   • http://localhost:3000/login"
echo "   • http://localhost:3000/register"
echo ""
echo "Expected behavior:"
echo "- Protected routes should immediately redirect to login page"
echo "- URL bar should show http://localhost:3000/login after redirect"
echo "- No content from protected pages should be visible"
echo "- After login, user should be able to access protected routes"
echo ""
echo "🔄 Session Testing:"
echo "=================="
echo "1. Login normally in the browser"
echo "2. Access dashboard (should work)"
echo "3. Close all browser windows"
echo "4. Open new browser window"
echo "5. Try accessing dashboard again (should redirect to login)"
