#!/bin/bash

# Test script to verify password age restriction error is displayed
echo "Testing password age restriction error display..."

# Get the current date and time for comparison
echo "Current time: $(date)"

# Test by attempting to change password twice in a row
# This script assumes you have a user account that can login

echo "Manual test steps:"
echo "1. Login to the application at http://localhost:3000"
echo "2. Go to Account -> Change Password"
echo "3. Change your password successfully"
echo "4. Immediately try to change the password again"
echo "5. You should now see the error message: 'Password was changed recently. You must wait at least 24 hours between password changes. Try again in X hour(s).'"

echo ""
echo "If the error message appears in the UI alert (red box), the fix is working correctly."
echo "If no error message appears, there's still an issue with the session handling."
