#!/bin/bash

# SecureTask Demo Script
echo "🚀 SecureTask Application Demo"
echo "================================"
echo ""

# Check if server is running
if ! lsof -i:3000 >/dev/null 2>&1; then
    echo "❌ Server not running on port 3000"
    echo "Please run: npm start"
    exit 1
fi

echo "✅ Server is running on http://localhost:3000"
echo ""

# Show current users
echo "👥 Current Users in Database:"
echo "================================"
sqlite3 securetask.db "SELECT '👑 ' || username || ' (' || role || ')' FROM users;"
echo ""

# Show current tasks
echo "📋 Current Tasks:"
echo "================================"
TASK_COUNT=$(sqlite3 securetask.db "SELECT COUNT(*) FROM tasks;")
if [ "$TASK_COUNT" -eq 0 ]; then
    echo "No tasks found. Create some through the web interface!"
else
    sqlite3 securetask.db "SELECT '📝 ' || title || ' - Status: ' || status FROM tasks;"
fi
echo ""

# Show recent logs
echo "📊 Recent Security Events:"
echo "================================"
sqlite3 securetask.db "SELECT datetime(timestamp, 'localtime') || ' - ' || level || ': ' || message FROM system_logs ORDER BY timestamp DESC LIMIT 5;"
echo ""

echo "🌐 Web Interface URLs:"
echo "================================"
echo "Login Page:      http://localhost:3000"
echo "Dashboard:       http://localhost:3000/dashboard"
echo "Admin Panel:     http://localhost:3000/admin"
echo "Account Settings: http://localhost:3000/account"
echo ""

echo "🔐 Default Credentials:"
echo "================================"
echo "Administrator:"
echo "  Username: admin"
echo "  Password: Admin123!"
echo ""
echo "⚠️  IMPORTANT: Change the default password after first login!"
echo ""

echo "🧪 Quick Test Commands:"
echo "================================"
echo "1. View all users:     sqlite3 securetask.db 'SELECT * FROM users;'"
echo "2. View all tasks:     sqlite3 securetask.db 'SELECT * FROM tasks;'"
echo "3. View security logs: sqlite3 securetask.db 'SELECT * FROM system_logs;'"
echo "4. Clear database:     rm securetask.db && npm start"
echo ""

echo "✨ Ready to test! Open http://localhost:3000 in your browser"
