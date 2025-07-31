# SecureTask Testing Guide

## 🚀 Quick Start Testing

### Step 1: Administrator Login
1. Go to `http://localhost:3000`
2. Login with:
   - Username: `admin`
   - Password: `Admin123!`
3. **IMPORTANT:** Change the default password immediately!

### Step 2: Create Test Users

#### Create a Project Manager:
1. Navigate to `Dashboard > Manager Management`
2. Click "Create New Manager"
3. Enter:
   - Username: `manager1`
   - Password: `Manager123!`
4. Click "Create Manager"

#### Create an Employee (via Registration):
1. Logout (top-right menu)
2. Click "Register as Employee" 
3. Enter:
   - Username: `employee1`
   - Password: `Employee123!`
4. Register and login

### Step 3: Test Task Management

#### As Project Manager (manager1):
1. Login with manager1 credentials
2. Go to Dashboard
3. Click "Create New Task"
4. Fill in:
   - Title: "Complete project documentation"
   - Description: "Write comprehensive project docs"
   - Assign to: employee1
5. Submit task

#### As Employee (employee1):
1. Login with employee1 credentials
2. View assigned tasks on dashboard
3. Click task to view details
4. Mark task as "Completed"

### Step 4: Security Testing

#### Test Account Lockout:
1. Try logging in with wrong password 5 times
2. Observe account lockout message
3. Wait 15 minutes or continue with other tests

#### Test Role-based Access:
1. Login as employee1
2. Try accessing: `http://localhost:3000/admin`
3. Should see "Access denied" message

#### Test Rate Limiting:
1. Refresh login page rapidly (>100 times in 15 minutes)
2. Should see rate limiting message

### Step 5: Admin Monitoring

#### View System Logs:
1. Login as admin
2. Go to `Dashboard > System Logs`
3. Review all security events:
   - Login attempts
   - Failed authentications
   - Access violations
   - Task operations

## 🧪 Feature Testing Checklist

### Authentication ✅
- [ ] Login with correct credentials
- [ ] Login with wrong credentials
- [ ] Account lockout after 5 failed attempts
- [ ] Registration process
- [ ] Session timeout
- [ ] Logout functionality

### Authorization ✅
- [ ] Administrator access to all features
- [ ] Project Manager task creation
- [ ] Employee task viewing only
- [ ] Access denial for unauthorized routes
- [ ] Role-based navigation menus

### Task Management ✅
- [ ] Create tasks (Project Manager)
- [ ] View assigned tasks (Employee)
- [ ] Update task status (Employee)
- [ ] Delete tasks (Project Manager)
- [ ] Task assignment workflow

### Security Features ✅
- [ ] Password hashing (bcrypt)
- [ ] Session security
- [ ] CSRF protection
- [ ] Input validation
- [ ] SQL injection prevention
- [ ] XSS protection (Helmet.js)
- [ ] Rate limiting
- [ ] Security logging

### Data Validation ✅
- [ ] Username requirements (3-30 chars, alphanumeric)
- [ ] Password complexity (8+ chars, uppercase, lowercase, number, special)
- [ ] Task title validation
- [ ] Input sanitization

## 🔍 Database Inspection

To check the database directly:
```bash
sqlite3 database/securetask.db
.tables
SELECT * FROM users;
SELECT * FROM tasks;
SELECT * FROM system_logs;
.exit
```

## 🐛 Common Issues & Solutions

### Port Already in Use:
```bash
lsof -ti:3000 | xargs kill
npm start
```

### Database Issues:
```bash
rm database/securetask.db
npm start  # Will recreate with default admin
```

### Session Issues:
- Clear browser cookies for localhost:3000
- Restart server

## 📊 Expected Behavior

### Successful Operations:
- Clean redirects between pages
- Appropriate success messages
- Proper role-based content display
- Secure password handling

### Security Events (Check logs):
- All login attempts logged
- Failed authentication attempts
- Access denial events
- Task creation/modification events
- Administrative actions

## 🎯 Testing Scenarios

### Scenario 1: Complete Workflow
1. Admin creates manager
2. Manager creates tasks for employees
3. Employees complete tasks
4. Admin monitors via logs

### Scenario 2: Security Breach Simulation
1. Attempt SQL injection in forms
2. Try XSS attacks in task descriptions
3. Attempt unauthorized URL access
4. Check security logs for all events

### Scenario 3: User Management
1. Create multiple users of each type
2. Test task assignments between different users
3. Verify role permissions are correctly enforced

## 📈 Performance Testing

### Load Testing:
- Multiple simultaneous logins
- Concurrent task operations
- Database query performance
- Memory usage monitoring

### Security Testing:
- Brute force protection
- Session hijacking prevention
- CSRF attack prevention
- Input validation bypass attempts
