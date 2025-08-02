# SecureTask - Secure Web Application

A minimalist, role-based web application designed for internal teams to manage projects and tasks with robust security controls.

## Features

### Security Controls
- **Authentication**: Salted password hashing (bcrypt), generic login errors, account lockout
- **Authorization**: Role-based access control with three distinct user roles
- **Input Validation**: Comprehensive validation with rejection-based approach
- **Security Logging**: Comprehensive audit logging of all security-sensitive events
- **Error Handling**: Custom error pages with no technical information exposure

### User Roles

#### Administrator
- Create, view, and delete Project Manager accounts
- View comprehensive audit logs
- Change own password
- Cannot manage tasks directly

#### Project Manager
- Create new tasks
- View all tasks they created
- Assign/reassign tasks to Employee users
- Delete tasks they created
- View list of Employee users
- Change own password

#### Employee
- View tasks assigned to them
- Change task status (Pending/Completed)
- Change own password
- Cannot view other employees' tasks

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd SecureTask
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the application**
   ```bash
   npm start
   ```
   
   For development with auto-restart:
   ```bash
   npm run dev
   ```

4. **Access the application**
   Open your browser to `http://localhost:3000`

## Default Credentials

**Administrator Account:**
- Username: `admin`
- Password: `Admin123!`

⚠️ **IMPORTANT**: Change the default administrator password immediately after first login!

## Environment Variables

For production deployment, set the following environment variables:

- `SESSION_SECRET`: A strong, unique secret for session encryption
- `PORT`: Application port (default: 3000)

## Security Features

### Password Requirements
- Minimum 6 characters
- Must contain at least one letter
- Must contain at least one number

### Account Lockout
- Accounts are locked for 15 minutes after 5 failed login attempts
- Failed attempts are reset upon successful login

### Session Security
- HTTP-only cookies
- 24-hour session timeout
- Secure session configuration

### Input Validation
- Server-side validation for all user inputs
- Length limits and format validation
- Rejection-based approach (no sanitization)

### Audit Logging
- All authentication events
- Authorization failures
- Administrative actions
- Task management operations
- Accessible only to Administrators

## Application Structure

```
SecureTask/
├── server.js                 # Main application server
├── package.json             # Node.js dependencies
├── database/
│   └── init.js              # Database schema and helpers
├── middleware/
│   └── auth.js              # Authentication and authorization
├── routes/
│   ├── auth.js              # Authentication routes
│   ├── dashboard.js         # Main dashboard routes
│   ├── admin.js             # Administrator routes
│   └── account.js           # Account management routes
├── utils/
│   ├── logger.js            # Security logging utility
│   └── validation.js        # Input validation helpers
├── views/
│   ├── layout.ejs           # Main template layout
│   ├── login.ejs            # Login page
│   ├── register.ejs         # Registration page
│   ├── error.ejs            # Error page
│   ├── dashboard/           # Role-specific dashboards
│   ├── admin/               # Administrator pages
│   └── account/             # Account management pages
└── logs/                    # Application log files
```

## Security Considerations

1. **Database**: Uses SQLite with parameterized queries to prevent SQL injection
2. **Sessions**: Secure session configuration with HTTP-only cookies
3. **Headers**: Security headers via Helmet.js
4. **Rate Limiting**: Protection against brute force attacks
5. **Input Validation**: Comprehensive validation with explicit rejection of malicious content
6. **Error Handling**: Generic error messages to prevent information disclosure
7. **Logging**: Comprehensive audit trail for security analysis

## Development Notes

- Built with Node.js, Express.js, and SQLite
- Uses EJS templating engine
- Bootstrap 5 for responsive UI
- Font Awesome for icons
- bcrypt for password hashing
- Winston for logging

## Production Deployment

1. Set environment variables (especially `SESSION_SECRET`)
2. Use HTTPS (set session `secure: true`)
3. Configure proper database permissions
4. Set up log rotation
5. Monitor audit logs regularly
6. Keep dependencies updated

## License

This project is for educational purposes as part of the CSSECDV course.
