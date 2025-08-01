const express = require('express');
const { dbHelpers } = require('../database/init');
const { securityLogger } = require('../utils/logger');
const { validationSets, handleValidationErrors, injectValidationData } = require('../utils/validation');
const { authorizeRole } = require('../middleware/auth');

const router = express.Router();

// Apply validation data injection to all routes
router.use(injectValidationData);

// Main dashboard route
router.get('/', (req, res) => {
    const user = req.session.user;
    
    switch (user.role) {
        case 'Administrator':
            // Get system statistics for admin dashboard
            dbHelpers.getUserCounts((err, userCounts) => {
                if (err) {
                    securityLogger.error('Failed to fetch user counts for admin dashboard', {
                        username: user.username,
                        error: err.message
                    });
                    userCounts = [];
                }

                dbHelpers.getTotalTaskCount((err, taskCount) => {
                    if (err) {
                        securityLogger.error('Failed to fetch task count for admin dashboard', {
                            username: user.username,
                            error: err.message
                        });
                        taskCount = { count: 0 };
                    }

                    // Process user counts into a more usable format
                    const stats = {
                        totalUsers: 0,
                        administrators: 0,
                        projectManagers: 0,
                        employees: 0,
                        totalTasks: taskCount.count
                    };

                    userCounts.forEach(item => {
                        stats.totalUsers += item.count;
                        switch (item.role) {
                            case 'Administrator':
                                stats.administrators = item.count;
                                break;
                            case 'Project Manager':
                                stats.projectManagers = item.count;
                                break;
                            case 'Employee':
                                stats.employees = item.count;
                                break;
                        }
                    });

                    res.render('dashboard/admin', {
                        title: 'Administrator Dashboard - SecureTask',
                        user: user,
                        stats: stats
                    });
                });
            });
            break;
            
        case 'Project Manager':
            // Get employees for task assignment dropdown
            dbHelpers.getEmployees((err, employees) => {
                if (err) {
                    securityLogger.error('Failed to fetch employees for manager dashboard', {
                        username: user.username,
                        error: err.message
                    });
                    employees = [];
                }

                // Get tasks created by this manager
                dbHelpers.getTasksByCreator(user.id, (err, tasks) => {
                    if (err) {
                        securityLogger.error('Failed to fetch manager tasks', {
                            username: user.username,
                            error: err.message
                        });
                        tasks = [];
                    }

                    res.render('dashboard/manager', {
                        title: 'Project Manager Dashboard - SecureTask',
                        user: user,
                        employees: employees,
                        tasks: tasks
                    });
                });
            });
            break;
            
        case 'Employee':
            // Get tasks assigned to this employee
            dbHelpers.getTasksByAssignee(user.id, (err, tasks) => {
                if (err) {
                    securityLogger.error('Failed to fetch employee tasks', {
                        username: user.username,
                        error: err.message
                    });
                    tasks = [];
                }

                res.render('dashboard/employee', {
                    title: 'Employee Dashboard - SecureTask',
                    user: user,
                    tasks: tasks
                });
            });
            break;
            
        default:
            securityLogger.error('Unknown user role accessing dashboard', {
                username: user.username,
                role: user.role
            });
            res.status(403).render('error', {
                message: 'Access denied. Invalid user role.',
                user: user
            });
    }
});

// Create new task (Project Manager only)
router.post('/create-task',
    authorizeRole(['Project Manager']),
    validationSets.createTask,
    handleValidationErrors,
    (req, res) => {
        const { title, description, assignedTo, priority } = req.body;
        const user = req.session.user;

        // Verify that the assigned user is actually an Employee
        dbHelpers.getUserById(assignedTo, (err, assignedUser) => {
            if (err) {
                securityLogger.error('Database error checking assigned user', {
                    username: user.username,
                    error: err.message,
                    assignedTo
                });
                req.session.validationErrors = [{ msg: 'Failed to create task. Please try again.' }];
                return res.redirect('/dashboard');
            }

            if (!assignedUser || assignedUser.role !== 'Employee') {
                securityLogger.warn('Attempt to assign task to invalid user', {
                    username: user.username,
                    assignedTo,
                    assignedUserRole: assignedUser?.role
                });
                req.session.validationErrors = [{ msg: 'Please select a valid employee.' }];
                return res.redirect('/dashboard');
            }

            // Create the task
            dbHelpers.createTask(title, description, priority, user.id, assignedTo, function(err) {
                if (err) {
                    securityLogger.error('Failed to create task', {
                        username: user.username,
                        error: err.message,
                        taskTitle: title
                    });
                    req.session.validationErrors = [{ msg: 'Failed to create task. Please try again.' }];
                    return res.redirect('/dashboard');
                }

                securityLogger.info('Task created', {
                    username: user.username,
                    taskId: this.lastID,
                    taskTitle: title,
                    assignedTo: assignedUser.username
                });

                req.session.successMessage = 'Task created successfully!';
                res.redirect('/dashboard');
            });
        });
    }
);

// Update task status (Employee only)
router.post('/update-task-status',
    authorizeRole(['Employee']),
    (req, res) => {
        const { taskId, status } = req.body;
        const user = req.session.user;

        // Validate status
        if (!['Pending', 'Completed'].includes(status)) {
            securityLogger.warn('Invalid task status update attempt', {
                username: user.username,
                taskId,
                status
            });
            req.session.validationErrors = [{ msg: 'Invalid task status.' }];
            return res.redirect('/dashboard');
        }

        // Update task status (only if it's assigned to this user)
        dbHelpers.updateTaskStatus(taskId, status, user.id, function(err) {
            if (err) {
                securityLogger.error('Failed to update task status', {
                    username: user.username,
                    error: err.message,
                    taskId,
                    status
                });
                req.session.validationErrors = [{ msg: 'Failed to update task status. Please try again.' }];
                return res.redirect('/dashboard');
            }

            if (this.changes === 0) {
                securityLogger.warn('Unauthorized task status update attempt', {
                    username: user.username,
                    taskId,
                    status
                });
                req.session.validationErrors = [{ msg: 'You can only update tasks assigned to you.' }];
                return res.redirect('/dashboard');
            }

            securityLogger.info('Task status updated', {
                username: user.username,
                taskId,
                newStatus: status
            });

            req.session.successMessage = 'Task status updated successfully!';
            res.redirect('/dashboard');
        });
    }
);

// Reassign task (Project Manager only)
router.post('/reassign-task',
    authorizeRole(['Project Manager']),
    (req, res) => {
        const { taskId, newAssignedTo } = req.body;
        const user = req.session.user;

        if (!taskId || isNaN(parseInt(taskId))) {
            securityLogger.warn('Invalid task reassignment attempt', {
                username: user.username,
                taskId
            });
            req.session.validationErrors = [{ msg: 'Invalid task ID.' }];
            return res.redirect('/dashboard');
        }

        // Verify that the new assignee is actually an Employee
        dbHelpers.getUserById(newAssignedTo, (err, assignedUser) => {
            if (err) {
                securityLogger.error('Database error checking new assignee', {
                    username: user.username,
                    error: err.message,
                    newAssignedTo
                });
                req.session.validationErrors = [{ msg: 'Failed to reassign task. Please try again.' }];
                return res.redirect('/dashboard');
            }

            if (!assignedUser || assignedUser.role !== 'Employee') {
                securityLogger.warn('Attempt to reassign task to invalid user', {
                    username: user.username,
                    newAssignedTo,
                    assignedUserRole: assignedUser?.role
                });
                req.session.validationErrors = [{ msg: 'Please select a valid employee.' }];
                return res.redirect('/dashboard');
            }

            // Reassign the task (only if it was created by this user)
            dbHelpers.reassignTask(taskId, newAssignedTo, user.id, function(err) {
                if (err) {
                    securityLogger.error('Failed to reassign task', {
                        username: user.username,
                        error: err.message,
                        taskId,
                        newAssignedTo
                    });
                    req.session.validationErrors = [{ msg: 'Failed to reassign task. Please try again.' }];
                    return res.redirect('/dashboard');
                }

                if (this.changes === 0) {
                    securityLogger.warn('Unauthorized task reassignment attempt', {
                        username: user.username,
                        taskId,
                        newAssignedTo
                    });
                    req.session.validationErrors = [{ msg: 'You can only reassign tasks you created.' }];
                    return res.redirect('/dashboard');
                }

                securityLogger.info('Task reassigned', {
                    username: user.username,
                    taskId,
                    newAssignee: assignedUser.username
                });

                req.session.successMessage = 'Task reassigned successfully!';
                res.redirect('/dashboard');
            });
        });
    }
);

// Delete task (Project Manager only)
router.post('/delete-task',
    authorizeRole(['Project Manager']),
    (req, res) => {
        const { taskId } = req.body;
        const user = req.session.user;

        if (!taskId || isNaN(parseInt(taskId))) {
            securityLogger.warn('Invalid task deletion attempt', {
                username: user.username,
                taskId
            });
            req.session.validationErrors = [{ msg: 'Invalid task ID.' }];
            return res.redirect('/dashboard');
        }

        // Delete task (only if it was created by this user)
        dbHelpers.deleteTask(taskId, user.id, function(err) {
            if (err) {
                securityLogger.error('Failed to delete task', {
                    username: user.username,
                    error: err.message,
                    taskId
                });
                req.session.validationErrors = [{ msg: 'Failed to delete task. Please try again.' }];
                return res.redirect('/dashboard');
            }

            if (this.changes === 0) {
                securityLogger.warn('Unauthorized task deletion attempt', {
                    username: user.username,
                    taskId
                });
                req.session.validationErrors = [{ msg: 'You can only delete tasks you created.' }];
                return res.redirect('/dashboard');
            }

            securityLogger.info('Task deleted', {
                username: user.username,
                taskId
            });

            req.session.successMessage = 'Task deleted successfully!';
            res.redirect('/dashboard');
        });
    }
);

module.exports = router;
