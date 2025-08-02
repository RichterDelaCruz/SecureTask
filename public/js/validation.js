/**
 * Client-side validation for SecureTask
 * This provides immediate feedback to users and prevents unnecessary server requests
 * Note: This is NOT a security measure - all validation must be done server-side
 */

class ClientValidation {
    constructor() {
        this.patterns = {
            username: /^[a-zA-Z0-9_]{3,20}$/,
            password: /^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z\d@$!%*?&#+\-_=[\]{}|\\:";'<>?,./]{6,128}$/,
            email: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
            phone: /^[\+]?[1-9][\d]{0,15}$/,
            date: /^\d{4}-\d{2}-\d{2}$/,
            time: /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/,
            url: /^https?:\/\/(?:[-\w.])+(?:\:[0-9]+)?(?:\/(?:[\w\._~!$&'()*+,;=:@]|%[\da-fA-F]{2})*)*(?:\?(?:[\w\._~!$&'()*+,;=:@/?]|%[\da-fA-F]{2})*)?(?:\#(?:[\w\._~!$&'()*+,;=:@/?]|%[\da-fA-F]{2})*)?$/
        };
        
        this.limits = {
            username: { min: 3, max: 20 },
            password: { min: 6, max: 128 },
            taskTitle: { min: 1, max: 100 },
            taskDescription: { min: 0, max: 500 },
            email: { min: 5, max: 254 },
            phone: { min: 7, max: 15 },
            url: { min: 10, max: 2048 },
            comment: { min: 1, max: 2000 }
        };
        
        this.commonPasswords = [
            'password', '12345678', 'qwerty123', 'admin123', 'password123',
            'letmein', 'welcome', 'monkey', '1234567890', 'password1',
            'abc123', 'qwerty', '123456789', 'welcome123'
        ];
        
        this.init();
    }
    
    init() {
        // Initialize validation on DOM load
        document.addEventListener('DOMContentLoaded', () => {
            this.attachValidationListeners();
            this.enhanceFormSubmission();
        });
    }
    
    attachValidationListeners() {
        // Username validation
        const usernameInputs = document.querySelectorAll('input[name="username"]');
        usernameInputs.forEach(input => {
            this.addRealTimeValidation(input, this.validateUsername.bind(this));
        });
        
        // Password validation
        const passwordInputs = document.querySelectorAll('input[name="password"]');
        passwordInputs.forEach(input => {
            this.addRealTimeValidation(input, this.validatePassword.bind(this));
            this.addPasswordStrengthIndicator(input);
        });
        
        // Confirm password validation
        const confirmPasswordInputs = document.querySelectorAll('input[name="confirmPassword"]');
        confirmPasswordInputs.forEach(input => {
            this.addRealTimeValidation(input, this.validateConfirmPassword.bind(this));
        });
        
        // Email validation
        const emailInputs = document.querySelectorAll('input[type="email"], input[name="email"]');
        emailInputs.forEach(input => {
            this.addRealTimeValidation(input, this.validateEmail.bind(this));
        });
        
        // Phone validation
        const phoneInputs = document.querySelectorAll('input[type="tel"], input[name="phone"]');
        phoneInputs.forEach(input => {
            this.addRealTimeValidation(input, this.validatePhone.bind(this));
        });
        
        // Task title validation
        const titleInputs = document.querySelectorAll('input[name="title"]');
        titleInputs.forEach(input => {
            this.addRealTimeValidation(input, this.validateTaskTitle.bind(this));
        });
        
        // Task description validation
        const descriptionInputs = document.querySelectorAll('textarea[name="description"]');
        descriptionInputs.forEach(input => {
            this.addRealTimeValidation(input, this.validateTaskDescription.bind(this));
            this.addCharacterCounter(input, this.limits.taskDescription.max);
        });
        
        // URL validation
        const urlInputs = document.querySelectorAll('input[type="url"], input[name="url"]');
        urlInputs.forEach(input => {
            this.addRealTimeValidation(input, this.validateURL.bind(this));
        });
        
        // Date validation
        const dateInputs = document.querySelectorAll('input[type="date"], input[name="date"]');
        dateInputs.forEach(input => {
            this.addRealTimeValidation(input, this.validateDate.bind(this));
        });
    }
    
    addRealTimeValidation(input, validator) {
        const showError = (message) => {
            this.showFieldError(input, message);
        };
        
        const hideError = () => {
            this.hideFieldError(input);
        };
        
        input.addEventListener('blur', () => {
            try {
                validator(input.value);
                hideError();
            } catch (error) {
                showError(error.message);
            }
        });
        
        input.addEventListener('input', () => {
            // Hide error on input to provide immediate feedback
            if (this.hasFieldError(input)) {
                hideError();
            }
        });
    }
    
    validateUsername(value) {
        if (!value) {
            throw new Error('Username is required');
        }
        
        if (value.length < this.limits.username.min || value.length > this.limits.username.max) {
            throw new Error(`Username must be ${this.limits.username.min}-${this.limits.username.max} characters long`);
        }
        
        if (!this.patterns.username.test(value)) {
            throw new Error('Username can only contain letters, numbers, and underscores');
        }
        
        return true;
    }
    
    validatePassword(value) {
        if (!value) {
            throw new Error('Password is required');
        }
        
        if (value.length < this.limits.password.min) {
            throw new Error(`Password must be at least ${this.limits.password.min} characters long`);
        }
        
        if (value.length > this.limits.password.max) {
            throw new Error(`Password must not exceed ${this.limits.password.max} characters`);
        }
        
        if (!this.patterns.password.test(value)) {
            throw new Error('Password must contain at least one letter and one number');
        }
        
        // Check for common passwords
        const lowerValue = value.toLowerCase();
        if (this.commonPasswords.some(common => lowerValue.includes(common))) {
            throw new Error('Password contains common patterns');
        }
        
        // Check for repeated characters
        if (/(.)\1{3,}/.test(value)) {
            throw new Error('Password cannot contain more than 3 consecutive identical characters');
        }
        
        return true;
    }
    
    validateConfirmPassword(value) {
        const passwordInput = document.querySelector('input[name="password"]');
        if (!passwordInput) return true;
        
        if (!value) {
            throw new Error('Password confirmation is required');
        }
        
        if (value !== passwordInput.value) {
            throw new Error('Passwords do not match');
        }
        
        return true;
    }
    
    validateEmail(value) {
        if (!value) {
            throw new Error('Email is required');
        }
        
        if (value.length < this.limits.email.min || value.length > this.limits.email.max) {
            throw new Error(`Email must be ${this.limits.email.min}-${this.limits.email.max} characters long`);
        }
        
        if (!this.patterns.email.test(value)) {
            throw new Error('Please enter a valid email address');
        }
        
        return true;
    }
    
    validatePhone(value) {
        if (!value) return true; // Optional field
        
        const cleaned = value.replace(/[^\d+]/g, '');
        
        if (cleaned.length < this.limits.phone.min || cleaned.length > this.limits.phone.max) {
            throw new Error(`Phone number must be ${this.limits.phone.min}-${this.limits.phone.max} digits long`);
        }
        
        if (!this.patterns.phone.test(cleaned)) {
            throw new Error('Please enter a valid phone number');
        }
        
        return true;
    }
    
    validateTaskTitle(value) {
        if (!value) {
            throw new Error('Task title is required');
        }
        
        if (value.length < this.limits.taskTitle.min || value.length > this.limits.taskTitle.max) {
            throw new Error(`Task title must be ${this.limits.taskTitle.min}-${this.limits.taskTitle.max} characters long`);
        }
        
        return true;
    }
    
    validateTaskDescription(value) {
        if (value && value.length > this.limits.taskDescription.max) {
            throw new Error(`Task description must not exceed ${this.limits.taskDescription.max} characters`);
        }
        
        return true;
    }
    
    validateURL(value) {
        if (!value) return true; // Optional field
        
        if (value.length < this.limits.url.min || value.length > this.limits.url.max) {
            throw new Error(`URL must be ${this.limits.url.min}-${this.limits.url.max} characters long`);
        }
        
        if (!this.patterns.url.test(value)) {
            throw new Error('Please enter a valid HTTP or HTTPS URL');
        }
        
        return true;
    }
    
    validateDate(value) {
        if (!value) return true; // Optional field
        
        if (!this.patterns.date.test(value)) {
            throw new Error('Please enter a valid date (YYYY-MM-DD)');
        }
        
        const date = new Date(value);
        if (isNaN(date.getTime())) {
            throw new Error('Please enter a valid date');
        }
        
        // Check if date is in the future (for due dates)
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        if (date < today) {
            throw new Error('Date cannot be in the past');
        }
        
        return true;
    }
    
    addPasswordStrengthIndicator(passwordInput) {
        const container = passwordInput.parentNode;
        const strengthIndicator = document.createElement('div');
        strengthIndicator.className = 'password-strength';
        strengthIndicator.innerHTML = `
            <div class="strength-bar">
                <div class="strength-fill"></div>
            </div>
            <div class="strength-text">Password strength: <span class="strength-label">None</span></div>
        `;
        
        // Add CSS if not already present
        if (!document.querySelector('#password-strength-styles')) {
            const style = document.createElement('style');
            style.id = 'password-strength-styles';
            style.textContent = `
                .password-strength {
                    margin-top: 0.5rem;
                    font-size: 0.75rem;
                }
                .strength-bar {
                    width: 100%;
                    height: 4px;
                    background-color: #e5e7eb;
                    border-radius: 2px;
                    overflow: hidden;
                    margin-bottom: 0.25rem;
                }
                .strength-fill {
                    height: 100%;
                    transition: all 0.3s ease;
                    width: 0%;
                }
                .strength-weak { background-color: #ef4444; width: 25%; }
                .strength-fair { background-color: #f59e0b; width: 50%; }
                .strength-good { background-color: #10b981; width: 75%; }
                .strength-strong { background-color: #059669; width: 100%; }
            `;
            document.head.appendChild(style);
        }
        
        container.appendChild(strengthIndicator);
        
        passwordInput.addEventListener('input', () => {
            this.updatePasswordStrength(passwordInput.value, strengthIndicator);
        });
    }
    
    updatePasswordStrength(password, indicator) {
        const fill = indicator.querySelector('.strength-fill');
        const label = indicator.querySelector('.strength-label');
        
        if (!password) {
            fill.className = 'strength-fill';
            label.textContent = 'None';
            return;
        }
        
        let score = 0;
        
        // Length check
        if (password.length >= 6) score++;
        if (password.length >= 10) score++;
        
        // Character variety (relaxed requirements)
        if (/[a-zA-Z]/.test(password)) score++;
        if (/\d/.test(password)) score++;
        if (/[A-Z]/.test(password)) score++; // Bonus for uppercase
        if (/[@$!%*?&#+\-_=[\]{}|\\:";'<>?,./]/.test(password)) score++; // Bonus for special chars
        
        // Deduct for common patterns
        if (this.commonPasswords.some(common => password.toLowerCase().includes(common))) {
            score = Math.max(0, score - 2);
        }
        
        if (score <= 2) {
            fill.className = 'strength-fill strength-weak';
            label.textContent = 'Weak';
        } else if (score <= 4) {
            fill.className = 'strength-fill strength-fair';
            label.textContent = 'Fair';
        } else if (score <= 5) {
            fill.className = 'strength-fill strength-good';
            label.textContent = 'Good';
        } else {
            fill.className = 'strength-fill strength-strong';
            label.textContent = 'Strong';
        }
    }
    
    addCharacterCounter(textarea, maxLength) {
        const container = textarea.parentNode;
        const counter = document.createElement('div');
        counter.className = 'character-counter';
        counter.style.cssText = 'font-size: 0.75rem; color: #6b7280; text-align: right; margin-top: 0.25rem;';
        
        const updateCounter = () => {
            const remaining = maxLength - textarea.value.length;
            counter.textContent = `${textarea.value.length}/${maxLength} characters`;
            
            if (remaining < 50) {
                counter.style.color = '#ef4444';
            } else if (remaining < 100) {
                counter.style.color = '#f59e0b';
            } else {
                counter.style.color = '#6b7280';
            }
        };
        
        container.appendChild(counter);
        textarea.addEventListener('input', updateCounter);
        updateCounter();
    }
    
    showFieldError(input, message) {
        this.hideFieldError(input);
        
        const errorDiv = document.createElement('div');
        errorDiv.className = 'field-error';
        errorDiv.style.cssText = 'color: #ef4444; font-size: 0.75rem; margin-top: 0.25rem;';
        errorDiv.textContent = message;
        errorDiv.setAttribute('data-field-error', 'true');
        
        input.style.borderColor = '#ef4444';
        input.parentNode.appendChild(errorDiv);
    }
    
    hideFieldError(input) {
        const existingError = input.parentNode.querySelector('[data-field-error]');
        if (existingError) {
            existingError.remove();
        }
        input.style.borderColor = '';
    }
    
    hasFieldError(input) {
        return !!input.parentNode.querySelector('[data-field-error]');
    }
    
    enhanceFormSubmission() {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', (e) => {
                if (!this.validateForm(form)) {
                    e.preventDefault();
                    this.showFormError(form, 'Please correct the errors above and try again.');
                }
            });
        });
    }
    
    validateForm(form) {
        let isValid = true;
        const inputs = form.querySelectorAll('input, textarea, select');
        
        inputs.forEach(input => {
            try {
                // Run appropriate validation based on input type/name
                if (input.name === 'username') {
                    this.validateUsername(input.value);
                } else if (input.name === 'password') {
                    this.validatePassword(input.value);
                } else if (input.name === 'confirmPassword') {
                    this.validateConfirmPassword(input.value);
                } else if (input.type === 'email' || input.name === 'email') {
                    this.validateEmail(input.value);
                } else if (input.name === 'title') {
                    this.validateTaskTitle(input.value);
                } else if (input.name === 'description') {
                    this.validateTaskDescription(input.value);
                }
                
                this.hideFieldError(input);
            } catch (error) {
                this.showFieldError(input, error.message);
                isValid = false;
            }
        });
        
        return isValid;
    }
    
    showFormError(form, message) {
        const existingError = form.querySelector('.form-error');
        if (existingError) {
            existingError.remove();
        }
        
        const errorDiv = document.createElement('div');
        errorDiv.className = 'form-error alert alert-danger';
        errorDiv.style.cssText = 'margin-bottom: 1rem;';
        errorDiv.textContent = message;
        
        form.insertBefore(errorDiv, form.firstChild);
        
        // Scroll to error
        errorDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

// Initialize client validation
new ClientValidation();
