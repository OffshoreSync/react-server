const express = require('express');
const router = express.Router();
const User = require('../models/User');
const PasswordReset = require('../models/PasswordReset');
const PasswordResetAttempt = require('../models/PasswordResetAttempt'); // New import
const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit'); // New import
const { body, validationResult } = require('express-validator'); // New import
const { safeLog, redactSensitiveData } = require('../utils/logger');
const fs = require('fs');
const path = require('path');

// Validate AWS SES Configuration
const validateSESConfig = () => {
  const requiredEnvVars = [
    'AWS_SES_ACCESS_KEY_ID', 
    'AWS_SES_SECRET_ACCESS_KEY', 
    'AWS_SES_REGION', 
    'AWS_SES_FROM_EMAIL'
  ];

  const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length > 0) {
    throw new Error(`Missing AWS SES configuration: ${missingVars.join(', ')}`);
  }

  // Additional validation for email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(process.env.AWS_SES_FROM_EMAIL)) {
    throw new Error('Invalid AWS_SES_FROM_EMAIL format');
  }
};

// Configure AWS SES Client with explicit credentials and validation
validateSESConfig();
const sesClient = new SESClient({
  region: process.env.AWS_SES_REGION,
  credentials: {
    accessKeyId: process.env.AWS_SES_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SES_SECRET_ACCESS_KEY
  }
});

// Send password reset email using AWS SES with localization support
const sendPasswordResetEmail = async (email, resetToken, language = 'en') => {
  try {
    // Load email template for the specified language
    const templatePath = path.join(
      __dirname, 
      `../locales/password-reset/${language}.json`
    );
    
    // Fallback to English if translation not found
    const templateExists = fs.existsSync(templatePath);
    const templateFile = templateExists 
      ? templatePath 
      : path.join(__dirname, '../locales/password-reset/en.json');
    
    const template = JSON.parse(fs.readFileSync(templateFile, 'utf8'));
    
    // Construct verification link
    const resetLink = `${process.env.REACT_APP_FRONTEND_URL}/reset-password?token=${resetToken}`;

    // Prepare email parameters
    const params = {
      Destination: {
        ToAddresses: [email]
      },
      Message: {
        Body: {
          Html: {
            Data: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f4f4f4;">
                <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                  <h2 style="color: #333; text-align: center; margin-bottom: 20px;">${template.subject}</h2>
                  
                  <p style="color: #666; line-height: 1.6; margin-bottom: 20px;">
                    ${template.body.split('{{verificationLink}}')[0]}
                  </p>
                  
                  <div style="text-align: center; margin: 20px 0;">
                    <a href="${resetLink}" style="
                      display: inline-block; 
                      padding: 12px 24px; 
                      background-color: #4CAF50; 
                      color: white; 
                      text-decoration: none; 
                      border-radius: 5px; 
                      font-weight: bold;
                      text-transform: uppercase;
                      transition: background-color 0.3s ease;
                    " target="_blank">
                      ${template.buttonText}
                    </a>
                  </div>
                  
                  <p style="color: #666; line-height: 1.6; margin-top: 20px;">
                    ${template.body.split('{{verificationLink}}')[1]}
                  </p>
                  
                  <p style="color: #999; font-size: 12px; text-align: center; margin-top: 20px;">
                    If you did not request this password reset, please ignore this email.
                  </p>
                </div>
              </div>
            `
          },
          Text: { 
            Data: template.body.replace('{{verificationLink}}', resetLink)
          }
        },
        Subject: { 
          Data: template.subject 
        }
      },
      Source: process.env.AWS_SES_FROM_EMAIL || 'noreply@offshoresync.com'
    };

    // Send email via AWS SES
    const command = new SendEmailCommand(params);
    await sesClient.send(command);
  } catch (error) {
    safeLog('Password reset email send failed:', redactSensitiveData(error), 'error');
    throw error;
  }
};

// Rate limiting for password reset requests
const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // Limit each IP to 3 password reset requests per windowMs
  message: 'Too many password reset attempts, please try again later',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Middleware for password reset request validation
const validatePasswordResetRequest = [
  body('email').isEmail().withMessage('Invalid email format'),
  body('email').normalizeEmail(),
  // Optional: Add more validation like checking email domain, etc.
];

// Request password reset route
router.post('/request-reset', 
  passwordResetLimiter,  // Add rate limiting
  validatePasswordResetRequest,  // Add input validation
  async (req, res) => {
    // Validate request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, language = 'en' } = req.body;

    try {
      // Additional bot protection: Check recent reset attempts
      const recentAttempts = await PasswordResetAttempt.countDocuments({
        email,
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      });

      if (recentAttempts > 2) {
        return res.status(429).json({ 
          message: 'Too many reset attempts for this email. Please contact support.' 
        });
      }

      // Existing user lookup and reset logic...
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'No account found with this email' });
      }

      // Log the reset attempt
      await PasswordResetAttempt.create({ 
        email, 
        ipAddress: req.ip 
      });

      // Generate reset token
      const resetToken = PasswordReset.generateResetToken();
      const hashedToken = PasswordReset.hashToken(resetToken);

      // Create password reset record
      await PasswordReset.create({
        user: user._id,
        token: hashedToken,
        expiresAt: new Date(Date.now() + parseInt(process.env.PASSWORD_RESET_EXPIRY))
      });

      // Send email using AWS SES with specified language
      try {
        await sendPasswordResetEmail(
          email, 
          resetToken, 
          language // Use the language passed from the client
        );
      } catch (emailError) {
        safeLog('Password reset email failed:', redactSensitiveData(emailError), 'error');
        return res.status(500).json({ 
          message: 'Failed to send password reset email' 
        });
      }

      // Success response
      res.status(200).json({ 
        message: 'Password reset link sent successfully' 
      });
    } catch (error) {
      safeLog('Password reset request error:', redactSensitiveData(error), 'error');
      res.status(500).json({ 
        message: 'Server error during password reset request' 
      });
    }
  }
);

// Verify reset token
router.post('/verify-token', async (req, res) => {
  try {
    const { token } = req.body;
    const hashedToken = PasswordReset.hashToken(token);

    const resetRequest = await PasswordReset.findOne({ 
      token: hashedToken, 
      expiresAt: { $gt: new Date() } 
    });

    if (!resetRequest) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    res.status(200).json({ message: 'Token is valid' });
  } catch (error) {
    safeLog('Verify token error:', redactSensitiveData(error));
    res.status(500).json({ 
      message: error.message || 'Failed to verify token',
      details: error.toString()
    });
  }
});

// Reset password route with enhanced security
router.post('/reset', async (req, res) => {
  try {
    const { token, newPassword, confirmPassword, email } = req.body;
    const currentTime = Date.now();

    // Validate input
    if (!token || !newPassword || !confirmPassword || !email) {
      return res.status(400).json({ 
        message: 'Token, email, new password, and confirmation are required',
        fields: {
          token: !token,
          newPassword: !newPassword,
          confirmPassword: !confirmPassword,
          email: !email
        }
      });
    }

    // Check if passwords match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ 
        message: 'Passwords do not match',
        field: 'confirmPassword'
      });
    }

    // Rate limiting for reset attempts
    const resetKey = `${email}_${token}`;
    const resetAttempts = {};
    if (resetAttempts[resetKey]) {
      const { attempts, lastAttempt, lockedUntil } = resetAttempts[resetKey];
      
      // Check if request is locked out
      if (lockedUntil && currentTime < lockedUntil) {
        const remainingLockTime = Math.ceil((lockedUntil - currentTime) / 1000 / 60);
        return res.status(429).json({ 
          message: `Too many reset attempts. Locked for ${remainingLockTime} minutes.`
        });
      }

      // Check reset attempt frequency
      if (attempts >= 3) {
        resetAttempts[resetKey] = {
          attempts: attempts + 1,
          lastAttempt: currentTime,
          lockedUntil: currentTime + 24 * 60 * 60 * 1000
        };
        return res.status(429).json({ 
          message: 'Too many reset attempts. Please try again later.'
        });
      }
    }

    // Validate password complexity
    const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!complexityRegex.test(newPassword)) {
      return res.status(400).json({ 
        message: 'Password does not meet complexity requirements',
        requirements: [
          'Minimum 8 characters',
          'At least one uppercase letter',
          'At least one lowercase letter', 
          'At least one number',
          'At least one special character'
        ]
      });
    }

    // Verify reset token
    const hashedToken = PasswordReset.hashToken(token);
    const resetRequest = await PasswordReset.findOne({ 
      token: hashedToken, 
      expiresAt: { $gt: new Date() } 
    });

    if (!resetRequest) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    // Find user by email
    const user = await User.findById(resetRequest.user);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update user's password
    user.password = hashedPassword;
    await user.save();

    // Delete the used reset token
    await PasswordReset.deleteOne({ _id: resetRequest._id });

    // Track successful reset
    if (resetAttempts[resetKey]) {
      delete resetAttempts[resetKey];
    }

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    safeLog('Password reset error:', redactSensitiveData(error));
    res.status(500).json({ 
      message: 'Failed to reset password',
      details: error.message 
    });
  }
});

module.exports = router;
