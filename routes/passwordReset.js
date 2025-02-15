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

// Send email using AWS SES with comprehensive error handling
const sendPasswordResetEmail = async (email, resetLink) => {
  // Validate input
  if (!email || !resetLink) {
    throw new Error('Email and reset link are required');
  }

  const params = {
    Source: process.env.AWS_SES_FROM_EMAIL,
    Destination: {
      ToAddresses: [email]
    },
    Message: {
      Subject: {
        Data: 'Password Reset Request for OffshoreSync'
      },
      Body: {
        Html: {
          Data: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2>Password Reset Request</h2>
              <p>You have requested to reset your password for OffshoreSync.</p>
              <p>Click the link below to reset your password:</p>
              <a href="${resetLink}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">
                Reset Password
              </a>
              <p>If you did not request this reset, please ignore this email or contact support.</p>
              <p>This link will expire in 1 hour.</p>
            </div>
          `
        },
        Text: {
          Data: `Password Reset Link: ${resetLink}\n\nThis link will expire in 1 hour.`
        }
      }
    }
  };

  try {
    const command = new SendEmailCommand(params);
    const response = await sesClient.send(command);
    
    safeLog('Email sending response:', redactSensitiveData({
      messageId: response.$metadata.requestId,
      httpStatusCode: response.$metadata.httpStatusCode
    }));

    return response;
  } catch (error) {
    // Comprehensive error logging
    safeLog('Detailed SES Email Send Error:', redactSensitiveData({
      message: error.message,
      name: error.name,
      code: error.code,
    }));

    // Specific error handling
    if (error.name === 'MessageRejected') {
      throw new Error(`Email sending failed. Possible reasons:
        1. Email address may be invalid
        2. Sender email not properly configured
        3. AWS SES sending limits exceeded`);
    }
    if (error.name === 'ConfigurationSetDoesNotExist') {
      throw new Error('AWS SES configuration error. Please check your SES setup.');
    }
    if (error.code === 'AccessDeniedException') {
      throw new Error('AWS credentials do not have permission to send emails.');
    }

    throw new Error(`Failed to send password reset email: ${error.message}`);
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

    const { email } = req.body;

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

      // Construct reset link
      const resetLink = `${process.env.REACT_APP_FRONTEND_URL}/reset-password/${resetToken}`;

      // Send email using AWS SES
      await sendPasswordResetEmail(email, resetLink);

      res.status(200).json({ message: 'Password reset link sent successfully' });
    } catch (error) {
      safeLog('Password reset request error:', redactSensitiveData(error));
      res.status(500).json({ 
        message: error.message || 'Failed to process password reset request',
        details: error.toString()
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
