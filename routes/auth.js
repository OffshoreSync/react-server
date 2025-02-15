const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const validateGoogleToken = require('../middleware/googleTokenValidator');
const bcrypt = require('bcryptjs');
const path = require('path');
const { getCountryCode } = require('../utils/countries');
const crypto = require('crypto');
const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
const rateLimit = require('express-rate-limit');
const { safeLog, redactSensitiveData } = require('../utils/logger');
const fs = require('fs');
const { sendPasswordResetEmail } = require('./passwordReset');

// Initialize SES client
const sesClient = new SESClient({
  region: process.env.AWS_SES_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_SES_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SES_SECRET_ACCESS_KEY
  }
});

// Utility function for password complexity
const validatePasswordComplexity = (password) => {
  // Require:
  // - Minimum 8 characters
  // - At least one uppercase letter
  // - At least one lowercase letter
  // - At least one number
  // - At least one special character
  const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return complexityRegex.test(password);
};

// Utility function for email validation
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Sanitize username
const sanitizeUsername = (username) => {
  // Remove any non-alphanumeric characters except underscore
  return username.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
};

// Disposable email domains list
const DISPOSABLE_DOMAINS = [
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
  'guerrillamail.biz', 'temp-mail.org', '10minutemail.com', 'throwawaymail.com', 
  'tempmail.com', 'tempmail.net', 'tempemail.com', 'tempemails.com', 'tempemails.net',
  'emailtemporaire.com', 'jetable.org', 'noemail.xyz', 'spam4.me', 'yopmail.com',
  'dispostable.com', 'sharklasers.com', 'guerrillamail.info', 'grr.la', 'spam.la',
  'pokemail.net', 'temp.email', 'dropmail.me', 'fakeinbox.com', '33mail.com'
];

// Middleware to block disposable emails
const blockDisposableEmails = (req, res, next) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ 
      message: 'Email is required',
      errors: { email: 'Email is required' }
    });
  }
  
  const emailDomain = email.split('@')[1].toLowerCase();
  
  if (DISPOSABLE_DOMAINS.includes(emailDomain)) {
    return res.status(400).json({ 
      message: 'Disposable email addresses are not allowed',
      errors: { 
        email: 'Please use a valid personal or corporate email address' 
      }
    });
  }
  
  next();
};

// Function to load email translations
const loadEmailTranslations = (language) => {
  const translationPath = path.join(__dirname, '..', 'locales', 'verification-emails', `${language}.json`);
  
  try {
    // Ensure the directory exists
    const directoryPath = path.dirname(translationPath);
    fs.mkdirSync(directoryPath, { recursive: true });
    
    // Create default translation files if they don't exist
    const defaultTranslations = {
      en: {
        subject: 'Verify Your OffshoreSync Account',
        body: `Welcome to OffshoreSync! 

Please verify your email by clicking the link below:
{{verificationLink}}

If you did not create an account, please ignore this email.

Best regards,
OffshoreSync Team`
      },
      pt: {
        subject: 'Verifique sua Conta OffshoreSync',
        body: `Bem-vindo ao OffshoreSync!

Por favor, verifique seu e-mail clicando no link abaixo:
{{verificationLink}}

Se você não criou esta conta, por favor, ignore este e-mail.

Melhores cumprimentos,
Equipe OffshoreSync`
      },
      es: {
        subject: 'Verifique su Cuenta de OffshoreSync',
        body: `¡Bienvenido a OffshoreSync!

Por favor, verifique su correo electrónico haciendo clic en el enlace a continuación:
{{verificationLink}}

Si no creó esta cuenta, ignore este correo electrónico.

Saludos cordiales,
Equipe de OffshoreSync`
      }
    };

    // If file doesn't exist, create it with default translations
    if (!fs.existsSync(translationPath)) {
      const defaultTranslation = defaultTranslations[language] || defaultTranslations['en'];
      fs.writeFileSync(translationPath, JSON.stringify(defaultTranslation, null, 2));
    }

    // Read and parse the translation file
    const translationContent = fs.readFileSync(translationPath, 'utf8');
    return JSON.parse(translationContent);
  } catch (error) {
    safeLog(`Error loading email translation for ${language}:`, error, 'error');
    // Fallback to English if translation loading fails
    return loadEmailTranslations('en');
  }
};

// Utility function to extract language
const extractLanguage = (req) => {
  // Check various possible sources of language information
  const language = 
    req.body.language ||  // Explicitly passed language
    req.headers['accept-language'] ||  // HTTP Accept-Language header
    req.headers['x-language'] ||  // Custom header
    'en';  // Default to English

  // Normalize language code
  const normalizedLanguage = language.split('-')[0].toLowerCase();
  
  // Validate against supported languages
  const supportedLanguages = ['en', 'pt', 'es'];
  return supportedLanguages.includes(normalizedLanguage) ? normalizedLanguage : 'en';
};

// Send verification email using AWS SES with localization support
const sendVerificationEmail = async (email, verificationToken, language = 'en') => {
  // Normalize language code (in case of full locale codes like en-US)
  const normalizedLanguage = language.split('-')[0].toLowerCase();
  
  // Load translations
  const template = loadEmailTranslations(normalizedLanguage);
  const verificationLink = `${process.env.REACT_APP_FRONTEND_URL}/verify-email?token=${verificationToken}`;

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
                  <a href="${verificationLink}" style="
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
                    Verify Email
                  </a>
                </div>
                
                <p style="color: #666; line-height: 1.6; margin-top: 20px;">
                  ${template.body.split('{{verificationLink}}')[1]}
                </p>
                
                <p style="color: #999; font-size: 12px; text-align: center; margin-top: 20px;">
                  If you did not create an account, please ignore this email.
                </p>
              </div>
            </div>
          `
        },
        Text: { 
          Data: template.body.replace('{{verificationLink}}', verificationLink)
        }
      },
      Subject: { 
        Data: template.subject 
      }
    },
    Source: process.env.AWS_SES_FROM_EMAIL || 'noreply@offshoresync.com'
  };

  try {
    const command = new SendEmailCommand(params);
    await sesClient.send(command);
    safeLog(`Verification email sent to ${email} in ${normalizedLanguage} language`);
  } catch (error) {
    safeLog(`Error sending verification email to ${email}: ${error.message}`, 'error');
    throw error;
  }
};

// Register new user
router.post('/register', blockDisposableEmails, async (req, res) => {
  try {
    safeLog('Received registration data:', redactSensitiveData(req.body));

    const { 
      username, 
      email, 
      password, 
      fullName, 
      offshoreRole, 
      workingRegime, 
      customOnDutyDays, 
      customOffDutyDays,
      country,
      company,
      unitName,
      googleLogin // New flag
    } = req.body;

    // Validate required fields
    if (!username || !email || !password || !fullName || !offshoreRole || !country) {
      return res.status(400).json({ 
        message: 'Missing required fields',
        errors: {
          username: !username ? 'Username is required' : undefined,
          email: !email ? 'Email is required' : undefined,
          password: !password ? 'Password is required' : undefined,
          fullName: !fullName ? 'Full name is required' : undefined,
          offshoreRole: !offshoreRole ? 'Offshore role is required' : undefined,
          country: !country ? 'Country is required' : undefined
        }
      });
    }

    // Prepare working regime
    let userWorkingRegime;
    const predefinedRegimes = User.getPredefinedRegimes();

    if (workingRegime === 'custom') {
      // Validate custom working regime
      if (!customOnDutyDays || !customOffDutyDays) {
        return res.status(400).json({ 
          message: 'Custom working regime requires both on and off duty days',
          errors: {
            customOnDutyDays: !customOnDutyDays ? 'On duty days are required' : undefined,
            customOffDutyDays: !customOffDutyDays ? 'Off duty days are required' : undefined
          }
        });
      }

      const totalDays = parseInt(customOnDutyDays, 10) + parseInt(customOffDutyDays, 10);
      if (totalDays > 365) {
        return res.status(400).json({ 
          message: 'Total working days must not exceed 365',
          errors: {
            customOnDutyDays: 'Total on and off duty days must not exceed 365',
            customOffDutyDays: 'Total on and off duty days must not exceed 365'
          }
        });
      }

      userWorkingRegime = {
        onDutyDays: parseInt(customOnDutyDays, 10),
        offDutyDays: parseInt(customOffDutyDays, 10)
      };
    } else {
      // Use predefined regime
      if (!predefinedRegimes[workingRegime]) {
        return res.status(400).json({ 
          message: 'Invalid working regime',
          errors: { workingRegime: 'Selected working regime is not valid' }
        });
      }
      userWorkingRegime = predefinedRegimes[workingRegime];
    }

    // Sanitize and validate inputs
    const sanitizedUsername = sanitizeUsername(username);
    
    // Email validation
    if (!validateEmail(email)) {
      return res.status(400).json({ 
        message: 'Invalid email format',
        field: 'email'
      });
    }

    // Password complexity check for non-Google users
    if (!googleLogin && !validatePasswordComplexity(password)) {
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

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ username: sanitizedUsername }, { email }] 
    });

    if (existingUser) {
      // If Google login, update existing user
      if (googleLogin && !existingUser.isGoogleUser) {
        existingUser.isGoogleUser = true;
        await existingUser.save();
      } else if (existingUser.isGoogleUser) {
        return res.status(400).json({ message: 'Google user already exists' });
      } else {
        return res.status(400).json({ 
          message: 'User already exists',
          errors: {
            username: existingUser.username === sanitizedUsername ? 'Username is already taken' : undefined,
            email: existingUser.email === email ? 'Email is already registered' : undefined
          }
        });
      }
    }

    // For non-Google users, add verification
    let verificationToken = null;
    let verificationTokenExpires = null;

    if (!googleLogin) {
      // Generate verification token
      verificationToken = crypto.randomBytes(32).toString('hex');
      verificationTokenExpires = new Date(Date.now() + 24 * 3600 * 1000); // 24 hours
      
      // Send verification email
      try {
        // Use the new extractLanguage function to get the correct language
        const language = extractLanguage(req);
        await sendVerificationEmail(email, verificationToken, language);
      } catch (emailError) {
        safeLog('Verification email send failed:', redactSensitiveData(emailError));
        
        return res.status(500).json({
          message: 'Failed to send verification email',
          error: emailError.message
        });
      }
    }

    // Create new user
    const newUser = new User({
      username: sanitizedUsername,
      email,
      password: googleLogin ? undefined : password, // Optional for Google users
      fullName,
      offshoreRole,
      workingRegime: userWorkingRegime,
      country,
      company: company || null,
      unitName: unitName || null,
      isGoogleUser: googleLogin || false,
      profilePicture: googleLogin ? undefined : null, // Set profilePicture to null for non-Google users
      isVerified: googleLogin || false,
      verificationToken: googleLogin ? null : verificationToken,
      verificationTokenExpires: googleLogin ? null : verificationTokenExpires,
    });

    // Hash password
    if (!googleLogin) {
      safeLog('Hashing password for non-Google user');
      safeLog(`Password length: ${password.length}`);
      
      const salt = await bcrypt.genSalt(10);
      safeLog(`Generated salt: ${salt}`);
      
      const hashedPassword = await bcrypt.hash(password, salt);
      safeLog(`Hashed password length: ${hashedPassword.length}`);
      safeLog(`Hashed password starts with: ${hashedPassword.substring(0, 20)}...`);
      
      newUser.password = hashedPassword;
      
      // Additional verification
      safeLog('Verifying password hash...');
      const verifyMatch = await bcrypt.compare(password, hashedPassword);
      safeLog(`Password verification result: ${verifyMatch}`);
    }

    // Save user to database
    try {
      await newUser.save();
    } catch (saveError) {
      safeLog('User save error:', redactSensitiveData(saveError));
      return res.status(400).json({ 
        message: 'Error saving user', 
        details: saveError.message,
        errors: saveError.errors 
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: newUser._id, 
        username: newUser.username,
        isGoogleUser: newUser.isGoogleUser
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Return user info and token (excluding password)
    const userResponse = {
      _id: newUser._id,
      username: newUser.username,
      email: newUser.email,
      fullName: newUser.fullName,
      offshoreRole: newUser.offshoreRole,
      workingRegime: newUser.workingRegime,
      isGoogleUser: newUser.isGoogleUser,
      company: newUser.company,
      unitName: newUser.unitName,
      country: newUser.country,
      profilePicture: newUser.isGoogleUser ? undefined : null // Explicitly set to null for non-Google users
    };

    res.status(201).json({ 
      user: userResponse, 
      token,
      requiresVerification: !googleLogin
    });

  } catch (error) {
    safeLog('Registration error:', redactSensitiveData(error), 'error');
    res.status(500).json({ 
      message: 'Server error during registration',
      error: error.message 
    });
  }
});

// Rate limiting for email verification
const emailVerificationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // Limit each IP to 3 email verification attempts per windowMs
  message: {
    error: 'Too many email verification attempts, please try again later',
    translationKey: 'verifyEmail.error.tooManyAttempts'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Email verification route
router.get('/verify-email', emailVerificationLimiter, async (req, res) => {
  try {
    const { token } = req.query;

    safeLog('Received verification token', token ? 'Token present' : 'No token');

    if (!token) {
      safeLog('No verification token provided');
      return res.status(400).json({ 
        message: 'No verification token provided',
        error: req.t ? req.t('verifyEmail.error.invalidToken') : 'The verification link is invalid or has expired.'
      });
    }

    // Find user with this token that hasn't expired
    const user = await User.findOne({
      verificationToken: token,
      verificationTokenExpires: { $gt: new Date() }
    });

    safeLog('User found during verification', user ? 'User exists' : 'No user found');
    safeLog('Current time', new Date().toISOString());
    safeLog('Token expiration', user ? 'Token has expiration' : 'No expiration');

    // Check for existing user even if current query didn't find a user
    const existingUser = await User.findOne({ 
      verificationToken: token 
    });

    // If no user found in current query, check existing user
    if (!user && existingUser) {
      // If user already verified, return success
      if (existingUser.isVerified) {
        safeLog(`User ${existingUser.email} is already verified`);
        return res.status(200).json({ 
          message: req.t ? req.t('verifyEmail.success.message') : 'Email is already verified. You can now log in.',
          alreadyVerified: true
        });
      }
    }

    // If no user found at all
    if (!user && !existingUser) {
      safeLog('Invalid or expired verification token');
      return res.status(400).json({ 
        message: 'Invalid or expired verification token',
        error: req.t ? req.t('verifyEmail.error.invalidToken') : 'The verification link is invalid or has expired.'
      });
    }

    // Use existing user if current query user is null
    const userToVerify = user || existingUser;

    // Prevent multiple verification attempts
    if (userToVerify.isVerificationProcessed) {
      safeLog(`Verification already processed for user ${userToVerify.email}`);
      return res.status(200).json({ 
        message: req.t ? req.t('verifyEmail.success.message') : 'Email verified successfully. You can now log in.',
        verified: true
      });
    }

    // Mark user as verified 
    userToVerify.isVerified = true;
    userToVerify.isVerificationProcessed = true; // Add one-time flag
    userToVerify.verificationToken = undefined; // Clear the verification token
    userToVerify.verificationTokenExpires = undefined; // Clear token expiration

    await userToVerify.save();

    safeLog(`User ${userToVerify.email} verified successfully`);

    res.status(200).json({ 
      message: req.t ? req.t('verifyEmail.success.message') : 'Email verified successfully. You can now log in.',
      verified: true
    });
  } catch (error) {
    safeLog('Email verification error:', redactSensitiveData(error), 'error');
    res.status(500).json({ 
      message: 'Server error during email verification',
      error: error.message
    });
  }
});

// Login user
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    safeLog(`Login attempt for username`, username ? 'Username provided' : 'No username');

    // Find user by username
    const user = await User.findOne({ username });

    if (!user) {
      safeLog(`Login failed: No user found with username ${username}`);
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Detailed user information logging for diagnostics
    safeLog(`User found: 
      Username: ${user.username}
      Is Google User: ${user.isGoogleUser}
      Password Hash Length: ${user.password ? user.password.length : 'No password'}
    `);

    // Additional check for password existence
    if (!user.password && !user.isGoogleUser) {
      safeLog(`Login error: Non-Google user ${username} has no password`);
      return res.status(400).json({ message: 'Account setup incomplete' });
    }

    // Check if user is not verified (for non-Google users)
    if (!user.isGoogleUser && !user.isVerified) {
      return res.status(403).json({ 
        message: 'Please verify your email before logging in',
        requiresVerification: true,
        email: user.email
      });
    }

    // Check password
    let isMatch = false;
    try {
      // Use the new integrity verification method
      const integrityResult = await user.verifyPasswordIntegrity(password);
      safeLog('Password Integrity Verification Result:', JSON.stringify(integrityResult, null, 2));
      
      // Determine match based on integrity check
      isMatch = integrityResult.isMatch;
      
      // If no match, log additional details
      if (!isMatch) {
        safeLog(`Login failed for user ${username}. Detailed integrity check:`);
        safeLog(`Stored Hash Length: ${integrityResult.storedHashLength}`);
        safeLog(`New Hash Length: ${integrityResult.newHashLength}`);
        safeLog(`Stored Hash Prefix: ${integrityResult.storedHashPrefix}`);
        safeLog(`New Hash Prefix: ${integrityResult.newHashPrefix}`);
      }
    } catch (compareError) {
      safeLog(`Password comparison error for user ${username}:`, redactSensitiveData(compareError), 'error');
      return res.status(500).json({ message: 'Internal server error during password verification' });
    }

    safeLog(`Password match result for ${username}: ${isMatch}`);

    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Ensure profilePicture is null for non-Google users
    if (!user.isGoogleUser && user.profilePicture !== null) {
      safeLog(`Resetting profile picture for non-Google user ${username}`);
      user.profilePicture = null;
      await user.save();
    }

    // Generate token
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username,
        isGoogleUser: user.isGoogleUser
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Explicitly include all fields in the response
    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        offshoreRole: user.offshoreRole,
        workingRegime: user.workingRegime,
        isGoogleUser: user.isGoogleUser,
        company: user.company || null,
        workSchedule: user.workSchedule || {},
        
        // Explicitly include these fields with null fallback
        unitName: user.unitName || null,
        country: user.country || null,
        isGoogleUser: user.isGoogleUser,
        nextOnBoardDate: user.nextOnBoardDate || null
      }
    });
  } catch (error) {
    safeLog('Login error for user:', req.body.username, 'error');
    res.status(500).json({ 
      message: 'Server error during login',
      details: error.message 
    });
  }
});

// Country mapping function
const mapCountryToCode = (countryName) => {
  // Use the getCountryCode function from server utils
  return getCountryCode(countryName);
};

// Google Login/Registration
router.post('/google-login', validateGoogleToken, async (req, res) => {
  try {
    // Use validated Google user info from middleware
    const { email, name, picture, googleId, country } = req.googleUser;

    // Map country name to country code
    const countryCode = mapCountryToCode(country);

    // Log incoming profile details
    safeLog('Incoming Google Profile:', redactSensitiveData({
      email,
      name,
      picture,
      googleId,
      country,
      mappedCountryCode: countryCode
    }));

    // Check if user already exists
    let user = await User.findOne({ email });

    if (!user) {
      // Create new user with Google credentials
      user = new User({
        email,
        fullName: name,
        username: email.split('@')[0],
        isGoogleUser: true,
        googleId,
        profilePicture: picture, // Explicitly set profile picture
        // Use mapped country code
        country: countryCode,
        // Default values for required fields
        offshoreRole: 'Support', // Default role
        workingRegime: {
          onDutyDays: 28,
          offDutyDays: 28
        }
      });

      await user.save();
      safeLog('New user created with details:', redactSensitiveData({
        profilePicture: user.profilePicture,
        country: user.country
      }));
    } else {
      // Update existing user's profile picture and country
      user.profilePicture = picture;
      
      // Only update country if it's not already set
      if (!user.country || user.country === 'Unknown') {
        user.country = countryCode;
      }

      await user.save();
      safeLog('Existing user updated with details:', redactSensitiveData({
        profilePicture: user.profilePicture,
        country: user.country
      }));
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username,
        isGoogleUser: true
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Return user info and token (excluding password)
    const userResponse = {
      _id: user._id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      offshoreRole: user.offshoreRole,
      workingRegime: user.workingRegime,
      isGoogleUser: user.isGoogleUser || true, // Ensure this is always set for Google logins
      profilePicture: user.profilePicture, // Explicitly return profile picture
      country: user.country || 'US', // Ensure country is always returned
      company: user.company || null,
      unitName: user.unitName || null
    };

    // Additional logging
    safeLog('User Response:', redactSensitiveData({
      profilePicture: userResponse.profilePicture,
      country: userResponse.country
    }));

    res.status(200).json({ 
      user: userResponse, 
      token 
    });
  } catch (error) {
    safeLog('Google Login Error:', redactSensitiveData(error), 'error');
    res.status(500).json({ 
      message: 'Internal server error during Google login',
      error: error.message 
    });
  }
});

// Delete user account
router.delete('/delete-account', async (req, res) => {
  try {
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find and delete user
    const user = await User.findByIdAndDelete(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    safeLog('Account deletion error:', redactSensitiveData(error), 'error');
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }

    res.status(500).json({ message: 'Server error during account deletion' });
  }
});

// Update user profile
router.put('/update-profile', async (req, res) => {
  try {
    // Log incoming request body for debugging
    safeLog('Received profile update request:', redactSensitiveData(req.body));

    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find user
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Destructure request body with explicit handling
    const { 
      username, 
      email, 
      fullName, 
      offshoreRole, 
      workingRegime,
      company, 
      workSchedule,
      country,
      unitName
    } = req.body;

    // Update user fields with explicit preservation
    if (username) user.username = username;
    if (email) user.email = email;
    if (fullName) user.fullName = fullName;
    if (offshoreRole) user.offshoreRole = offshoreRole;
    if (workingRegime) user.workingRegime = workingRegime;
    if (company) user.company = company;
    if (workSchedule) user.workSchedule = workSchedule;
    
    // Explicitly handle country and unitName with logging
    safeLog('Incoming country:', country);
    safeLog('Incoming unitName:', unitName);
    safeLog('Existing user country:', user.country);
    safeLog('Existing user unitName:', user.unitName);

    // Preserve existing values if not provided
    if (country !== undefined) user.country = country;
    if (unitName !== undefined) user.unitName = unitName;

    // Explicitly handle company with clear removal support
    if (company !== undefined) {
      safeLog('Incoming company:', company);
      safeLog('Existing user company:', user.company);
      user.company = company || null;  // Set to null if empty string or falsy
    }

    // Save updated user
    await user.save();

    // Log saved user for verification
    safeLog('Updated user:', redactSensitiveData({
      country: user.country,
      unitName: user.unitName,
      company: user.company
    }));

    // Generate new token with updated information
    const newToken = jwt.sign(
      { 
        userId: user._id, 
        username: user.username,
        email: user.email,
        fullName: user.fullName
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Explicitly include all fields in the response
    res.json({ 
      message: 'Profile updated successfully', 
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        offshoreRole: user.offshoreRole,
        workingRegime: user.workingRegime,
        company: user.company || null,
        workSchedule: user.workSchedule || {},
        
        // Explicitly include these fields with null fallback
        unitName: user.unitName || null,
        country: user.country || null,
        isGoogleUser: user.isGoogleUser,
        nextOnBoardDate: user.nextOnBoardDate || null
      },
      token: newToken
    });
  } catch (error) {
    safeLog('Profile update error:', redactSensitiveData(error), 'error');
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({ message: 'Validation error', details: error.errors });
    }

    res.status(500).json({ message: 'Server error during profile update', error: error.message });
  }
});

// Get User Profile
router.get('/profile', async (req, res) => {
  try {
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find user
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Log user details for debugging
    safeLog('User Profile Details:', redactSensitiveData({
      isGoogleUser: user.isGoogleUser,
      profilePicture: user.profilePicture
    }));

    // Return user profile (excluding sensitive information)
    res.json({ 
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        offshoreRole: user.offshoreRole,
        workingRegime: user.workingRegime || {
          onDutyDays: 28,
          offDutyDays: 28
        },
        company: user.company,
        workSchedule: user.workSchedule,
        unitName: user.unitName || null,
        country: user.country || null,
        isGoogleUser: user.isGoogleUser,
        profilePicture: user.profilePicture || null // Explicitly include profilePicture
      }
    });
  } catch (error) {
    safeLog('Profile retrieval error:', redactSensitiveData(error), 'error');
    res.status(500).json({ message: 'Server error during profile retrieval' });
  }
});

// Set Next On Board Date
router.put('/set-onboard-date', async (req, res) => {
  try {
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find user
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get on board date from request
    const { nextOnBoardDate } = req.body;

    if (!nextOnBoardDate) {
      return res.status(400).json({ message: 'Next on board date is required' });
    }

    // Ensure working regime is set
    const onDutyDays = user.workingRegime?.onDutyDays || 14;
    const offDutyDays = user.workingRegime?.offDutyDays || 14;

    // Calculate off board date based on current working regime
    const onBoardDate = new Date(nextOnBoardDate);
    const offBoardDate = new Date(onBoardDate);
    offBoardDate.setDate(offBoardDate.getDate() + onDutyDays);

    // Update user's work schedule
    user.workSchedule = {
      nextOnBoardDate: onBoardDate,
      nextOffBoardDate: offBoardDate
    };

    // Save updated user
    await user.save();

    // Generate new token with updated information
    const newToken = jwt.sign(
      { 
        userId: user._id, 
        username: user.username,
        email: user.email,
        fullName: user.fullName
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    res.json({ 
      message: 'On board date updated successfully', 
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        offshoreRole: user.offshoreRole,
        company: user.company || null,
        workSchedule: {
          nextOnBoardDate: user.workSchedule.nextOnBoardDate,
          nextOffBoardDate: user.workSchedule.nextOffBoardDate
        },
        workingRegime: user.workingRegime,
        unitName: user.unitName || null,
        country: user.country || null,
        isGoogleUser: user.isGoogleUser
      },
      token: newToken
    });
  } catch (error) {
    safeLog('Set on board date error:', redactSensitiveData(error), 'error');
    res.status(500).json({ message: 'Server error during on board date update', error: error.message });
  }
});

// Reset Work Schedule and Prepare for New Onboarding
router.put('/reset-next-onboard-date', async (req, res) => {
  try {
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    // Find the user
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Reset work schedule details
    user.workSchedule = {
      nextOnBoardDate: null,
      nextOffBoardDate: null
    };

    // Save the updated user
    await user.save();

    res.json({ 
      message: 'Work schedule reset successfully',
      workSchedule: user.workSchedule 
    });
  } catch (error) {
    safeLog('Error resetting work schedule:', redactSensitiveData(error), 'error');
    res.status(500).json({ 
      message: 'Server error while resetting work schedule',
      error: error.message 
    });
  }
});

// Generate and save work cycles for a user
router.post('/generate-work-cycles', async (req, res) => {
  try {
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find the user and populate all necessary fields
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get working regime from user
    const { onDutyDays, offDutyDays } = user.workingRegime;

    // Prepare work cycles
    const workCycles = [];
    const nextOnBoardDate = new Date(user.workSchedule.nextOnBoardDate);
    const twoYearsFromNow = new Date(nextOnBoardDate);
    twoYearsFromNow.setFullYear(twoYearsFromNow.getFullYear() + 2);

    let currentDate = nextOnBoardDate;
    let cycleNumber = 1;

    while (currentDate < twoYearsFromNow) {
      // On Board cycle
      const onBoardStart = new Date(currentDate);
      const onBoardEnd = new Date(currentDate);
      onBoardEnd.setDate(onBoardEnd.getDate() + onDutyDays);

      // Ensure on-board start date is strictly after off-board end date (HAX)
      if (cycleNumber > 1 && workCycles.length > 0) {
        const prevCycle = workCycles[workCycles.length - 1];
        const prevCycleEnd = new Date(prevCycle.endDate);
        
        if (onBoardStart.getTime() === prevCycleEnd.getTime()) {
          onBoardStart.setDate(onBoardStart.getDate() + 1);
        }
      }

      workCycles.push({
        startDate: onBoardStart,
        endDate: onBoardEnd,
        type: 'OnBoard',
        cycleNumber
      });

      // Move to Off Board cycle
      currentDate = new Date(onBoardEnd);
      const offBoardStart = new Date(currentDate);
      const offBoardEnd = new Date(currentDate);
      offBoardEnd.setDate(offBoardEnd.getDate() + offDutyDays);

      // Ensure off-board start date is strictly after on-board end date (HAX)
      if (offBoardStart.getTime() === onBoardEnd.getTime()) {
        offBoardStart.setDate(offBoardStart.getDate() + 1);
      }

      workCycles.push({
        startDate: offBoardStart,
        endDate: offBoardEnd,
        type: 'OffBoard',
        cycleNumber
      });

      // Prepare for next cycle
      currentDate = offBoardEnd;
      cycleNumber++;
    }

    // Use findOneAndUpdate to atomically update work cycles
    try {
      const updatedUser = await User.findOneAndUpdate(
        { _id: user._id },
        { 
          $set: { 
            workCycles: workCycles 
          } 
        },
        { 
          new: true,  // Return the modified document
          runValidators: true  // Run model validations
        }
      );

      if (!updatedUser) {
        throw new Error('User not found or could not update work cycles');
      }

      // Prepare response with full user data
      const userResponse = {
        _id: updatedUser._id,
        username: updatedUser.username,
        email: updatedUser.email,
        fullName: updatedUser.fullName,
        workSchedule: updatedUser.workSchedule,
        workingRegime: updatedUser.workingRegime,
        workCycles: updatedUser.workCycles,
        isGoogleUser: updatedUser.isGoogleUser
      };

      res.status(200).json({ 
        message: 'Work cycles generated successfully',
        user: userResponse,
        workCycles: updatedUser.workCycles
      });

    } catch (error) {
      safeLog('Error generating work cycles:', redactSensitiveData(error), 'error');
      res.status(500).json({ 
        message: 'Server error while generating work cycles',
        error: error.message 
      });
    }
  } catch (error) {
    safeLog('Error generating work cycles:', redactSensitiveData(error), 'error');
    res.status(500).json({ 
      message: 'Server error while generating work cycles',
      error: error.message 
    });
  }
});

// Retrieve a specific user's work cycles
router.get('/user-work-cycles/:userId', async (req, res) => {
  try {
    // Get token from headers for authentication
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    const { userId } = req.params;

    // Find target user
    const targetUser = await User.findById(userId)
      .select('workCycles fullName username isGoogleUser');

    if (!targetUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Sort work cycles chronologically
    const sortedWorkCycles = targetUser.workCycles
      .map(cycle => ({
        ...cycle.toObject(),
        startDate: new Date(cycle.startDate),
        endDate: new Date(cycle.endDate)
      }))
      .sort((a, b) => a.startDate - b.startDate);

    // Prepare response
    res.status(200).json({
      userId: targetUser._id,
      fullName: targetUser.fullName,
      username: targetUser.username,
      isGoogleUser: targetUser.isGoogleUser,
      workCycles: sortedWorkCycles
    });

  } catch (error) {
    safeLog('Error retrieving user work cycles:', redactSensitiveData(error), 'error');
    res.status(500).json({ 
      message: 'Server error while retrieving user work cycles',
      error: error.message 
    });
  }
});

// Fetch all users for sync functionality
router.get('/all-users', async (req, res) => {
  try {
    // Get token from headers for authentication
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find the current user
    const currentUser = await User.findById(decoded.userId);

    if (!currentUser) {
      return res.status(404).json({ message: 'Current user not found' });
    }

    // Fetch all users except the current user
    const users = await User.find({ 
      _id: { $ne: currentUser._id } 
    }).select('id fullName username email isGoogleUser');

    // Validate and filter users
    const validUsers = users.map(user => ({
      id: user._id,
      fullName: user.fullName,
      username: user.username,
      email: user.email,
      isGoogleUser: user.isGoogleUser
    }));

    res.status(200).json({ 
      users: validUsers,
      total: validUsers.length
    });

  } catch (error) {
    safeLog('Error fetching all users:', redactSensitiveData(error), 'error');
    res.status(500).json({ 
      message: 'Server error while fetching users',
      error: error.message 
    });
  }
});

// Import Friend model
const Friend = require('../models/Friend');

// Send Friend Request
router.post('/friend-request', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    const { friendId } = req.body;

    // Validate input
    if (!friendId) {
      return res.status(400).json({ message: 'Friend ID is required' });
    }

    // Check if the target user exists
    const targetUser = await User.findById(friendId);
    if (!targetUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if users are trying to friend themselves
    if (currentUserId.toString() === friendId) {
      return res.status(400).json({ message: 'You cannot send a friend request to yourself' });
    }

    // Check for existing friend requests or friendships
    const existingRequest = await Friend.findOne({
      $or: [
        { 
          user: currentUserId, 
          friend: friendId 
        },
        { 
          user: friendId, 
          friend: currentUserId 
        }
      ]
    });

    if (existingRequest) {
      if (existingRequest.status === 'ACCEPTED') {
        return res.status(400).json({ message: 'You are already friends' });
      }
      if (existingRequest.status === 'PENDING') {
        return res.status(400).json({ message: 'Friend request already sent or pending' });
      }
    }

    // Create new friend request
    const newFriendRequest = new Friend({
      user: currentUserId,
      friend: friendId,
      status: 'PENDING',
      createdAt: new Date()
    });

    await newFriendRequest.save();

    // Populate the friend request with user details for notification purposes
    await newFriendRequest.populate('user friend', 'fullName email profilePicture');

    // Optional: Send notification to the target user
    // You can implement this later with a notification system

    res.status(201).json({ 
      message: 'Friend request sent successfully', 
      friendRequest: newFriendRequest 
    });

  } catch (error) {
    safeLog('Send friend request error:', redactSensitiveData(error), 'error');
    res.status(500).json({ message: 'Server error sending friend request' });
  }
});

// Respond to Friend Request
router.put('/friend-request/:requestId', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    const { status } = req.body; // 'ACCEPTED' or 'BLOCKED'
    const { requestId } = req.params;

    const friendRequest = await Friend.findOneAndUpdate(
      { 
        _id: requestId, 
        friend: currentUserId,
        status: 'PENDING'
      },
      { 
        status,
        'sharingPreferences.allowScheduleSync': status === 'ACCEPTED'
      },
      { new: true }
    );

    if (!friendRequest) {
      return res.status(404).json({ message: 'Friend request not found' });
    }

    res.status(200).json({ 
      message: 'Friend request updated', 
      status: friendRequest.status 
    });

  } catch (error) {
    safeLog('Friend request update error:', redactSensitiveData(error), 'error');
    res.status(500).json({ message: 'Server error updating friend request' });
  }
});

// Get Friends List
router.get('/friends', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    // Find all accepted friendships for the current user
    const friendships = await Friend.find({
      $or: [
        { user: currentUserId, status: 'ACCEPTED' },
        { friend: currentUserId, status: 'ACCEPTED' }
      ]
    }).populate('user friend', 'fullName email profilePicture');

    // Transform friendships to include friend details
    const friends = friendships.map(friendship => {
      const isFriendInitiator = friendship.user._id.toString() === currentUserId;
      const friendDetails = isFriendInitiator ? friendship.friend : friendship.user;
      
      return {
        id: friendDetails._id,
        fullName: friendDetails.fullName,
        email: friendDetails.email,
        profilePicture: friendDetails.profilePicture,
        sharingPreferences: {
          allowScheduleSync: friendship.sharingPreferences.allowScheduleSync
        }
      };
    });

    res.status(200).json({ friends });

  } catch (error) {
    safeLog('Get friends error:', redactSensitiveData(error), 'error');
    res.status(500).json({ message: 'Server error retrieving friends' });
  }
});

// Get Pending Friend Requests
router.get('/friend-requests', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    // Find pending friend requests for the current user
    const pendingRequests = await Friend.find({
      friend: currentUserId,
      status: 'PENDING'
    }).populate('user', 'fullName email profilePicture');

    const requests = pendingRequests.map(request => ({
      id: request._id,
      user: {
        id: request.user._id,
        fullName: request.user.fullName,
        email: request.user.email,
        profilePicture: request.user.profilePicture
      },
      requestedAt: request.requestedAt
    }));

    res.status(200).json({ pendingRequests: requests });

  } catch (error) {
    safeLog('Get pending requests error:', redactSensitiveData(error), 'error');
    res.status(500).json({ message: 'Server error retrieving pending requests' });
  }
});

// Search Users Route
router.get('/search-users', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    const { query } = req.query;

    // Validate search query
    if (!query || query.trim().length < 2) {
      return res.status(400).json({ 
        message: 'Search query must be at least 2 characters long' 
      });
    }

    // Search users by full name or username, excluding current user
    const users = await User.find({
      $and: [
        { _id: { $ne: currentUserId } }, // Exclude current user
        {
          $or: [
            { fullName: { $regex: query, $options: 'i' } }, // Case-insensitive full name search
            { username: { $regex: query, $options: 'i' } }  // Case-insensitive username search
          ]
        }
      ]
    }).select('fullName username email profilePicture offshoreRole'); // Select specific fields

    // Check existing friend requests or friendships
    const friendRequests = await Friend.find({
      $or: [
        { user: currentUserId },
        { friend: currentUserId }
      ]
    });

    // Annotate users with friendship status
    const usersWithStatus = users.map(user => {
      const existingRequest = friendRequests.find(
        req => 
          (req.user.toString() === user._id.toString() || 
           req.friend.toString() === user._id.toString())
      );

      return {
        id: user._id,
        fullName: user.fullName,
        username: user.username,
        email: user.email,
        profilePicture: user.profilePicture,
        offshoreRole: user.offshoreRole,
        friendshipStatus: existingRequest ? existingRequest.status : 'NO_REQUEST'
      };
    });

    res.status(200).json({ users: usersWithStatus });

  } catch (error) {
    safeLog('Search users error:', redactSensitiveData(error), 'error');
    res.status(500).json({ message: 'Server error searching users' });
  }
});

// Password reset request route
router.post('/password/request-reset', async (req, res) => {
  try {
    const { email, language } = req.body;

    // Validate email
    if (!validateEmail(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      // For security, return generic message
      return res.status(200).json({ 
        message: 'If an account exists with this email, a reset link will be sent' 
      });
    }

    // Generate password reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour

    // Update user with reset token
    user.passwordResetToken = resetToken;
    user.passwordResetTokenExpires = resetTokenExpires;
    await user.save();

    // Send password reset email
    try {
      await sendPasswordResetEmail(
        email, 
        resetToken, 
        language || 'en'
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
});

module.exports = router;
