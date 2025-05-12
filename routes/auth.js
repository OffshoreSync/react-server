const express = require('express');
const axios = require('axios');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const validateGoogleToken = require('../middleware/googleTokenValidator');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { safeLog, redactSensitiveData } = require('../utils/logger');
const { getCountryCode } = require('../utils/countries');
const crypto = require('crypto');
const path = require('path');
const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
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

// Login user
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    safeLog(`Login attempt for username`, username ? 'Username provided' : 'No username');

    // Find user by username and ensure workSchedule and workingRegime are properly initialized
    const user = await User.findOne({ username });

    if (!user) {
      safeLog(`Login failed: No user found with username ${username}`);
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Initialize workingRegime if not set
    if (!user.workingRegime) {
      user.workingRegime = {
        onDutyDays: 28,
        offDutyDays: 28
      };
      await user.save();
    }

    // Initialize workSchedule if not set
    if (!user.workSchedule) {
      user.workSchedule = {};
      await user.save();
    }

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
      // Use the integrity verification method
      const integrityResult = await user.verifyPasswordIntegrity(password);
      safeLog('Password Integrity Verification Result:', JSON.stringify(integrityResult, null, 2));
      isMatch = integrityResult.isMatch;
    } catch (compareError) {
      safeLog(`Password comparison error for user ${username}:`, redactSensitiveData(compareError), 'error');
      return res.status(500).json({ message: 'Internal server error during password verification' });
    }

    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Generate tokens
    const { token, refreshToken } = generateTokens(user);

    // Store refresh token
    await storeRefreshToken(user, refreshToken);

    // Return tokens and user data
    res.json({
      token,
      refreshToken,
      user: createUserResponse(user)
    });

  } catch (error) {
    safeLog('Login error for user:', req.body.username, 'error');
    res.status(500).json({ 
      message: 'Server error during login',
      details: error.message 
    });
  }
});

// Helper function to generate tokens
const generateTokens = (user) => {
  try {
    // Log user details
    safeLog('User details for token generation:', {
      id: user._id?.toString(),
      email: redactSensitiveData(user.email),
      username: redactSensitiveData(user.username)
    });

    // Validate user object
    if (!user._id) throw new Error('User ID is missing');
    if (!user.email) throw new Error('User email is missing');
    if (!user.username) throw new Error('Username is missing');

    // Generate access token
    let token;
    try {
      token = jwt.sign(
        { 
          userId: user._id.toString(),
          email: user.email,
          username: user.username,
          isGoogleUser: user.isGoogleUser,
          fullName: user.fullName
        }, 
        process.env.JWT_SECRET, 
        { expiresIn: '15m' } // 15 minutes for access token
      );
      safeLog('Access token generated');
    } catch (tokenError) {
      safeLog('Access token generation failed:', tokenError);
      throw tokenError;
    }

    // Generate refresh token
    let refreshToken;
    try {
      refreshToken = jwt.sign(
        { userId: user._id.toString() },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '30d' } // 30 days for refresh token
      );
      safeLog('Refresh token generated');
    } catch (refreshError) {
      safeLog('Refresh token generation failed:', refreshError);
      throw refreshError;
    }

    return { token, refreshToken };
  } catch (error) {
    safeLog('Token generation error:', {
      error: error.message,
      stack: error.stack
    });
    throw error;
  }
};

// Helper function to store refresh token
const storeRefreshToken = async (user, refreshToken) => {
  // Create expiration date (30 days from now)
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 30);

  // Initialize refreshTokens array if it doesn't exist
  user.refreshTokens = user.refreshTokens || [];
  
  // Check if this exact token already exists
  const tokenExists = user.refreshTokens.some(existingToken => 
    existingToken.token === refreshToken && !existingToken.isRevoked
  );
  
  // Only add the token if it doesn't already exist
  if (!tokenExists) {
    user.refreshTokens.push({
      token: refreshToken,
      expiresAt,
      isRevoked: false
    });
  }

  // Remove expired tokens
  user.refreshTokens = user.refreshTokens.filter(token => 
    token.expiresAt > new Date() && !token.isRevoked
  );

  await user.save();
};

// Helper function to set auth cookies
const setAuthCookies = (res, { token, refreshToken }) => {
  // Debug cookie settings
  safeLog('Setting auth cookies:', {
    tokenLength: token?.length,
    refreshTokenLength: refreshToken?.length,
    cookieSettings: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    }
  });

  // Set access token cookie (15 minutes)
  res.cookie('token', token, {
    httpOnly: false, // Allow JavaScript access for client-side auth
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 15 * 60 * 1000 // 15 minutes
  });

  // Set refresh token cookie (30 days)
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true, // Keep refresh token secure
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  });
};

// Helper function to create user response object
const createUserResponse = (user) => ({
  id: user._id.toString(), // Use consistent id field
  _id: user._id.toString(), // Keep _id for backward compatibility
  username: user.username,
  fullName: user.fullName,
  email: user.email,
  country: user.country,
  timezone: user.timezone,
  isVerified: user.isVerified,
  nextOnboardDate: user.nextOnboardDate,
  workCycles: user.workCycles || [],
  profilePicture: user.profilePicture,
  isGoogleUser: user.isGoogleUser,
  offshoreRole: user.offshoreRole || 'Support',
  company: user.company || null,
  unitName: user.unitName || null,
  workingRegime: user.workingRegime || {
    onDutyDays: 28,
    offDutyDays: 28
  },
  workSchedule: user.workSchedule || {}
});

// Rate limiting for token refresh
const refreshTokenLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  handler: (req, res) => {
    safeLog('Rate limit exceeded for refresh token endpoint', {
      ip: req.ip,
      path: req.path
    }, 'warn');
    res.status(429).json({ 
      message: 'Too many refresh token attempts. Please try again later.',
      retryAfter: Math.ceil(windowMs / 1000 / 60) // minutes
    });
  }
});

// Refresh token endpoint
router.post('/refresh-token', refreshTokenLimiter, async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      safeLog('Refresh token missing in request', { ip: req.ip }, 'warn');
      return res.status(400).json({ message: 'Refresh token is required' });
    }

    // Log the refresh token attempt (first few characters only for security)
    safeLog('Refresh token attempt', { 
      tokenFirstChars: refreshToken.substring(0, 10) + '...',
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    // Verify refresh token
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (jwtError) {
      safeLog('Invalid refresh token', { 
        error: jwtError.message,
        name: jwtError.name,
        ip: req.ip,
        userAgent: req.headers['user-agent']
      }, 'warn');
      return res.status(401).json({ 
        message: 'Invalid refresh token',
        error: jwtError.name === 'TokenExpiredError' ? 'Token has expired' : 'Token is invalid'
      });
    }

    // Find user and check if refresh token exists and is valid
    const user = await User.findById(decoded.userId);
    if (!user) {
      safeLog('User not found during token refresh', { 
        userId: decoded.userId,
        ip: req.ip,
        userAgent: req.headers['user-agent']
      }, 'warn');
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if user has any refresh tokens at all
    if (!user.refreshTokens || user.refreshTokens.length === 0) {
      safeLog('User has no refresh tokens', {
        userId: user._id,
        ip: req.ip,
        userAgent: req.headers['user-agent']
      }, 'warn');
      return res.status(401).json({ message: 'No refresh tokens found for user' });
    }

    // Find the specific token in the user's tokens array
    const storedToken = user.refreshTokens.find(t => t.token === refreshToken);
    
    // First check if token exists at all
    if (!storedToken) {
      safeLog('Refresh token not found in user records', { 
        userId: user._id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        tokenCount: user.refreshTokens.length
      }, 'warn');
      return res.status(401).json({ message: 'Refresh token not found', error: 'token_not_found' });
    }
    
    // Then check if token is revoked
    if (storedToken.isRevoked) {
      safeLog('Attempted to use revoked refresh token', { 
        userId: user._id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        revokedAt: storedToken.revokedAt
      }, 'warn');
      return res.status(401).json({ message: 'Refresh token has been revoked', error: 'token_revoked' });
    }
    
    // Finally check if token is expired
    if (storedToken.expiresAt < new Date()) {
      safeLog('Attempted to use expired refresh token', { 
        userId: user._id,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        expiresAt: storedToken.expiresAt,
        currentTime: new Date()
      }, 'warn');
      return res.status(401).json({ message: 'Refresh token has expired', error: 'token_expired' });
    }

    // Generate new tokens
    const { token: newToken, refreshToken: newRefreshToken } = generateTokens(user);

    // Revoke old refresh token
    storedToken.isRevoked = true;
    storedToken.revokedAt = new Date();

    // Store new refresh token
    await storeRefreshToken(user, newRefreshToken);

    // Set cookies in response with production-specific settings
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    };

    res.cookie('token', newToken, { ...cookieOptions, maxAge: 15 * 60 * 1000 }); // 15 minutes
    res.cookie('refreshToken', newRefreshToken, cookieOptions);

    // Log successful token refresh
    safeLog('Refresh token successfully exchanged', { 
      userId: user._id,
      ip: req.ip,
      environment: process.env.NODE_ENV,
      cookieSecure: cookieOptions.secure,
      cookieSameSite: cookieOptions.sameSite
    }, 'info');

    // Return new tokens and user data
    res.json({
      token: newToken,
      refreshToken: newRefreshToken,
      user: createUserResponse(user)
    });

  } catch (error) {
    safeLog('Error in refresh token:', redactSensitiveData(error), 'error');
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }
    res.status(500).json({ message: 'Server error during token refresh' });
  }
});

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

    // Generate tokens
    const tokens = await generateTokens(newUser);
    setAuthCookies(res, tokens);

    // Return user info and token (excluding password)
    const userResponse = {
      _id: newUser._id,
      username: newUser.username,
      email: newUser.email,
      fullName: newUser.fullName,
      offshoreRole: newUser.offshoreRole,
      workingRegime: newUser.workingRegime,
      isGoogleUser: newUser.isGoogleUser,
      company: newUser.company || null,
      unitName: newUser.unitName || null,
      country: newUser.country,
      profilePicture: newUser.isGoogleUser ? undefined : null // Explicitly set to null for non-Google users
    };

    res.status(201).json({ 
      user: userResponse, 
      token: tokens.accessToken,
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

// Country mapping function
const mapCountryToCode = (countryName) => {
  // Use the getCountryCode function from server utils
  return getCountryCode(countryName);
};

// Google Login/Registration
router.post('/google-login', validateGoogleToken, async (req, res) => {
  try {
    safeLog('Google login request received');
    
    // Validate required fields
    if (!req.googleUser || !req.googleUser.email) {
      safeLog('Missing Google user info:', { hasUser: !!req.googleUser });
      return res.status(400).json({ 
        message: 'Invalid Google authentication',
        error: 'Missing required user information'
      });
    }

    // Destructure validated Google user info
    const { email, name, picture, country } = req.googleUser;
    safeLog('Processing Google login for:', redactSensitiveData(email));

    // Map country name to country code
    const countryCode = mapCountryToCode(country);
    safeLog('Mapped country code:', countryCode);

    // Find or create user
    let user;
    try {
      user = await User.findOne({ email });
      safeLog('Existing user found:', !!user);
    } catch (findError) {
      safeLog('Error finding user:', redactSensitiveData(findError));
      throw findError;
    }

    if (!user) {
      safeLog('Creating new user for Google login');
      // Create new user with Google credentials
      const username = email.split('@')[0];
      user = new User({
        email,
        username,
        fullName: name,
        isGoogleUser: true,
        profilePicture: picture,
        isVerified: true,
        country: countryCode,
        offshoreRole: 'Support',
        workingRegime: {
          onDutyDays: 28,
          offDutyDays: 28
        }
      });
      
      try {
        await user.save();
        safeLog('New Google user created successfully');
      } catch (saveError) {
        safeLog('Error saving new Google user:', redactSensitiveData(saveError));
        // Check if username already exists
        if (saveError.code === 11000) {
          // Try with a unique username
          user.username = `${username}_${Math.random().toString(36).substr(2, 5)}`;
          await user.save();
          safeLog('Saved user with modified username');
        } else {
          throw saveError;
        }
      }
    } else {
      safeLog('Updating existing user profile');
      // Update existing user's profile
      user.profilePicture = picture || user.profilePicture;
      user.isGoogleUser = true;
      
      // Only update country if it's not already set
      if (!user.country || user.country === 'Unknown') {
        user.country = countryCode;
      }

      try {
        await user.save();
        safeLog('Updated existing user profile');
      } catch (updateError) {
        safeLog('Error updating user profile:', redactSensitiveData(updateError));
        throw updateError;
      }
    }

    // Ensure user has required fields for token generation
    if (!user._id || !user.email || !user.username) {
      safeLog('Invalid user object:', {
        hasId: !!user._id,
        hasEmail: !!user.email,
        hasUsername: !!user.username
      });
      throw new Error('Invalid user object for token generation');
    }

    safeLog('Generating tokens for user');
    // Generate tokens
    const { token, refreshToken } = generateTokens(user);

    safeLog('Storing refresh token');
    // Store refresh token
    await storeRefreshToken(user, refreshToken);

    safeLog('Sending response');
    // Return tokens and user data
    res.json({
      token,
      refreshToken,
      user: createUserResponse(user)
    });

  } catch (error) {
    safeLog('Google login error:', {
      name: error.name,
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ 
      message: 'Error during Google authentication',
      error: error.message
    });
  }
});

// Google login with calendar scope
router.post('/google-login-with-calendar', async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ message: 'Authorization code is required' });
    }
    
    safeLog('Received Google auth code for login with calendar scope');
    
    // Exchange the authorization code for tokens
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: process.env.REACT_APP_FRONTEND_URL || 'http://localhost:3000',
      grant_type: 'authorization_code'
    });
    
    // Get access and refresh tokens
    const { access_token, refresh_token, id_token } = tokenResponse.data;
    
    if (!access_token || !id_token) {
      return res.status(400).json({ message: 'Failed to obtain Google tokens' });
    }
    
    // Get user info using the access token
    const userInfoResponse = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    
    const googleUserInfo = userInfoResponse.data;
    
    if (!googleUserInfo.email) {
      return res.status(400).json({ message: 'Failed to obtain user email from Google' });
    }
    
    safeLog(`Google user info retrieved for: ${googleUserInfo.email}`);
    
    // Check if user exists
    let user = await User.findOne({ email: googleUserInfo.email });
    
    if (user) {
      // Update existing user with Google info if needed
      if (!user.isGoogleUser) {
        user.isGoogleUser = true;
        user.googleId = googleUserInfo.sub;
        user.isVerified = true;
        
        // Store Google Calendar token information
        user.googleCalendarToken = access_token;
        user.googleCalendarRefreshToken = refresh_token;
        user.googleCalendarTokenExpiry = new Date(Date.now() + tokenResponse.data.expires_in * 1000);
        
        await user.save();
        safeLog(`Updated existing user with Google Calendar info: ${user.email}`);
      } else {
        // Update Google Calendar token information
        user.googleCalendarToken = access_token;
        if (refresh_token) {
          user.googleCalendarRefreshToken = refresh_token;
        }
        user.googleCalendarTokenExpiry = new Date(Date.now() + tokenResponse.data.expires_in * 1000);
        await user.save();
        safeLog(`Updated Google Calendar tokens for existing user: ${user.email}`);
      }
    } else {
      // Create new user with Google info
      safeLog('Creating new user for Google login with calendar scope');
      const username = googleUserInfo.email.split('@')[0];
      user = new User({
        email: googleUserInfo.email,
        username,
        fullName: googleUserInfo.name,
        isGoogleUser: true,
        googleId: googleUserInfo.sub,
        profilePicture: googleUserInfo.picture,
        isVerified: true,
        country: 'US', // Default country code: US
        offshoreRole: 'Support', // Default role: Support
        workingRegime: {
          onDutyDays: 28,
          offDutyDays: 28
        },
        // Store Google Calendar token information
        googleCalendarToken: access_token,
        googleCalendarRefreshToken: refresh_token,
        googleCalendarTokenExpiry: new Date(Date.now() + tokenResponse.data.expires_in * 1000)
      });
      
      try {
        await user.save();
        safeLog('New Google user created successfully with calendar scope');
      } catch (saveError) {
        safeLog('Error saving new Google user:', saveError);
        // Check if username already exists
        if (saveError.code === 11000) {
          // Try with a unique username
          user.username = `${username}_${Math.random().toString(36).substr(2, 5)}`;
          await user.save();
          safeLog('Saved user with modified username');
        } else {
          throw saveError;
        }
      }
    }
    
    // Generate tokens for authentication
    const { token, refreshToken } = generateTokens(user);
    
    // Store refresh token
    await storeRefreshToken(user, refreshToken);
    
    // Return tokens and user data
    res.json({
      token,
      refreshToken,
      user: createUserResponse(user)
    });
    
  } catch (error) {
    safeLog('Google login with calendar scope error:', {
      name: error.name,
      message: error.message,
      response: error.response?.data
    });
    
    res.status(500).json({
      message: 'Error during Google authentication with calendar scope',
      error: error.message
    });
  }
});

// Get Google Calendar token for authenticated users
router.post('/google-calendar-token', async (req, res) => {
  try {
    // Get token from headers, body, or cookies (in that order of preference)
    let token = req.headers.authorization?.split(' ')[1] || 
                req.body.token || 
                req.cookies.token || 
                req.cookies.token_pwa;
    
    if (!token) {
      console.error('Google Calendar token request missing token', {
        hasAuthHeader: !!req.headers.authorization,
        hasBodyToken: !!req.body.token,
        hasCookieToken: !!req.cookies.token,
        hasPwaCookieToken: !!req.cookies.token_pwa
      });
      return res.status(401).json({ message: 'No token provided' });
    }
    
    console.log('Processing Google Calendar token request with token', {
      tokenLength: token.length,
      tokenFirstChars: token.substring(0, 20) + '...'
    });
    
    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ message: 'Invalid token' });
    }
    
    // Get user from database
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check if user has Google Calendar token
    if (!user.googleCalendarToken) {
      return res.status(404).json({ message: 'No Google Calendar token found' });
    }
    
    // Check if token is expired
    const isTokenExpired = user.googleCalendarTokenExpiry && new Date() > new Date(user.googleCalendarTokenExpiry);
    
    if (isTokenExpired && user.googleCalendarRefreshToken) {
      try {
        // Refresh the token
        const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          refresh_token: user.googleCalendarRefreshToken,
          grant_type: 'refresh_token'
        });
        
        // Update user with new token
        user.googleCalendarToken = tokenResponse.data.access_token;
        user.googleCalendarTokenExpiry = new Date(Date.now() + tokenResponse.data.expires_in * 1000);
        await user.save();
        
        // Return the new token
        return res.json({
          access_token: user.googleCalendarToken,
          expires_in: Math.floor((new Date(user.googleCalendarTokenExpiry) - new Date()) / 1000)
        });
      } catch (error) {
        console.error('Error refreshing Google token:', error.response?.data || error.message);
        return res.status(401).json({ message: 'Failed to refresh Google token' });
      }
    }
    
    // Return the token
    return res.json({
      access_token: user.googleCalendarToken,
      expires_in: user.googleCalendarTokenExpiry ? 
        Math.floor((new Date(user.googleCalendarTokenExpiry) - new Date()) / 1000) : 
        3600 // Default 1 hour if no expiry is set
    });
    
  } catch (error) {
    console.error('Error getting Google Calendar token:', error);
    res.status(500).json({
      message: 'Error retrieving Google Calendar token',
      error: error.message
    });
  }
});

// Google token exchange for calendar access (original endpoint)
router.post('/google-token-exchange', async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ message: 'Authorization code is required' });
    }
    
    // Exchange the authorization code for tokens
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: process.env.REACT_APP_FRONTEND_URL || 'http://localhost:3000',
      grant_type: 'authorization_code'
    });
    
    res.json({
      access_token: tokenResponse.data.access_token,
      expires_in: tokenResponse.data.expires_in
    });
    
  } catch (error) {
    console.error('Google token exchange error:', error.response?.data || error.message);
    res.status(500).json({
      message: 'Error exchanging Google authorization code',
      error: error.response?.data?.error || error.message
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

    // Clear all auth-related cookies
    const cookiesToClear = ['token', 'refreshToken', 'user', 'XSRF-TOKEN'];
    cookiesToClear.forEach(cookieName => {
      res.clearCookie(cookieName, {
        httpOnly: cookieName === 'token' || cookieName === 'refreshToken',
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
      });
    });

    res.json({ 
      message: 'Account deleted successfully',
      clearAuth: true
    });
  } catch (error) {
    safeLog('Account deletion error:', redactSensitiveData(error), 'error');
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }
    
    res.status(500).json({ message: 'Error deleting account' });
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
      { expiresIn: '15m' } // 15 minutes
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
// Supports nocache parameter to bypass any caching and get fresh data
router.get('/profile', async (req, res) => {
  try {
    // Get token from headers
    const authHeader = req.headers.authorization;
    
    // Debug auth header
    safeLog('Profile Request Auth:', {
      hasAuthHeader: !!authHeader,
      headerValue: authHeader ? `${authHeader.substring(0, 20)}...` : 'none'
    });

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];

    // Debug raw token
    safeLog('Raw token:', {
      length: token?.length,
      firstChars: token ? `${token.substring(0, 20)}...` : 'none'
    });

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Debug decoded token
      safeLog('Decoded token:', {
        userId: decoded.userId,
        email: decoded.email,
        isGoogleUser: decoded.isGoogleUser
      });
    } catch (error) {
      // Log the specific JWT error
      safeLog('JWT Verification Error:', {
        name: error.name,
        message: error.message,
        token: token ? `${token.substring(0, 20)}...` : 'none'
      });

      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      return res.status(401).json({ 
        message: 'Invalid token',
        error: error.name
      });
    }

    // Check if nocache parameter is present to bypass any caching
    const bypassCache = req.query.nocache !== undefined;

    // Log cache status for debugging
    safeLog('Profile request cache status:', {
      bypassCache,
      nocacheParam: req.query.nocache
    });

    // Find user with a fresh database query when nocache is present
    let user;
    if (bypassCache) {
      // Force a fresh query by using findOne with lean() to get a plain JS object
      // This bypasses any potential mongoose document caching
      user = await User.findOne({ _id: decoded.userId }).lean();
      safeLog('Profile fetch using fresh query due to nocache parameter');
    } else {
      // Standard query when no cache bypass is requested
      user = await User.findById(decoded.userId);
    }

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate new token for the response
    const newToken = jwt.sign(
      { 
        userId: user._id.toString(),
        email: user.email,
        username: user.username,
        isGoogleUser: user.isGoogleUser,
        fullName: user.fullName
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '15m' } // 15 minutes
    );

    // Return user profile with new token
    res.json({ 
      user: createUserResponse(user),
      token: newToken
    });
  } catch (error) {
    safeLog('Profile fetch error:', error, 'error');
    res.status(500).json({ message: 'Server error fetching profile' });
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

    // Get on board date and past date flag from request
    const { nextOnBoardDate, allowPastDates = false } = req.body;

    if (!nextOnBoardDate) {
      return res.status(400).json({ message: 'Next on board date is required' });
    }

    // Validate date
    const onBoardDate = new Date(nextOnBoardDate);
    if (isNaN(onBoardDate.getTime())) {
      return res.status(400).json({ message: 'Invalid date provided' });
    }

    // Check if past dates are allowed
    const now = new Date();
    if (!allowPastDates && onBoardDate < now) {
      return res.status(400).json({ 
        message: 'Past dates are not allowed. Use allowPastDates flag to override.',
        currentDate: now.toISOString()
      });
    }

    // Ensure working regime is set
    const onDutyDays = user.workingRegime?.onDutyDays || 14;
    const offDutyDays = user.workingRegime?.offDutyDays || 14;

    // Calculate off board date based on current working regime
    const offBoardDate = new Date(onBoardDate);
    offBoardDate.setDate(offBoardDate.getDate() + onDutyDays);

    // Update user's work schedule
    user.workSchedule = {
      nextOnBoardDate: onBoardDate,
      nextOffBoardDate: offBoardDate
    };

    // Generate work cycles based on the new onboard date
    const workCycles = [];
    const twoYearsFromNow = new Date(onBoardDate);
    twoYearsFromNow.setFullYear(twoYearsFromNow.getFullYear() + 2);

    let currentDate = new Date(onBoardDate);
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

    // Update user's work cycles
    user.workCycles = workCycles;

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
      { expiresIn: '15m' } // 15 minutes
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
        workCycles: user.workCycles,
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
    
    // Clear work cycles as they are no longer valid without a nextOnBoardDate
    user.workCycles = [];

    // Save the updated user
    await user.save();

    res.json({ 
      message: 'Work schedule reset successfully',
      workSchedule: user.workSchedule,
      workCycles: user.workCycles
    });
  } catch (error) {
    safeLog('Error resetting work schedule:', redactSensitiveData(error), 'error');
    res.status(500).json({ 
      message: 'Server error while resetting work schedule',
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
    await newFriendRequest.populate('user friend', 'fullName email profilePicture company unitName');

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
    const { requestId } = req.params;
    const { status } = req.body;

    if (!['ACCEPTED', 'DECLINED'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const friendRequest = await Friend.findOneAndUpdate(
      { 
        _id: requestId, 
        friend: currentUserId,
        status: 'PENDING'
      },
      { status },
      { new: true }
    );

    if (!friendRequest) {
      return res.status(404).json({ message: 'Friend request not found' });
    }

    // If the request was accepted, return the friend data for immediate UI update
    let friendData = null;
    if (status === 'ACCEPTED') {
      // Get the requester's user data to return to the client
      const friendUser = await User.findById(friendRequest.user);
      if (friendUser) {
        friendData = {
          _id: friendUser._id,
          id: friendUser._id, // Include both formats for compatibility
          fullName: friendUser.fullName,
          email: friendUser.email,
          profilePicture: friendUser.profilePicture,
          company: friendUser.company || '',
          unitName: friendUser.unitName || '',
          sharingPreferences: friendRequest.sharingPreferences || { allowScheduleSync: false }
        };
      }
    }

    res.status(200).json({ 
      message: 'Friend request updated', 
      status: friendRequest.status,
      friendData
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
    })
    .populate('user', 'fullName email profilePicture company unitName')
    .populate('friend', 'fullName email profilePicture company unitName');

    // Transform friendships to include friend details and mutual sync preferences
    const friends = friendships.map(friendship => {
      // Determine if current user is the initiator or receiver of friendship
      const isInitiator = friendship.user._id.toString() === currentUserId;
      const friendData = isInitiator ? friendship.friend : friendship.user;
      
      // Get sync preferences from both perspectives
      const myPreferences = isInitiator ? friendship.sharingPreferences : friendship.friendSharingPreferences;
      const theirPreferences = isInitiator ? friendship.friendSharingPreferences : friendship.sharingPreferences;

      // Calculate the effective sync status
      const myAllowSync = myPreferences?.allowScheduleSync || false;
      const theirAllowSync = theirPreferences?.allowScheduleSync || false;
      
      // For sync to be fully enabled, both users need to have allowScheduleSync set to true
      const effectiveSyncEnabled = myAllowSync && theirAllowSync;
      
      return {
        _id: friendData._id,
        fullName: friendData.fullName,
        email: friendData.email,
        profilePicture: friendData.profilePicture,
        company: friendData.company || '',
        unitName: friendData.unitName || '',
        sharingPreferences: {
          // Main sync toggle for UI display - this is what the toggle in FriendManagement controls
          allowScheduleSync: myAllowSync,
          // Whether I've enabled sync to see their schedule
          iCanSeeTheirSchedule: myAllowSync,
          // Whether they've enabled sync to let me see their schedule
          theyCanSeeMySchedule: theirAllowSync,
          // Whether sync is effectively enabled (both sides have enabled it)
          effectiveSyncEnabled: effectiveSyncEnabled
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

    // First, find any users that the current user has blocked
    const blockedFriendships = await Friend.find({
      $or: [
        { user: currentUserId, status: 'BLOCKED' },
        { friend: currentUserId, status: 'BLOCKED' }
      ]
    });
    
    // Extract the IDs of blocked users
    const blockedUserIds = blockedFriendships.map(friendship => 
      friendship.user.toString() === currentUserId.toString() 
        ? friendship.friend.toString() 
        : friendship.user.toString()
    );
    
    // Find pending friend requests for the current user, excluding blocked users
    const pendingRequests = await Friend.find({
      friend: currentUserId,
      status: 'PENDING',
      user: { $nin: blockedUserIds } // Exclude requests from blocked users
    }).populate('user', 'fullName email profilePicture company unitName');

    const requests = pendingRequests.map(request => ({
      id: request._id,
      user: {
        id: request.user._id,
        fullName: request.user.fullName,
        email: request.user.email,
        profilePicture: request.user.profilePicture,
        company: request.user.company || '',
        unitName: request.user.unitName || ''
      },
      requestedAt: request.requestedAt
    }));

    res.status(200).json({ pendingRequests: requests });

  } catch (error) {
    safeLog('Get pending requests error:', redactSensitiveData(error), 'error');
    res.status(500).json({ message: 'Server error retrieving pending requests' });
  }
});

// Block Friend
router.put('/friend/block/:friendId', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;
    const { friendId } = req.params;
    
    if (!friendId) {
      return res.status(400).json({ message: 'Friend ID is required' });
    }

    // Find the friendship (in either direction)
    const friendship = await Friend.findOne({
      $or: [
        { user: currentUserId, friend: friendId },
        { user: friendId, friend: currentUserId }
      ]
    });

    if (!friendship) {
      return res.status(404).json({ message: 'Friendship not found' });
    }

    // Update the status to BLOCKED
    friendship.status = 'BLOCKED';
    await friendship.save();

    res.status(200).json({ 
      message: 'Friend has been blocked', 
      friendshipId: friendship._id 
    });
  } catch (error) {
    safeLog('Block friend error:', redactSensitiveData(error), 'error');
    res.status(500).json({ message: 'Server error blocking friend' });
  }
});

// Remove Friend
router.delete('/friend/:friendId', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;
    const { friendId } = req.params;
    
    if (!friendId) {
      return res.status(400).json({ message: 'Friend ID is required' });
    }

    // Find and remove the friendship (in either direction)
    const result = await Friend.findOneAndDelete({
      $or: [
        { user: currentUserId, friend: friendId },
        { user: friendId, friend: currentUserId }
      ]
    });

    if (!result) {
      return res.status(404).json({ message: 'Friendship not found' });
    }

    res.status(200).json({ 
      message: 'Friend has been removed', 
      friendshipId: result._id 
    });
  } catch (error) {
    safeLog('Remove friend error:', redactSensitiveData(error), 'error');
    res.status(500).json({ message: 'Server error removing friend' });
  }
});

// Search Users Route
router.get('/search-users', async (req, res) => {
  try {
    const { query } = req.query;
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    if (!query || query.length < 2) {
      return res.status(400).json({ message: 'Search query must be at least 2 characters long' });
    }

    // Search users by name or email, excluding the current user
    const users = await User.find({
      _id: { $ne: currentUserId },
      $or: [
        { fullName: { $regex: query, $options: 'i' } },
        { email: { $regex: query, $options: 'i' } }
      ]
    }).select('fullName email profilePicture company unitName');

    // Get friend status for each user
    const friendships = await Friend.find({
      $or: [
        { user: currentUserId },
        { friend: currentUserId }
      ]
    });

    const usersWithStatus = users.map(user => {
      const friendship = friendships.find(f => 
        (f.user.toString() === user._id.toString() || f.friend.toString() === user._id.toString())
      );

      return {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        profilePicture: user.profilePicture,
        company: user.company || '',
        unitName: user.unitName || '',
        friendshipStatus: friendship ? friendship.status : 'NONE'
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
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour

    // Update user with reset token
    user.passwordResetToken = resetToken;
    user.passwordResetTokenExpires = resetTokenExpiry;
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
        message: 'Failed to send password reset email',
        error: emailError.message
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

// Toggle friend sync status
router.put('/friend-sync/:friendId', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;
    const { friendId } = req.params;
    const { allowScheduleSync } = req.body;

    // Find the friendship document
    const friendship = await Friend.findOne({
      $or: [
        { user: currentUserId, friend: friendId, status: 'ACCEPTED' },
        { user: friendId, friend: currentUserId, status: 'ACCEPTED' }
      ]
    });

    if (!friendship) {
      return res.status(404).json({ 
        success: false,
        message: 'Friendship not found' 
      });
    }

    // Determine if current user is the initiator or receiver
    const isInitiator = friendship.user._id.toString() === currentUserId;
    
    // Update the appropriate sharing preferences
    const updateQuery = isInitiator
      ? { sharingPreferences: { allowScheduleSync } }
      : { friendSharingPreferences: { allowScheduleSync } };

    // Update and get the new document in one operation
    const updatedFriendship = await Friend.findByIdAndUpdate(
      friendship._id,
      { $set: updateQuery },
      { 
        new: true,
        runValidators: true
      }
    ).populate('user', 'fullName email profilePicture company unitName')
      .populate('friend', 'fullName email profilePicture company unitName');

    if (!updatedFriendship) {
      return res.status(404).json({
        success: false,
        message: 'Failed to update friendship'
      });
    }

    // Format the response with mutual sync status
    const friendData = isInitiator ? updatedFriendship.friend : updatedFriendship.user;
    const myPreferences = isInitiator ? updatedFriendship.sharingPreferences : updatedFriendship.friendSharingPreferences;
    const theirPreferences = isInitiator ? updatedFriendship.friendSharingPreferences : updatedFriendship.sharingPreferences;

    const formattedResponse = {
      success: true,
      message: allowScheduleSync ? 'Sync enabled' : 'Sync disabled',
      friend: {
        _id: friendData._id,
        id: friendData._id,
        fullName: friendData.fullName,
        email: friendData.email,
        profilePicture: friendData.profilePicture,
        company: friendData.company || '',
        unitName: friendData.unitName || '',
        sharingPreferences: {
          allowScheduleSync: myPreferences?.allowScheduleSync || false,
          iCanSeeTheirSchedule: myPreferences?.allowScheduleSync || false,
          theyCanSeeMySchedule: theirPreferences?.allowScheduleSync || false
        }
      }
    };

    res.status(200).json(formattedResponse);

  } catch (error) {
    safeLog('Toggle friend sync error:', redactSensitiveData(error), 'error');
    res.status(500).json({ 
      success: false,
      message: 'Server error toggling sync status' 
    });
  }
});

// Note: The Google token exchange endpoint is now consolidated at line ~1220

// Create Google Calendar event with attendees
router.post('/google-calendar-event', async (req, res) => {
  try {
    const { accessToken, event, attendeeIds } = req.body;
    const token = req.headers.authorization?.split(' ')[1];

    if (!accessToken || !event) {
      return res.status(400).json({ error: 'Access token and event details are required' });
    }

    // Get the current user's ID from the JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    // Get the current user's email
    const currentUser = await User.findById(currentUserId);
    if (!currentUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get attendee emails from friend IDs
    let attendees = [];
    safeLog('Calendar event creation - received data:', {
      attendeeIds: redactSensitiveData(attendeeIds),
      currentUserId: redactSensitiveData(currentUserId),
      currentUserEmail: redactSensitiveData(currentUser.email)
    });

    if (attendeeIds && attendeeIds.length > 0) {
      // Find friends with mutual sync enabled using Friend model
      const Friend = require('../models/Friend');

      // Find friend relationships where both users have enabled sharing
      const friendships = await Friend.find({
        $or: [
          // Current user is the 'user', friend is in attendeeIds
          {
            user: currentUserId,
            friend: { $in: attendeeIds },
            status: 'ACCEPTED',
            'sharingPreferences.allowScheduleSync': true,
            'friendSharingPreferences.allowScheduleSync': true
          },
          // Current user is the 'friend', user is in attendeeIds
          {
            friend: currentUserId,
            user: { $in: attendeeIds },
            status: 'ACCEPTED',
            'friendSharingPreferences.allowScheduleSync': true,
            'sharingPreferences.allowScheduleSync': true
          }
        ]
      }).populate('user friend', 'email');

      safeLog('Calendar event creation - found friendships:', 
        redactSensitiveData(friendships.map(f => ({
          id: f._id,
          userEmail: f.user.email,
          friendEmail: f.friend.email,
          status: f.status,
          sharingPreferences: f.sharingPreferences,
          friendSharingPreferences: f.friendSharingPreferences
        })))
      );

      // Extract friend emails from the relationships
      const friendEmails = friendships.map(friendship => {
        const friendEmail = friendship.user._id.toString() === currentUserId ?
          friendship.friend.email : friendship.user.email;
        return {
          email: friendEmail,
          responseStatus: 'needsAction'
        };
      });

      attendees = friendEmails;
      safeLog('Calendar event creation - attendees list:', redactSensitiveData(attendees));
    }

    // Add attendees to the event
    const eventWithAttendees = {
      ...event,
      // Ensure creator and organizer are set
      creator: {
        email: currentUser.email,
        self: true
      },
      organizer: {
        email: currentUser.email,
        self: true
      },
      // Add all attendees including the creator
      attendees: [
        {
          email: currentUser.email,
          responseStatus: 'accepted',
          organizer: true,
          self: true
        },
        ...attendees
      ],
      // Ensure reminders are enabled
      reminders: {
        useDefault: true
      }
    };

    // Add sendUpdates parameter and ensure proper event configuration
    const finalEvent = {
      ...eventWithAttendees,
      guestsCanSeeOtherGuests: true,
      guestsCanModify: false,
      guestsCanInviteOthers: false
    };

    safeLog('Calendar event creation - final event:', redactSensitiveData(finalEvent));

    // Make API call to create event and send notifications
    try {
      const response = await axios.post(
        'https://www.googleapis.com/calendar/v3/calendars/primary/events',
        finalEvent,
        {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          params: {
            sendUpdates: 'all',  // Ensures notifications are sent to all attendees
            supportsAttachments: false,
            conferenceDataVersion: 0
          },
          timeout: 30000  // Increase timeout to 30 seconds
        }
      );
      
      safeLog('Calendar event creation - Google Calendar API response:', redactSensitiveData(response.data));
      res.json(response.data);
    } catch (error) {
      safeLog('Calendar event creation - Google Calendar API error:', redactSensitiveData(error.response?.data || error.message), 'error');
      res.status(error.response?.status || 500).json({
        error: error.response?.data?.error || error.message
      });
    }
  } catch (error) {
    console.error('Error creating Google Calendar event:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({
      error: error.response?.data?.error || 'Failed to create calendar event'
    });
  }
});

module.exports = router;
