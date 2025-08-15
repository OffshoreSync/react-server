const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');  // Add path module
const crypto = require('crypto');
const jwt = require('jsonwebtoken'); // Add jwt import
require('dotenv').config();
const { safeLog } = require('./utils/logger');

const app = express();

// Security middleware
app.use(helmet({
  crossOriginEmbedderPolicy: false, // Required for Google Sign-In
  crossOriginOpenerPolicy: false, // Required for Google Sign-In popup
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'", process.env.REACT_APP_FRONTEND_URL],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://accounts.google.com", "https://apis.google.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", process.env.REACT_APP_FRONTEND_URL, process.env.REACT_APP_BACKEND_URL, "https://accounts.google.com"],
      frameSrc: ["'self'", "https://accounts.google.com"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  }
}));

// CSRF Protection Middleware
const generateCSRFToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

const csrfProtection = (req, res, next) => {
  // Always allow safe methods
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }

  // Completely exempt routes (minimal set)
  const exemptRoutes = [
    '/api/auth/google-login',
    '/api/auth/google-login-with-calendar',
    '/api/auth/google-calendar-token',
    '/api/auth/check-session',
    '/api/csrf-token',
    '/api/auth/register',
    '/api/auth/login',
    '/api/auth/refresh',
    '/api/password/request',
    '/api/password/request-reset',
    '/api/password/reset',
    '/api/password/verify-token',
    '/api/verify-email'
  ];

  if (exemptRoutes.some(route => req.path.startsWith(route))) {
    return next();
  }

  // Check for JWT token in Authorization header
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    try {
      // Verify the token to ensure it's valid
      jwt.verify(token, process.env.JWT_SECRET);
      // If token is valid, we can skip CSRF for authenticated routes
      return next();
    } catch (error) {
      // Token is invalid, continue with CSRF validation
      safeLog('Invalid JWT token, proceeding with CSRF check', { path: req.path });
    }
  }

  // Validate CSRF for other routes
  const csrfCookie = req.cookies['XSRF-TOKEN'];
  const csrfHeader = req.headers['x-csrf-token'] || req.headers['x-xsrf-token'];

  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    safeLog('CSRF Token Validation Failed', {
      path: req.path,
      method: req.method,
      hasCookie: !!csrfCookie,
      hasHeader: !!csrfHeader,
      tokensMatch: csrfCookie === csrfHeader
    });

    return res.status(403).json({ 
      message: 'CSRF token validation failed',
      error: 'INVALID_CSRF_TOKEN'
    });
  }

  next();
};

// CORS configuration
const allowedOrigins = [
  process.env.REACT_APP_FRONTEND_URL || 'http://localhost:3000',
  'capacitor://localhost',
  'ionic://localhost',
  'http://localhost',
  'https://react-client-static.onrender.com',  // Render domain frontend
  'https://react-client-staging.onrender.com',  // Render domain staging frontend
  null // allow null origin for service workers
];

// Regular expressions for local network IP addresses (for mobile testing)
const localNetworkRegexes = [
  /^https?:\/\/192\.168\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]+)?$/,
  /^https?:\/\/172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]+)?$/,
  /^https?:\/\/10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]+)?$/
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, curl requests)
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    // Only allow flexible origin checking in development mode
    if (process.env.NODE_ENV !== 'production') {
      // Check if origin matches any of the regex patterns (for local IP addresses)
      for (const pattern of localNetworkRegexes) {
        if (pattern.test(origin)) {
          safeLog(`Development mode - allowing CORS for local network: ${origin}`);
          return callback(null, true);
        }
      }
    }
    
    // Log the rejected origin for debugging
    safeLog(`CORS rejected origin: ${origin}`);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-XSRF-TOKEN',
    'X-Requested-With',
    'X-CSRF-Token',
    'Accept',
    'Origin',
    'Cookie',
    'Service-Worker-Allowed', // Add support for service worker
    'Cache-Control',          // Allow cache control headers in requests
    'Pragma',                 // Allow pragma header in requests
    'Expires'                 // Allow expires header in requests
  ],
  exposedHeaders: [
    'X-CSRF-Token', 
    'Set-Cookie',
    'Cache-Control',  // Expose cache control headers
    'ETag',          // Expose ETag for caching
    'Last-Modified'  // Expose last modified for caching
  ],
  maxAge: 86400 // 24 hours
}));

// Cookie parser middleware with secure settings
app.use(cookieParser(process.env.JWT_SECRET)); // Sign cookies with JWT secret

// Configure cookie settings for the entire app
app.use((req, res, next) => {
  res.cookie = res.cookie.bind(res);
  const originalCookie = res.cookie;
  res.cookie = function (name, value, options = {}) {
    const defaultOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days default
    };
    return originalCookie.call(this, name, value, { ...defaultOptions, ...options });
  };
  next();
});

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logging middleware
app.use(morgan('dev'));

app.use(csrfProtection);

// API routes
const apiRouter = express.Router();
app.use('/api', apiRouter);

// Import required models and utilities for email verification
const User = require('./models/User');
const rateLimit = require('express-rate-limit');

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

// Mount auth routes
const authRoutes = require('./routes/auth');
const passwordResetRoutes = require('./routes/passwordReset');
const notificationRoutes = require('./routes/notifications');
const eventRoutes = require('./routes/events');
apiRouter.use('/auth', authRoutes);
apiRouter.use('/password', passwordResetRoutes);
apiRouter.use('/notifications', notificationRoutes);
apiRouter.use('/events', eventRoutes);

// Health check endpoint for connectivity testing
apiRouter.head('/health', (req, res) => {
  res.status(200).end();
});

apiRouter.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Public username availability check endpoint
apiRouter.get('/check-username', async (req, res) => {
  try {
    const { username } = req.query;
    
    if (!username) {
      return res.status(400).json({ message: 'Username parameter is required' });
    }
    
    // Check if the username exists in the database
    const existingUser = await User.findOne({ username: username });
    
    // Return whether the username is available
    return res.json({ available: !existingUser });
  } catch (error) {
    console.error('Error checking username availability:', error);
    return res.status(500).json({ message: 'Server error checking username availability' });
  }
});

// Public email availability check endpoint
apiRouter.get('/check-email', async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ message: 'Email parameter is required' });
    }
    
    // Check if the email exists in the database
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    
    // Return whether the email is available
    return res.json({ available: !existingUser });
  } catch (error) {
    console.error('Error checking email availability:', error);
    return res.status(500).json({ message: 'Server error checking email availability' });
  }
});

// Public email verification endpoint
apiRouter.post('/verify-email', emailVerificationLimiter, async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ 
        message: 'Verification token is required' 
      });
    }

    const user = await User.findOne({
      verificationToken: token,
      verificationTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ 
        message: 'Invalid or expired verification token' 
      });
    }

    if (user.isVerified) {
      return res.status(400).json({ 
        message: 'Email is already verified' 
      });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();

    res.json({ 
      success: true,
      message: 'Email verified successfully' 
    });
  } catch (error) {
    safeLog('Email verification error:', error, 'error');
    res.status(500).json({ 
      message: 'Server error during email verification' 
    });
  }
});

// CSRF token endpoint
apiRouter.get('/csrf-token', (req, res) => {
  // Ensure CSRF token is set
  let csrfToken = req.cookies['XSRF-TOKEN'];
  
  if (!csrfToken) {
    csrfToken = generateCSRFToken();
    res.cookie('XSRF-TOKEN', csrfToken, {
      httpOnly: false,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      path: '/'
    });
  }

  res.json({ 
    csrfToken: csrfToken 
  });
});

// Root route
app.get('/', (req, res) => {
  res.send('Welcome to the Offshore Sync Application');
});

// Home route - serves the same content as root for SEO purposes
app.get('/home', (req, res) => {
  res.send('Welcome to the Offshore Sync Application');
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost/mern_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const connection = mongoose.connection;
connection.once('open', () => {
  safeLog('MongoDB database connection established successfully');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  safeLog(`Server is running on port: ${PORT}`);
});
