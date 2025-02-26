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
    '/api/auth/check-session',
    '/api/csrf-token',
    '/api/auth/register',
    '/api/auth/login',
    '/api/auth/refresh',
    '/api/password/request-reset',
    '/api/password/reset'
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
app.use(cors({
  origin: process.env.REACT_APP_FRONTEND_URL || 'http://localhost:3000',
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
    'Cookie'
  ],
  exposedHeaders: ['X-CSRF-Token', 'Set-Cookie'],
  maxAge: 600 // 10 minutes
}));

// Cookie parser middleware
app.use(cookieParser());

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logging middleware
app.use(morgan('dev'));

app.use(csrfProtection);

// API routes
const apiRouter = express.Router();
app.use('/api', apiRouter);

// Mount auth routes
const authRoutes = require('./routes/auth');
const passwordResetRoutes = require('./routes/passwordReset');
apiRouter.use('/auth', authRoutes);
apiRouter.use('/password', passwordResetRoutes);

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
