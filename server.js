const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');  // Add path module
const crypto = require('crypto');
const cookieParser = require('cookie-parser');  // Add this import
const jwt = require('jsonwebtoken'); // Add jwt import
require('dotenv').config();

const app = express();

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
    '/api/auth/password/request-reset'
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
      console.warn('Invalid JWT token, proceeding with CSRF check', { path: req.path });
    }
  }

  // Validate CSRF for other routes
  const csrfCookie = req.cookies['XSRF-TOKEN'];
  const csrfHeader = req.headers['x-xsrf-token'];

  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    console.error('CSRF Token Validation Failed', {
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

// Middleware
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:3000', 
      process.env.REACT_APP_FRONTEND_URL
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-Requested-With', 
    'X-XSRF-TOKEN',  // Explicitly allow CSRF token header
    'Accept'
  ],
  exposedHeaders: ['X-XSRF-TOKEN']  // Expose CSRF token header to client
}));

app.use(cookieParser());  // Add cookie-parser middleware
app.use(express.json());

// Handle preflight requests
app.options('*', cors());  // Enable preflight requests for all routes

app.use(csrfProtection);

// CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
  // Ensure CSRF token is set
  let csrfToken = req.cookies['XSRF-TOKEN'];
  
  if (!csrfToken) {
    csrfToken = generateCSRFToken();
    res.cookie('XSRF-TOKEN', csrfToken, {
      httpOnly: false,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production'
    });
  }

  console.log('CSRF Token Endpoint - Token:', csrfToken);

  res.json({ 
    csrfToken: csrfToken 
  });
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost/mern_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const connection = mongoose.connection;
connection.once('open', () => {
  console.log('MongoDB database connection established successfully');
});

// Routes
const authRoutes = require('./routes/auth');
const passwordResetRoutes = require('./routes/passwordReset');

app.use('/api/auth', authRoutes);
app.use('/api/password', passwordResetRoutes);

// Root route
app.get('/', (req, res) => {
  res.send('Welcome to the Offshore Sync Application');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});
