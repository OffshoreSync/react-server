const jwt = require('jsonwebtoken');
const { safeLog } = require('../utils/logger');

/**
 * Authentication middleware
 * Verifies JWT token and adds user info to request
 */
const auth = (req, res, next) => {
  // Get token from header
  const token = req.headers.authorization?.split(' ')[1];
  
  // Check if no token
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Add user from payload
    req.user = {
      id: decoded.userId,
      email: decoded.email
    };
    
    next();
  } catch (error) {
    safeLog('Token verification failed:', error);
    
    // Check if token expired
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: 'Token expired', 
        error: 'TOKEN_EXPIRED' 
      });
    }
    
    res.status(401).json({ message: 'Token is not valid' });
  }
};

module.exports = auth;
