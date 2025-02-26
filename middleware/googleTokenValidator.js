const { OAuth2Client } = require('google-auth-library');
const geoip = require('geoip-lite');
const { safeLog, redactSensitiveData } = require('../utils/logger');

const client = new OAuth2Client(process.env.REACT_APP_GOOGLE_CLIENT_ID);

const validateGoogleToken = async (req, res, next) => {
  const { credential } = req.body;

  if (!credential) {
    return res.status(400).json({ message: 'No Google credential provided' });
  }

  try {
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.REACT_APP_GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    
    // Validate token payload
    if (!payload) {
      return res.status(401).json({ message: 'Invalid Google token' });
    }

    // Extract and validate key user information
    const { 
      email, 
      name, 
      picture, 
      sub: googleId,
      locale // Try to get locale information
    } = payload;

    if (!email || !name) {
      return res.status(401).json({ message: 'Incomplete user information' });
    }

    // Attempt to derive country from locale or IP
    let country = 'United States'; // Default fallback
    
    // Try to extract country from locale
    if (locale) {
      const countryCode = locale.split('_').pop();
      // Map some common locale codes to full country names
      const countryMap = {
        'US': 'United States',
        'CA': 'Canada',
        'GB': 'United Kingdom',
        'AU': 'Australia'
      };
      
      country = countryMap[countryCode] || 'United States';
    }

    // Attach validated user info to request
    req.googleUser = {
      email,
      name,
      picture,
      googleId,
      country,
      locale
    };

    next();
  } catch (error) {
    safeLog('Google token validation error:', redactSensitiveData(error));
    return res.status(401).json({ 
      message: 'Failed to validate Google token',
      error: redactSensitiveData(error.message) 
    });
  }
};

module.exports = validateGoogleToken;
