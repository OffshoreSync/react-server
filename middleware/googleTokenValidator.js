const { OAuth2Client } = require('google-auth-library');
const geoip = require('geoip-lite');
const { safeLog, redactSensitiveData } = require('../utils/logger');

// Debug log environment variables (redacted)
safeLog('Google Client ID available:', !!process.env.GOOGLE_CLIENT_ID);
safeLog('Google Client ID length:', process.env.GOOGLE_CLIENT_ID?.length || 0);

// Initialize OAuth client with server-side environment variable
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const validateGoogleToken = async (req, res, next) => {
  const { credential } = req.body;

  // Debug log request
  safeLog('Google token validation request:', {
    hasCredential: !!credential,
    credentialLength: credential?.length || 0
  });

  if (!credential) {
    return res.status(400).json({ message: 'No Google credential provided' });
  }

  try {
    // Debug log verification attempt
    safeLog('Attempting to verify token with client ID:', process.env.GOOGLE_CLIENT_ID?.substring(0, 10) + '...');
    
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    
    // Debug log payload
    safeLog('Token payload received:', {
      hasPayload: !!payload,
      email: payload?.email ? 'Present' : 'Missing',
      name: payload?.name ? 'Present' : 'Missing',
      picture: payload?.picture ? 'Present' : 'Missing',
      locale: payload?.locale || 'Missing'
    });
    
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

    // Debug log success
    safeLog('Successfully validated Google token for:', redactSensitiveData(email));

    next();
  } catch (error) {
    // Detailed error logging
    safeLog('Google token validation error:', {
      name: error.name,
      message: redactSensitiveData(error.message),
      stack: error.stack ? 'Present' : 'Missing'
    });

    return res.status(401).json({ 
      message: 'Failed to validate Google token',
      error: redactSensitiveData(error.message) 
    });
  }
};

module.exports = validateGoogleToken;
