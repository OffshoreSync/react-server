const mongoose = require('mongoose');
const crypto = require('crypto');
const { safeLog, redactSensitiveData } = require('../utils/logger');

const PasswordResetSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  token: {
    type: String,
    required: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 } // Automatically delete document after expiration
  }
});

// Method to generate a secure reset token
PasswordResetSchema.statics.generateResetToken = function() {
  try {
    return crypto.randomBytes(32).toString('hex');
  } catch (error) {
    safeLog('Password reset model error:', redactSensitiveData(error));
  }
};

// Method to hash the token for secure storage
PasswordResetSchema.statics.hashToken = function(token) {
  try {
    return crypto.createHash('sha256').update(token).digest('hex');
  } catch (error) {
    safeLog('Password reset model error:', redactSensitiveData(error));
  }
};

module.exports = mongoose.model('PasswordReset', PasswordResetSchema);
