const mongoose = require('mongoose');
const crypto = require('crypto');

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
  return crypto.randomBytes(32).toString('hex');
};

// Method to hash the token for secure storage
PasswordResetSchema.statics.hashToken = function(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
};

module.exports = mongoose.model('PasswordReset', PasswordResetSchema);
