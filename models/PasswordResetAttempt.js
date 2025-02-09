const mongoose = require('mongoose');

const PasswordResetAttemptSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true
  },
  ipAddress: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 24 * 60 * 60 // Document will be automatically deleted after 24 hours
  }
});

// Create an index to help with quick lookups and expiration
PasswordResetAttemptSchema.index({ email: 1, createdAt: 1 });

module.exports = mongoose.model('PasswordResetAttempt', PasswordResetAttemptSchema);