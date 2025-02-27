const mongoose = require('mongoose');
const { safeLog, redactSensitiveData } = require('../utils/logger');

const sharingPreferencesSchema = new mongoose.Schema({
  allowScheduleSync: {
    type: Boolean,
    default: false
  }
}, { _id: false });

const FriendSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  friend: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  status: {
    type: String,
    enum: ['PENDING', 'ACCEPTED', 'BLOCKED'],
    default: 'PENDING'
  },
  sharingPreferences: {
    type: sharingPreferencesSchema,
    default: () => ({})
  },
  friendSharingPreferences: {
    type: sharingPreferencesSchema,
    default: () => ({})
  },
  requestedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Ensure unique friend requests
FriendSchema.index({ user: 1, friend: 1 }, { unique: true });

module.exports = mongoose.model('Friend', FriendSchema);
