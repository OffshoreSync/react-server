const mongoose = require('mongoose');

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
    allowScheduleSync: {
      type: Boolean,
      default: false
    }
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
