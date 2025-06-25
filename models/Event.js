const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * Event Schema for custom user-created calendar events
 * These events are separate from the work cycle visualization
 */
const EventSchema = new Schema({
  // User who created the event
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  // Event details
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  startDate: {
    type: Date,
    required: true,
    index: true
  },
  endDate: {
    type: Date,
    required: true,
    index: true
  },
  location: {
    type: String,
    trim: true
  },
  eventType: {
    type: String,
    enum: ['onboard', 'offboard'],
    default: 'offboard'
  },
  color: {
    type: String,
    default: '#1976D2' // Default to blue (offboard)
  },
  isAllDay: {
    type: Boolean,
    default: false
  },
  // Sharing capabilities
  sharedWith: [{
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    permission: {
      type: String,
      enum: ['view', 'edit'],
      default: 'view'
    },
    status: {
      type: String,
      enum: ['pending', 'accepted', 'declined'],
      default: 'pending'
    }
  }],
  // Google Calendar integration
  googleCalendarEventId: {
    type: String
  },
  isSyncedWithGoogle: {
    type: Boolean,
    default: false
  },
  // Recurrence using iCal RRule format
  recurrence: {
    type: String
  },
  // Reminder notifications
  reminders: {
    weekBefore: {
      type: Boolean,
      default: false
    },
    dayBefore: {
      type: Boolean,
      default: false
    },
    hours12: {
      type: Boolean,
      default: false
    },
    hours6: {
      type: Boolean,
      default: false
    },
    hour1: {
      type: Boolean,
      default: false
    }
  },
  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update the updatedAt field before saving
EventSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Event', EventSchema);
