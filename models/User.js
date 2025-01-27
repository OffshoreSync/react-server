const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const WorkingRegimeSchema = new mongoose.Schema({
  onDutyDays: {
    type: Number,
    required: true,
    min: 7,
    max: 365
  },
  offDutyDays: {
    type: Number,
    required: true,
    min: 7,
    max: 365
  }
}, { _id: false });

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: function() { return !this.isGoogleUser; },
    minlength: function() { return this.isGoogleUser ? 0 : 6; }
  },
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  offshoreRole: {
    type: String,
    enum: ['Drilling', 'Production', 'Maintenance', 'Support', 'Management'],
    required: true
  },
  workingRegime: {
    type: WorkingRegimeSchema,
    required: true,
    validate: {
      validator: function(regime) {
        // Ensure total days don't exceed 365
        return (regime.onDutyDays + regime.offDutyDays) <= 365;
      },
      message: 'Total on and off duty days must not exceed 365'
    }
  },
  company: {
    type: String,
    trim: true,
    default: null
  },
  unitName: {
    type: String,
    trim: true,
    default: null
  },
  country: {
    type: String,
    required: true,
    trim: true
  },
  nextOnBoardDate: {
    type: Date,
    default: null
  },
  workSchedule: {
    type: Object,
    default: {}
  },
  workCycles: [{
    startDate: {
      type: Date,
      required: true
    },
    endDate: {
      type: Date,
      required: true
    },
    type: {
      type: String,
      enum: ['OnBoard', 'OffBoard'],
      required: true
    },
    cycleNumber: {
      type: Number,
      required: true
    }
  }],
  googleId: {
    type: String,
    unique: true,
    sparse: true
  },
  isGoogleUser: {
    type: Boolean,
    default: false
  },
  profilePicture: {
    type: String
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Predefined working regimes
UserSchema.statics.getPredefinedRegimes = function() {
  return {
    '7/7': { onDutyDays: 7, offDutyDays: 7 },
    '14/14': { onDutyDays: 14, offDutyDays: 14 },
    '28/28': { onDutyDays: 28, offDutyDays: 28 }
  };
};

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Method to check password
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);
