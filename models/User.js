const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

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
    required: true,
    minlength: 6
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
    type: Number,
    required: true,
    validate: {
      validator: function(v) {
        return v === 7 || v === 14 || v === 28 || (v > 28 && v <= 365);
      },
      message: props => `${props.value} is not a valid working regime! Must be 7, 14, 28, or between 29-365.`
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
  workSchedule: {
    type: Object,
    default: {}
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

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
