const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { safeLog, redactSensitiveData } = require('../utils/logger');

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

const RefreshTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true
  },
  isRevoked: {
    type: Boolean,
    default: false
  },
  expiresAt: {
    type: Date,
    required: true
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
    minlength: 6,
    validate: {
      validator: function(v) {
        // Only validate password complexity for non-Google users
        if (this.isGoogleUser) return true;
        
        // Optional: Add a more flexible password validation
        // This allows passwords of at least 6 characters
        return v && v.length >= 6;
      },
      message: 'Password must be at least 6 characters long'
    }
  },
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  offshoreRole: {
    type: String,
    enum: ['Drilling', 'Production', 'Maintenance', 'Support', 'Management',
      'Operations', 'Safety', 'Bridge'],
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
  refreshTokens: [RefreshTokenSchema],
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
  googleCalendarToken: {
    type: String,
    default: null
  },
  googleCalendarRefreshToken: {
    type: String,
    default: null
  },
  googleCalendarTokenExpiry: {
    type: Date,
    default: null
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  isVerificationProcessed: {
    type: Boolean,
    default: false
  },
  verificationToken: {
    type: String,
    default: null
  },
  verificationTokenExpires: {
    type: Date,
    default: null
  },
  verificationTokenUsedAt: {
    type: Date,
    default: null
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
  // Only hash password if it has been modified or is new
  if (this.isModified('password') && !this.isGoogleUser && this.password) {
    try {
      safeLog('Pre-save password hashing triggered');
      safeLog(`Password modification for user: ${this.username}`);
      
      // Use a consistent salt round
      const SALT_ROUNDS = 10;
      
      // If password is already a hash, skip re-hashing
      if (this.password.startsWith('$2')) {
        safeLog('Password already appears to be hashed. Skipping re-hash.');
        return next();
      }
      
      // Generate salt and hash
      const salt = await bcrypt.genSalt(SALT_ROUNDS);
      const hashedPassword = await bcrypt.hash(this.password, salt);
      
      safeLog(`Pre-save hash generation for ${this.username}`);
      safeLog(`Original password length: ${this.password.length}`);
      safeLog(`Hashed password length: ${hashedPassword.length}`);
      
      // Replace password with hashed version
      this.password = hashedPassword;
    } catch (error) {
      safeLog('Pre-save password hashing error:', redactSensitiveData(error));
      return next(error);
    }
  }
  next();
});

// Method to compare password
UserSchema.methods.comparePassword = async function(candidatePassword) {
  safeLog(`Comparing password for user: ${this.username}`);
  safeLog(`Candidate password length: ${candidatePassword.length}`);
  safeLog(`Stored password hash length: ${this.password.length}`);
  
  try {
    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    safeLog(`Password comparison result: ${isMatch}`);
    return isMatch;
  } catch (error) {
    safeLog('Error during password comparison:', redactSensitiveData(error));
    throw error;
  }
};

// Diagnostic method to help troubleshoot password issues
UserSchema.methods.debugPasswordIssue = async function(candidatePassword) {
  safeLog('===== PASSWORD DEBUGGING =====');
  safeLog(`Username: ${this.username}`);
  safeLog(`Is Google User: ${this.isGoogleUser}`);
  
  // Check password existence
  if (!this.password) {
    safeLog('No password hash found for user');
    return { 
      error: 'No password hash', 
      details: 'User account may be improperly configured' 
    };
  }

  // Try different comparison scenarios
  try {
    safeLog('Attempting direct bcrypt comparison...');
    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    safeLog(`Direct bcrypt comparison result: ${isMatch}`);

    // Additional diagnostic checks
    safeLog('Checking password complexity...');
    safeLog(`Candidate password length: ${candidatePassword.length}`);
    safeLog(`Stored hash length: ${this.password.length}`);

    // Optional: Check for common password reset or migration scenarios
    safeLog('Checking for potential migration or reset scenarios...');
    const potentialResetPatterns = [
      'reset', 
      'temporary', 
      'default'
    ];
    
    const matchesPotentialResetPattern = potentialResetPatterns.some(pattern => 
      candidatePassword.toLowerCase().includes(pattern)
    );

    if (matchesPotentialResetPattern) {
      safeLog('Candidate password matches potential reset pattern');
    }

    return {
      isMatch,
      candidatePasswordLength: candidatePassword.length,
      storedHashLength: this.password.length,
      matchesPotentialResetPattern
    };
  } catch (error) {
    safeLog('Error during password debugging:', redactSensitiveData(error));
    return { 
      error: 'Debugging failed', 
      details: error.message 
    };
  }
};

// Advanced password debugging method
UserSchema.methods.advancedPasswordDebug = async function(candidatePassword) {
  safeLog('===== ADVANCED PASSWORD DEBUGGING =====');
  
  try {
    // Generate a new hash from the candidate password
    const saltRounds = 10;
    const newHash = await bcrypt.hash(candidatePassword, saltRounds);
    
    safeLog('Comparison Analysis:');
    safeLog(`Original Stored Hash: ${this.password}`);
    safeLog(`Newly Generated Hash: ${newHash}`);
    
    // Detailed character-by-character comparison
    const originalHashChars = this.password.split('');
    const newHashChars = newHash.split('');
    
    let differentChars = 0;
    const maxLength = Math.max(originalHashChars.length, newHashChars.length);
    
    for (let i = 0; i < maxLength; i++) {
      if (originalHashChars[i] !== newHashChars[i]) {
        safeLog(`Difference at index ${i}:`);
        safeLog(`  Original: ${originalHashChars[i] || 'N/A'}`);
        safeLog(`  New:      ${newHashChars[i] || 'N/A'}`);
        differentChars++;
      }
    }
    
    safeLog(`Total different characters: ${differentChars}`);
    
    // Additional bcrypt-specific checks
    const bcryptVersionCheck = this.password.startsWith('$2');
    const newHashVersionCheck = newHash.startsWith('$2');
    
    safeLog('BCrypt Version Checks:');
    safeLog(`  Original Hash BCrypt Version: ${bcryptVersionCheck}`);
    safeLog(`  New Hash BCrypt Version:      ${newHashVersionCheck}`);
    
    return {
      originalHashLength: this.password.length,
      newHashLength: newHash.length,
      differentCharacters: differentChars,
      bcryptVersionMatches: bcryptVersionCheck === newHashVersionCheck
    };
  } catch (error) {
    safeLog('Advanced password debugging failed:', redactSensitiveData(error));
    return { 
      error: 'Advanced debugging failed', 
      details: error.message 
    };
  }
};

// Method to verify password hashing and storage
UserSchema.methods.verifyPasswordIntegrity = async function(plainTextPassword) {
  safeLog('===== PASSWORD INTEGRITY CHECK =====');
  safeLog(`Username: ${this.username}`);
  safeLog(`Is Google User: ${this.isGoogleUser}`);
  
  if (!this.password) {
    safeLog('No password hash found for user');
    return { 
      hasPassword: false,
      error: 'No password hash exists' 
    };
  }

  try {
    // Attempt to compare the password
    const isMatch = await bcrypt.compare(plainTextPassword, this.password);
    
    safeLog('Detailed Password Hash Analysis:');
    safeLog(`Stored Password Hash Length: ${this.password.length}`);
    safeLog(`Stored Password Hash Prefix: ${this.password.substring(0, 20)}...`);
    safeLog(`BCrypt Version Check: ${this.password.startsWith('$2')}`);
    
    // Regenerate hash to compare
    const newSalt = await bcrypt.genSalt(10);
    const newHash = await bcrypt.hash(plainTextPassword, newSalt);
    
    safeLog('Regenerated Hash Comparison:');
    safeLog(`New Hash Length: ${newHash.length}`);
    safeLog(`New Hash Prefix: ${newHash.substring(0, 20)}...`);
    safeLog(`BCrypt Version Check: ${newHash.startsWith('$2')}`);
    
    return {
      isMatch,
      storedHashLength: this.password.length,
      newHashLength: newHash.length,
      storedHashPrefix: this.password.substring(0, 20),
      newHashPrefix: newHash.substring(0, 20)
    };
  } catch (error) {
    safeLog('Password integrity check failed:', redactSensitiveData(error));
    return { 
      error: 'Integrity check failed', 
      details: error.message 
    };
  }
};

module.exports = mongoose.model('User', UserSchema);
