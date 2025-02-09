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
    minlength: 6,
    validate: {
      validator: function(v) {
        // Only validate password complexity for non-Google users
        if (this.isGoogleUser) return true;
        
        // Optional: Add a more flexible password validation
        // This allows passwords of at least 6 characters
        return v.length >= 6;
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
  isVerified: {
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
  if (this.isModified('password') && !this.isGoogleUser) {
    try {
      console.log('Pre-save password hashing triggered');
      console.log(`Password modification for user: ${this.username}`);
      
      // Use a consistent salt round
      const SALT_ROUNDS = 10;
      
      // If password is already a hash, skip re-hashing
      if (this.password.startsWith('$2')) {
        console.log('Password already appears to be hashed. Skipping re-hash.');
        return next();
      }
      
      // Generate salt and hash
      const salt = await bcrypt.genSalt(SALT_ROUNDS);
      const hashedPassword = await bcrypt.hash(this.password, salt);
      
      console.log(`Pre-save hash generation for ${this.username}`);
      console.log(`Original password length: ${this.password.length}`);
      console.log(`Hashed password length: ${hashedPassword.length}`);
      
      // Replace password with hashed version
      this.password = hashedPassword;
    } catch (error) {
      console.error('Pre-save password hashing error:', error);
      return next(error);
    }
  }
  next();
});

// Method to compare password
UserSchema.methods.comparePassword = async function(candidatePassword) {
  console.log(`Comparing password for user: ${this.username}`);
  console.log(`Candidate password length: ${candidatePassword.length}`);
  console.log(`Stored password hash length: ${this.password.length}`);
  
  try {
    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    console.log(`Password comparison result: ${isMatch}`);
    return isMatch;
  } catch (error) {
    console.error('Error during password comparison:', error);
    throw error;
  }
};

// Diagnostic method to help troubleshoot password issues
UserSchema.methods.debugPasswordIssue = async function(candidatePassword) {
  console.log('===== PASSWORD DEBUGGING =====');
  console.log(`Username: ${this.username}`);
  console.log(`Is Google User: ${this.isGoogleUser}`);
  
  // Check password existence
  if (!this.password) {
    console.error('No password hash found for user');
    return { 
      error: 'No password hash', 
      details: 'User account may be improperly configured' 
    };
  }

  // Try different comparison scenarios
  try {
    console.log('Attempting direct bcrypt comparison...');
    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    console.log(`Direct bcrypt comparison result: ${isMatch}`);

    // Additional diagnostic checks
    console.log('Checking password complexity...');
    console.log(`Candidate password length: ${candidatePassword.length}`);
    console.log(`Stored hash length: ${this.password.length}`);

    // Optional: Check for common password reset or migration scenarios
    console.log('Checking for potential migration or reset scenarios...');
    const potentialResetPatterns = [
      'reset', 
      'temporary', 
      'default'
    ];
    
    const matchesPotentialResetPattern = potentialResetPatterns.some(pattern => 
      candidatePassword.toLowerCase().includes(pattern)
    );

    if (matchesPotentialResetPattern) {
      console.warn('Candidate password matches potential reset pattern');
    }

    return {
      isMatch,
      candidatePasswordLength: candidatePassword.length,
      storedHashLength: this.password.length,
      matchesPotentialResetPattern
    };
  } catch (error) {
    console.error('Error during password debugging:', error);
    return { 
      error: 'Debugging failed', 
      details: error.message 
    };
  }
};

// Advanced password debugging method
UserSchema.methods.advancedPasswordDebug = async function(candidatePassword) {
  console.log('===== ADVANCED PASSWORD DEBUGGING =====');
  
  try {
    // Generate a new hash from the candidate password
    const saltRounds = 10;
    const newHash = await bcrypt.hash(candidatePassword, saltRounds);
    
    console.log('Comparison Analysis:');
    console.log(`Original Stored Hash: ${this.password}`);
    console.log(`Newly Generated Hash: ${newHash}`);
    
    // Detailed character-by-character comparison
    const originalHashChars = this.password.split('');
    const newHashChars = newHash.split('');
    
    let differentChars = 0;
    const maxLength = Math.max(originalHashChars.length, newHashChars.length);
    
    for (let i = 0; i < maxLength; i++) {
      if (originalHashChars[i] !== newHashChars[i]) {
        console.log(`Difference at index ${i}:`);
        console.log(`  Original: ${originalHashChars[i] || 'N/A'}`);
        console.log(`  New:      ${newHashChars[i] || 'N/A'}`);
        differentChars++;
      }
    }
    
    console.log(`Total different characters: ${differentChars}`);
    
    // Additional bcrypt-specific checks
    const bcryptVersionCheck = this.password.startsWith('$2');
    const newHashVersionCheck = newHash.startsWith('$2');
    
    console.log('BCrypt Version Checks:');
    console.log(`  Original Hash BCrypt Version: ${bcryptVersionCheck}`);
    console.log(`  New Hash BCrypt Version:      ${newHashVersionCheck}`);
    
    return {
      originalHashLength: this.password.length,
      newHashLength: newHash.length,
      differentCharacters: differentChars,
      bcryptVersionMatches: bcryptVersionCheck === newHashVersionCheck
    };
  } catch (error) {
    console.error('Advanced password debugging failed:', error);
    return { 
      error: 'Advanced debugging failed', 
      details: error.message 
    };
  }
};

// Method to verify password hashing and storage
UserSchema.methods.verifyPasswordIntegrity = async function(plainTextPassword) {
  console.log('===== PASSWORD INTEGRITY CHECK =====');
  console.log(`Username: ${this.username}`);
  console.log(`Is Google User: ${this.isGoogleUser}`);
  
  if (!this.password) {
    console.error('No password hash found for user');
    return { 
      hasPassword: false,
      error: 'No password hash exists' 
    };
  }

  try {
    // Attempt to compare the password
    const isMatch = await bcrypt.compare(plainTextPassword, this.password);
    
    console.log('Detailed Password Hash Analysis:');
    console.log(`Stored Password Hash Length: ${this.password.length}`);
    console.log(`Stored Password Hash Prefix: ${this.password.substring(0, 20)}...`);
    console.log(`BCrypt Version Check: ${this.password.startsWith('$2')}`);
    
    // Regenerate hash to compare
    const newSalt = await bcrypt.genSalt(10);
    const newHash = await bcrypt.hash(plainTextPassword, newSalt);
    
    console.log('Regenerated Hash Comparison:');
    console.log(`New Hash Length: ${newHash.length}`);
    console.log(`New Hash Prefix: ${newHash.substring(0, 20)}...`);
    console.log(`BCrypt Version Check: ${newHash.startsWith('$2')}`);
    
    return {
      isMatch,
      storedHashLength: this.password.length,
      newHashLength: newHash.length,
      storedHashPrefix: this.password.substring(0, 20),
      newHashPrefix: newHash.substring(0, 20)
    };
  } catch (error) {
    console.error('Password integrity check failed:', error);
    return { 
      error: 'Integrity check failed', 
      details: error.message 
    };
  }
};

module.exports = mongoose.model('User', UserSchema);
