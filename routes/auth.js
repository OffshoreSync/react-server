const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const validateGoogleToken = require('../middleware/googleTokenValidator');
const bcrypt = require('bcryptjs');
const path = require('path');
const { getCountryCode } = require('../utils/countries');

// Register new user
router.post('/register', async (req, res) => {
  try {
    console.log('Received registration data:', JSON.stringify(req.body, null, 2));

    const { 
      username, 
      email, 
      password, 
      fullName, 
      offshoreRole, 
      workingRegime,
      company, 
      unitName, 
      country,
      googleLogin // New flag
    } = req.body;

    // Validate required fields
    if (!username || !email || !fullName || !offshoreRole || !workingRegime || !country) {
      console.error('Missing required fields');
      return res.status(400).json({ 
        message: 'Missing required fields', 
        missingFields: {
          username: !username,
          email: !email,
          fullName: !fullName,
          offshoreRole: !offshoreRole,
          workingRegime: !workingRegime,
          country: !country
        }
      });
    }

    // Check if user already exists
    let existingUser = await User.findOne({ $or: [{ username }, { email }] });

    if (existingUser) {
      // If Google login, update existing user
      if (googleLogin && !existingUser.isGoogleUser) {
        existingUser.isGoogleUser = true;
        await existingUser.save();
      } else if (existingUser.isGoogleUser) {
        return res.status(400).json({ message: 'Google user already exists' });
      } else {
        return res.status(400).json({ message: 'User already exists with this username or email' });
      }
    }

    // Create new user
    const newUser = new User({
      username,
      email,
      password: googleLogin ? undefined : password, // Optional for Google users
      fullName,
      offshoreRole,
      workingRegime: {
        onDutyDays: workingRegime.onDutyDays,
        offDutyDays: workingRegime.offDutyDays
      },
      company: company || null,
      unitName: unitName || null,
      country,
      isGoogleUser: googleLogin || false,
      profilePicture: googleLogin ? undefined : null // Set profilePicture to null for non-Google users
    });

    // Hash password
    if (!googleLogin) {
      const salt = await bcrypt.genSalt(10);
      newUser.password = await bcrypt.hash(password, salt);
    }

    // Save user to database
    try {
      await newUser.save();
    } catch (saveError) {
      console.error('User save error:', saveError);
      return res.status(400).json({ 
        message: 'Error saving user', 
        details: saveError.message,
        errors: saveError.errors 
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: newUser._id, 
        username: newUser.username,
        isGoogleUser: newUser.isGoogleUser
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Return user info and token (excluding password)
    const userResponse = {
      _id: newUser._id,
      username: newUser.username,
      email: newUser.email,
      fullName: newUser.fullName,
      offshoreRole: newUser.offshoreRole,
      workingRegime: newUser.workingRegime,
      isGoogleUser: newUser.isGoogleUser,
      company: newUser.company,
      unitName: newUser.unitName,
      country: newUser.country,
      profilePicture: newUser.isGoogleUser ? undefined : null // Explicitly set to null for non-Google users
    };

    res.status(201).json({ 
      user: userResponse, 
      token 
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      message: 'Server error during registration',
      error: error.message 
    });
  }
});

// Country mapping function
const mapCountryToCode = (countryName) => {
  // Use the getCountryCode function from server utils
  return getCountryCode(countryName);
};

// Google Login/Registration
router.post('/google-login', validateGoogleToken, async (req, res) => {
  try {
    // Use validated Google user info from middleware
    const { email, name, picture, googleId, country } = req.googleUser;

    // Map country name to country code
    const countryCode = mapCountryToCode(country);

    // Log incoming profile details
    console.log('Incoming Google Profile:', {
      email,
      name,
      picture,
      googleId,
      country,
      mappedCountryCode: countryCode
    });

    // Check if user already exists
    let user = await User.findOne({ email });

    if (!user) {
      // Create new user with Google credentials
      user = new User({
        email,
        fullName: name,
        username: email.split('@')[0],
        isGoogleUser: true,
        googleId,
        profilePicture: picture, // Explicitly set profile picture
        // Use mapped country code
        country: countryCode,
        // Default values for required fields
        offshoreRole: 'Support', // Default role
        workingRegime: {
          onDutyDays: 28,
          offDutyDays: 28
        }
      });

      await user.save();
      console.log('New user created with details:', {
        profilePicture: user.profilePicture,
        country: user.country
      });
    } else {
      // Update existing user's profile picture and country
      user.profilePicture = picture;
      
      // Only update country if it's not already set
      if (!user.country || user.country === 'Unknown') {
        user.country = countryCode;
      }

      await user.save();
      console.log('Existing user updated with details:', {
        profilePicture: user.profilePicture,
        country: user.country
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username,
        isGoogleUser: true
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Return user info and token (excluding password)
    const userResponse = {
      _id: user._id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      offshoreRole: user.offshoreRole,
      workingRegime: user.workingRegime,
      isGoogleUser: user.isGoogleUser || true, // Ensure this is always set for Google logins
      profilePicture: user.profilePicture, // Explicitly return profile picture
      country: user.country || 'US', // Ensure country is always returned
      company: user.company || null,
      unitName: user.unitName || null
    };

    // Additional logging
    console.log('User Response:', {
      profilePicture: userResponse.profilePicture,
      country: userResponse.country
    });

    res.status(200).json({ 
      user: userResponse, 
      token 
    });
  } catch (error) {
    console.error('Google Login Error:', JSON.stringify(error, null, 2));
    res.status(500).json({ 
      message: 'Internal server error during Google login',
      error: error.message 
    });
  }
});

// Login user
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user by username
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    // Ensure profilePicture is null for non-Google users
    if (!user.isGoogleUser) {
      user.profilePicture = null;
      await user.save();
    }

    // Generate token
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username,
        email: user.email,
        fullName: user.fullName
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Explicitly include all fields in the response
    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        offshoreRole: user.offshoreRole,
        workingRegime: user.workingRegime,
        company: user.company || null,
        workSchedule: user.workSchedule || {},
        
        // Explicitly include these fields with null fallback
        unitName: user.unitName || null,
        country: user.country || null,
        isGoogleUser: user.isGoogleUser,
        profilePicture: user.isGoogleUser ? user.profilePicture : null, // Explicitly set to null for non-Google users
        nextOnBoardDate: user.nextOnBoardDate || null
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Delete user account
router.delete('/delete-account', async (req, res) => {
  try {
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find and delete user
    const user = await User.findByIdAndDelete(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Account deletion error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }

    res.status(500).json({ message: 'Server error during account deletion' });
  }
});

// Update user profile
router.put('/update-profile', async (req, res) => {
  try {
    // Log incoming request body for debugging
    console.log('Received profile update request:', JSON.stringify(req.body, null, 2));

    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find user
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Destructure request body with explicit handling
    const { 
      username, 
      email, 
      fullName, 
      offshoreRole, 
      workingRegime,
      company, 
      workSchedule,
      country,
      unitName
    } = req.body;

    // Update user fields with explicit preservation
    if (username) user.username = username;
    if (email) user.email = email;
    if (fullName) user.fullName = fullName;
    if (offshoreRole) user.offshoreRole = offshoreRole;
    if (workingRegime) user.workingRegime = workingRegime;
    if (company) user.company = company;
    if (workSchedule) user.workSchedule = workSchedule;
    
    // Explicitly handle country and unitName with logging
    console.log('Incoming country:', country);
    console.log('Incoming unitName:', unitName);
    console.log('Existing user country:', user.country);
    console.log('Existing user unitName:', user.unitName);

    // Preserve existing values if not provided
    if (country !== undefined) user.country = country;
    if (unitName !== undefined) user.unitName = unitName;

    // Save updated user
    await user.save();

    // Log saved user for verification
    console.log('Updated user:', {
      country: user.country,
      unitName: user.unitName
    });

    // Generate new token with updated information
    const newToken = jwt.sign(
      { 
        userId: user._id, 
        username: user.username,
        email: user.email,
        fullName: user.fullName
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Explicitly include all fields in the response
    res.json({ 
      message: 'Profile updated successfully', 
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        offshoreRole: user.offshoreRole,
        workingRegime: user.workingRegime,
        company: user.company || null,
        workSchedule: user.workSchedule || {},
        
        // Explicitly include these fields with null fallback
        unitName: user.unitName || null,
        country: user.country || null,
        isGoogleUser: user.isGoogleUser,
        nextOnBoardDate: user.nextOnBoardDate || null
      },
      token: newToken
    });
  } catch (error) {
    console.error('Profile update error:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({ message: 'Validation error', details: error.errors });
    }

    res.status(500).json({ message: 'Server error during profile update', error: error.message });
  }
});

// Get User Profile
router.get('/profile', async (req, res) => {
  try {
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find user
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Log user details for debugging
    console.log('User Profile Details:', {
      isGoogleUser: user.isGoogleUser,
      profilePicture: user.profilePicture
    });

    // Return user profile (excluding sensitive information)
    res.json({ 
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        offshoreRole: user.offshoreRole,
        workingRegime: user.workingRegime || {
          onDutyDays: 28,
          offDutyDays: 28
        },
        company: user.company,
        workSchedule: user.workSchedule,
        unitName: user.unitName || null,
        country: user.country || null,
        isGoogleUser: user.isGoogleUser,
        profilePicture: user.profilePicture || null // Explicitly include profilePicture
      }
    });
  } catch (error) {
    console.error('Profile retrieval error:', error);
    res.status(500).json({ message: 'Server error during profile retrieval' });
  }
});

// Set Next On Board Date
router.put('/set-onboard-date', async (req, res) => {
  try {
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find user
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get on board date from request
    const { nextOnBoardDate } = req.body;

    if (!nextOnBoardDate) {
      return res.status(400).json({ message: 'Next on board date is required' });
    }

    // Ensure working regime is set
    const onDutyDays = user.workingRegime?.onDutyDays || 14;
    const offDutyDays = user.workingRegime?.offDutyDays || 14;

    // Calculate off board date based on current working regime
    const onBoardDate = new Date(nextOnBoardDate);
    const offBoardDate = new Date(onBoardDate);
    offBoardDate.setDate(offBoardDate.getDate() + onDutyDays);

    // Update user's work schedule
    user.workSchedule = {
      nextOnBoardDate: onBoardDate,
      nextOffBoardDate: offBoardDate
    };

    // Save updated user
    await user.save();

    // Generate new token with updated information
    const newToken = jwt.sign(
      { 
        userId: user._id, 
        username: user.username,
        email: user.email,
        fullName: user.fullName
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    res.json({ 
      message: 'On board date updated successfully', 
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        offshoreRole: user.offshoreRole,
        company: user.company || null,
        workSchedule: {
          nextOnBoardDate: user.workSchedule.nextOnBoardDate,
          nextOffBoardDate: user.workSchedule.nextOffBoardDate
        },
        workingRegime: user.workingRegime,
        unitName: user.unitName || null,
        country: user.country || null,
        isGoogleUser: user.isGoogleUser
      },
      token: newToken
    });
  } catch (error) {
    console.error('Set on board date error:', error);
    res.status(500).json({ message: 'Server error during on board date update', error: error.message });
  }
});

// Reset Work Schedule and Prepare for New Onboarding
router.put('/reset-next-onboard-date', async (req, res) => {
  try {
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    // Find the user
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Reset work schedule details
    user.workSchedule = {
      nextOnBoardDate: null,
      nextOffBoardDate: null
    };

    // Save the updated user
    await user.save();

    res.json({ 
      message: 'Work schedule reset successfully',
      workSchedule: user.workSchedule 
    });
  } catch (error) {
    console.error('Error resetting work schedule:', error);
    res.status(500).json({ 
      message: 'Server error while resetting work schedule',
      error: error.message 
    });
  }
});

// Generate and save work cycles for a user
router.post('/generate-work-cycles', async (req, res) => {
  try {
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find the user and populate all necessary fields
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Get working regime from user
    const { onDutyDays, offDutyDays } = user.workingRegime;

    // Prepare work cycles
    const workCycles = [];
    const nextOnBoardDate = new Date(user.workSchedule.nextOnBoardDate);
    const twoYearsFromNow = new Date(nextOnBoardDate);
    twoYearsFromNow.setFullYear(twoYearsFromNow.getFullYear() + 2);

    let currentDate = nextOnBoardDate;
    let cycleNumber = 1;

    while (currentDate < twoYearsFromNow) {
      // On Board cycle
      const onBoardStart = new Date(currentDate);
      const onBoardEnd = new Date(currentDate);
      onBoardEnd.setDate(onBoardEnd.getDate() + onDutyDays);

      // Ensure on-board start date is strictly after off-board end date (HAX)
      if (cycleNumber > 1 && workCycles.length > 0) {
        const prevCycle = workCycles[workCycles.length - 1];
        const prevCycleEnd = new Date(prevCycle.endDate);
        
        if (onBoardStart.getTime() === prevCycleEnd.getTime()) {
          onBoardStart.setDate(onBoardStart.getDate() + 1);
        }
      }

      workCycles.push({
        startDate: onBoardStart,
        endDate: onBoardEnd,
        type: 'OnBoard',
        cycleNumber
      });

      // Move to Off Board cycle
      currentDate = new Date(onBoardEnd);
      const offBoardStart = new Date(currentDate);
      const offBoardEnd = new Date(currentDate);
      offBoardEnd.setDate(offBoardEnd.getDate() + offDutyDays);

      // Ensure off-board start date is strictly after on-board end date (HAX)
      if (offBoardStart.getTime() === onBoardEnd.getTime()) {
        offBoardStart.setDate(offBoardStart.getDate() + 1);
      }

      workCycles.push({
        startDate: offBoardStart,
        endDate: offBoardEnd,
        type: 'OffBoard',
        cycleNumber
      });

      // Prepare for next cycle
      currentDate = offBoardEnd;
      cycleNumber++;
    }

    // Use findOneAndUpdate to atomically update work cycles
    try {
      const updatedUser = await User.findOneAndUpdate(
        { _id: user._id },
        { 
          $set: { 
            workCycles: workCycles 
          } 
        },
        { 
          new: true,  // Return the modified document
          runValidators: true  // Run model validations
        }
      );

      if (!updatedUser) {
        throw new Error('User not found or could not update work cycles');
      }

      // Prepare response with full user data
      const userResponse = {
        _id: updatedUser._id,
        username: updatedUser.username,
        email: updatedUser.email,
        fullName: updatedUser.fullName,
        workSchedule: updatedUser.workSchedule,
        workingRegime: updatedUser.workingRegime,
        workCycles: updatedUser.workCycles,
        isGoogleUser: updatedUser.isGoogleUser
      };

      res.status(200).json({ 
        message: 'Work cycles generated successfully',
        user: userResponse,
        workCycles: updatedUser.workCycles
      });

    } catch (error) {
      console.error('Error generating work cycles:', error);
      res.status(500).json({ 
        message: 'Server error while generating work cycles',
        error: error.message 
      });
    }
  } catch (error) {
    console.error('Error generating work cycles:', error);
    res.status(500).json({ 
      message: 'Server error while generating work cycles',
      error: error.message 
    });
  }
});

// Retrieve a specific user's work cycles
router.get('/user-work-cycles/:userId', async (req, res) => {
  try {
    // Get token from headers for authentication
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    const { userId } = req.params;

    // Find target user
    const targetUser = await User.findById(userId)
      .select('workCycles fullName username isGoogleUser');

    if (!targetUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Sort work cycles chronologically
    const sortedWorkCycles = targetUser.workCycles
      .map(cycle => ({
        ...cycle.toObject(),
        startDate: new Date(cycle.startDate),
        endDate: new Date(cycle.endDate)
      }))
      .sort((a, b) => a.startDate - b.startDate);

    // Prepare response
    res.status(200).json({
      userId: targetUser._id,
      fullName: targetUser.fullName,
      username: targetUser.username,
      isGoogleUser: targetUser.isGoogleUser,
      workCycles: sortedWorkCycles
    });

  } catch (error) {
    console.error('Error retrieving user work cycles:', error);
    res.status(500).json({ 
      message: 'Server error while retrieving user work cycles',
      error: error.message 
    });
  }
});

// Fetch all users for sync functionality
router.get('/all-users', async (req, res) => {
  try {
    // Get token from headers for authentication
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          message: 'Token expired', 
          error: 'TokenExpiredError',
          requiresReAuthentication: true 
        });
      }
      throw error;
    }

    // Find the current user
    const currentUser = await User.findById(decoded.userId);

    if (!currentUser) {
      return res.status(404).json({ message: 'Current user not found' });
    }

    // Fetch all users except the current user
    const users = await User.find({ 
      _id: { $ne: currentUser._id } 
    }).select('id fullName username email isGoogleUser');

    // Validate and filter users
    const validUsers = users.map(user => ({
      id: user._id,
      fullName: user.fullName,
      username: user.username,
      email: user.email,
      isGoogleUser: user.isGoogleUser
    }));

    res.status(200).json({ 
      users: validUsers,
      total: validUsers.length
    });

  } catch (error) {
    console.error('Error fetching all users:', error);
    res.status(500).json({ 
      message: 'Server error while fetching users',
      error: error.message 
    });
  }
});

// Import Friend model
const Friend = require('../models/Friend');

// Send Friend Request
router.post('/friend-request', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    const { friendEmail } = req.body;

    // Find the target user
    const targetUser = await User.findOne({ email: friendEmail });

    if (!targetUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Prevent self-friending
    if (targetUser._id.toString() === currentUserId) {
      return res.status(400).json({ message: 'Cannot send friend request to yourself' });
    }

    // Check for existing friend request or friendship
    const existingRequest = await Friend.findOne({
      $or: [
        { user: currentUserId, friend: targetUser._id },
        { user: targetUser._id, friend: currentUserId }
      ]
    });

    if (existingRequest) {
      return res.status(400).json({ 
        message: 'Friend request already exists', 
        status: existingRequest.status 
      });
    }

    // Create friend request
    const friendRequest = new Friend({
      user: currentUserId,
      friend: targetUser._id,
      status: 'PENDING'
    });

    await friendRequest.save();

    res.status(201).json({ 
      message: 'Friend request sent', 
      requestId: friendRequest._id 
    });

  } catch (error) {
    console.error('Friend request error:', error);
    res.status(500).json({ message: 'Server error during friend request' });
  }
});

// Respond to Friend Request
router.put('/friend-request/:requestId', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    const { status } = req.body; // 'ACCEPTED' or 'BLOCKED'
    const { requestId } = req.params;

    const friendRequest = await Friend.findOneAndUpdate(
      { 
        _id: requestId, 
        friend: currentUserId,
        status: 'PENDING'
      },
      { 
        status,
        'sharingPreferences.allowScheduleSync': status === 'ACCEPTED'
      },
      { new: true }
    );

    if (!friendRequest) {
      return res.status(404).json({ message: 'Friend request not found' });
    }

    res.status(200).json({ 
      message: 'Friend request updated', 
      status: friendRequest.status 
    });

  } catch (error) {
    console.error('Friend request update error:', error);
    res.status(500).json({ message: 'Server error updating friend request' });
  }
});

// Get Friends List
router.get('/friends', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    // Find all accepted friendships for the current user
    const friendships = await Friend.find({
      $or: [
        { user: currentUserId, status: 'ACCEPTED' },
        { friend: currentUserId, status: 'ACCEPTED' }
      ]
    }).populate('user friend', 'fullName email profilePicture');

    // Transform friendships to include friend details
    const friends = friendships.map(friendship => {
      const isFriendInitiator = friendship.user._id.toString() === currentUserId;
      const friendDetails = isFriendInitiator ? friendship.friend : friendship.user;
      
      return {
        id: friendDetails._id,
        fullName: friendDetails.fullName,
        email: friendDetails.email,
        profilePicture: friendDetails.profilePicture,
        sharingPreferences: {
          allowScheduleSync: friendship.sharingPreferences.allowScheduleSync
        }
      };
    });

    res.status(200).json({ friends });

  } catch (error) {
    console.error('Get friends error:', error);
    res.status(500).json({ message: 'Server error retrieving friends' });
  }
});

// Get Pending Friend Requests
router.get('/friend-requests', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    // Find pending friend requests for the current user
    const pendingRequests = await Friend.find({
      friend: currentUserId,
      status: 'PENDING'
    }).populate('user', 'fullName email profilePicture');

    const requests = pendingRequests.map(request => ({
      id: request._id,
      user: {
        id: request.user._id,
        fullName: request.user.fullName,
        email: request.user.email,
        profilePicture: request.user.profilePicture
      },
      requestedAt: request.requestedAt
    }));

    res.status(200).json({ pendingRequests: requests });

  } catch (error) {
    console.error('Get pending requests error:', error);
    res.status(500).json({ message: 'Server error retrieving pending requests' });
  }
});

// Search Users Route
router.get('/search-users', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const currentUserId = decoded.userId;

    const { query } = req.query;

    // Validate search query
    if (!query || query.trim().length < 2) {
      return res.status(400).json({ 
        message: 'Search query must be at least 2 characters long' 
      });
    }

    // Search users by full name or username, excluding current user
    const users = await User.find({
      $and: [
        { _id: { $ne: currentUserId } }, // Exclude current user
        {
          $or: [
            { fullName: { $regex: query, $options: 'i' } }, // Case-insensitive full name search
            { username: { $regex: query, $options: 'i' } }  // Case-insensitive username search
          ]
        }
      ]
    }).select('fullName username email profilePicture offshoreRole'); // Select specific fields

    // Check existing friend requests or friendships
    const friendRequests = await Friend.find({
      $or: [
        { user: currentUserId },
        { friend: currentUserId }
      ]
    });

    // Annotate users with friendship status
    const usersWithStatus = users.map(user => {
      const existingRequest = friendRequests.find(
        req => 
          (req.user.toString() === user._id.toString() || 
           req.friend.toString() === user._id.toString())
      );

      return {
        id: user._id,
        fullName: user.fullName,
        username: user.username,
        email: user.email,
        profilePicture: user.profilePicture,
        offshoreRole: user.offshoreRole,
        friendshipStatus: existingRequest ? existingRequest.status : 'NO_REQUEST'
      };
    });

    res.status(200).json({ users: usersWithStatus });

  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ message: 'Server error searching users' });
  }
});

module.exports = router;
