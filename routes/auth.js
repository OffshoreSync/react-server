const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');

// Register new user
router.post('/register', async (req, res) => {
  try {
    const { 
      username, 
      email, 
      password, 
      fullName, 
      offshoreRole, 
      workingRegime,
      company, 
      unitName, 
      country 
    } = req.body;

    // Check if user already exists
    let existingUser = await User.findOne({ $or: [{ username }, { email }] });

    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this username or email' });
    }

    // Validate working regime
    if (!workingRegime || 
        typeof workingRegime.onDutyDays !== 'number' || 
        typeof workingRegime.offDutyDays !== 'number') {
      return res.status(400).json({ message: 'Invalid working regime format' });
    }

    // Create new user
    const newUser = new User({
      username,
      email,
      password,
      fullName,
      offshoreRole,
      workingRegime: {
        onDutyDays: workingRegime.onDutyDays,
        offDutyDays: workingRegime.offDutyDays
      },
      company,
      unitName,
      country
    });

    // Save user to database
    await newUser.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: newUser._id, 
        username: newUser.username 
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
      company: newUser.company,
      unitName: newUser.unitName,
      country: newUser.country
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

// Login user
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Create JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username 
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    res.json({ 
      message: 'Login successful',
      token,
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
        unitName: user.unitName,
        country: user.country
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
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

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
    // Get token from headers
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Find user
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Destructure request body
    const { 
      username, 
      email, 
      fullName, 
      offshoreRole, 
      workingRegime,
      company, 
      unitName, 
      country 
    } = req.body;

    // Validate working regime
    if (!workingRegime || 
        typeof workingRegime.onDutyDays !== 'number' || 
        typeof workingRegime.offDutyDays !== 'number') {
      return res.status(400).json({ message: 'Invalid working regime format' });
    }

    // Check if new username or email already exists (excluding current user)
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email }],
      _id: { $ne: user._id } 
    });

    if (existingUser) {
      return res.status(400).json({ message: 'Username or email already in use' });
    }

    // Update user fields
    user.username = username;
    user.email = email;
    user.fullName = fullName;
    user.offshoreRole = offshoreRole;
    user.workingRegime = {
      onDutyDays: workingRegime.onDutyDays,
      offDutyDays: workingRegime.offDutyDays
    };
    user.company = company || null;
    user.unitName = unitName || null;
    user.country = country;

    // Save updated user
    await user.save();

    // Generate new token (optional, but can be useful if needed)
    const newToken = jwt.sign(
      { 
        userId: user._id, 
        username: user.username 
      }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );

    // Prepare user response (excluding password)
    const userResponse = {
      _id: user._id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      offshoreRole: user.offshoreRole,
      workingRegime: user.workingRegime,
      company: user.company,
      unitName: user.unitName,
      country: user.country
    };

    res.json({ 
      message: 'Profile updated successfully', 
      user: userResponse,
      token: newToken
    });
  } catch (error) {
    console.error('Profile update error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    }

    res.status(500).json({ 
      message: 'Server error during profile update',
      error: error.message 
    });
  }
});

module.exports = router;
