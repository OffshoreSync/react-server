const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Notification = require('../models/Notification');
const User = require('../models/User');

/**
 * @route   GET api/notifications
 * @desc    Get user notifications with pagination
 * @access  Private
 */
router.get('/', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 0;
    const limit = parseInt(req.query.limit) || 20;
    
    const notifications = await Notification.find({ recipient: req.user.id })
      .sort({ createdAt: -1 })
      .skip(page * limit)
      .limit(limit);
    
    const unreadCount = await Notification.countDocuments({ 
      recipient: req.user.id,
      read: false
    });
    
    res.json({
      notifications,
      unreadCount,
      hasMore: notifications.length === limit
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * @route   PUT api/notifications/mark-read
 * @desc    Mark specific notifications as read
 * @access  Private
 */
router.put('/mark-read', auth, async (req, res) => {
  try {
    const { ids } = req.body;
    
    if (!ids || !Array.isArray(ids)) {
      return res.status(400).json({ error: 'Invalid notification IDs' });
    }
    
    await Notification.updateMany(
      { 
        _id: { $in: ids },
        recipient: req.user.id
      },
      { $set: { read: true } }
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error marking notifications as read:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * @route   PUT api/notifications/mark-all-read
 * @desc    Mark all user notifications as read
 * @access  Private
 */
router.put('/mark-all-read', auth, async (req, res) => {
  try {
    await Notification.updateMany(
      { recipient: req.user.id, read: false },
      { $set: { read: true } }
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * @route   POST api/notifications/register-token
 * @desc    Register an FCM token for the user
 * @access  Private
 */
router.post('/register-token', auth, async (req, res) => {
  try {
    const { token, device } = req.body;
    const userId = req.user.id;
    
    console.log(`Registering FCM token for user ${userId}`);
    console.log(`Token preview: ${token.substring(0, 10)}... from device: ${device || 'Unknown'}`);
    
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }
    
    // Validate token format (basic validation)
    if (token.length < 20) {
      return res.status(400).json({ error: 'Invalid token format' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Initialize fcmTokens array if it doesn't exist
    if (!user.fcmTokens) {
      user.fcmTokens = [];
    }
    
    // Check if token already exists
    const existingTokenIndex = user.fcmTokens.findIndex(t => t.token === token);
    
    if (existingTokenIndex >= 0) {
      console.log(`Updating existing FCM token for user ${userId}`);
      // Update existing token
      user.fcmTokens[existingTokenIndex].lastUsed = new Date();
      if (device) {
        user.fcmTokens[existingTokenIndex].device = device;
      }
    } else {
      console.log(`Adding new FCM token for user ${userId}`);
      // Add new token
      user.fcmTokens.push({
        token,
        device: device || 'Unknown device',
        lastUsed: new Date()
      });
    }
    
    // Clean up old tokens (keep only the 5 most recent tokens)
    if (user.fcmTokens.length > 5) {
      console.log(`User ${userId} has ${user.fcmTokens.length} tokens, cleaning up old ones`);
      // Sort by lastUsed (newest first)
      user.fcmTokens.sort((a, b) => new Date(b.lastUsed) - new Date(a.lastUsed));
      // Keep only the 5 most recent tokens
      user.fcmTokens = user.fcmTokens.slice(0, 5);
    }
    
    await user.save();
    
    // Log the current tokens for debugging
    console.log(`User ${userId} now has ${user.fcmTokens.length} FCM tokens:`, 
      user.fcmTokens.map(t => ({
        tokenPreview: t.token.substring(0, 10) + '...',
        device: t.device,
        lastUsed: t.lastUsed
      }))
    );
    
    res.json({ 
      success: true,
      message: 'FCM token registered successfully',
      tokenCount: user.fcmTokens.length
    });
  } catch (error) {
    console.error('Error registering FCM token:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * @route   POST api/notifications/unregister-token
 * @desc    Unregister an FCM token for the user (during logout)
 * @access  Private
 */
router.post('/unregister-token', auth, async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;
    
    console.log(`Unregistering FCM token for user ${userId}`);
    
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if user has FCM tokens
    if (!user.fcmTokens || user.fcmTokens.length === 0) {
      return res.json({ success: true, message: 'No tokens to unregister' });
    }
    
    // Remove the specified token
    const initialTokenCount = user.fcmTokens.length;
    user.fcmTokens = user.fcmTokens.filter(t => t.token !== token);
    
    // If we removed a token, save the user
    if (initialTokenCount !== user.fcmTokens.length) {
      await user.save();
      console.log(`Removed FCM token for user ${userId}. Tokens remaining: ${user.fcmTokens.length}`);
    } else {
      console.log(`Token not found for user ${userId}`);
    }
    
    res.json({ 
      success: true,
      message: 'FCM token unregistered successfully',
      tokenCount: user.fcmTokens.length
    });
  } catch (error) {
    console.error('Error unregistering FCM token:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * @route   PUT api/notifications/preferences
 * @desc    Update user notification preferences
 * @access  Private
 */
router.put('/preferences', auth, async (req, res) => {
  try {
    console.log('PUT /preferences - Request body:', req.body);
    console.log('User ID:', req.user.id);
    
    const user = await User.findById(req.user.id);
    console.log('Current user notification preferences:', user.notificationPreferences);
    
    // Initialize notification preferences if they don't exist
    if (!user.notificationPreferences) {
      console.log('Initializing notification preferences with defaults');
      user.notificationPreferences = {
        friendRequests: true,
        friendAccepted: true,
        workCycleUpdates: true,
        calendarEvents: true,
        appUpdates: true,
        systemAnnouncements: true
      };
    }
    
    // Update preferences with provided values
    const updatedPreferences = {
      ...user.notificationPreferences,
      ...req.body
    };
    
    console.log('Updated preferences to save:', updatedPreferences);
    user.notificationPreferences = updatedPreferences;
    
    // Explicitly mark the notificationPreferences field as modified
    user.markModified('notificationPreferences');
    
    await user.save();
    console.log('User saved successfully, returning preferences:', user.notificationPreferences);
    res.json(user.notificationPreferences);
  } catch (error) {
    console.error('Error updating notification preferences:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

/**
 * @route   GET api/notifications/preferences
 * @desc    Get user notification preferences
 * @access  Private
 */
router.get('/preferences', auth, async (req, res) => {
  try {
    console.log('GET /preferences - User ID:', req.user.id);
    
    const user = await User.findById(req.user.id);
    console.log('Retrieved user:', user ? 'Found' : 'Not found');
    
    // Check if user has notification preferences
    const hasPreferences = user && user.notificationPreferences;
    console.log('User has notification preferences:', hasPreferences ? 'Yes' : 'No');
    
    // Return preferences or default values if not set
    const preferences = user.notificationPreferences || {
      friendRequests: true,
      friendAccepted: true,
      workCycleUpdates: true,
      calendarEvents: true,
      appUpdates: true,
      systemAnnouncements: true
    };
    
    console.log('Returning notification preferences:', preferences);
    res.json(preferences);
  } catch (error) {
    console.error('Error fetching notification preferences:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
