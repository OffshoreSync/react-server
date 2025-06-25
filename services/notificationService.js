const admin = require('firebase-admin');
const User = require('../models/User');
const Notification = require('../models/Notification');

// Create an in-memory cache for invalid tokens to prevent repeatedly trying to send to them
// This helps reduce unnecessary API calls and improves performance
const invalidTokenCache = new Map();
const INVALID_TOKEN_CACHE_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours

// Helper function to add a token to the invalid token cache
function addToInvalidTokenCache(token) {
  invalidTokenCache.set(token, Date.now() + INVALID_TOKEN_CACHE_EXPIRY);
  
  // Schedule cleanup of expired cache entries
  setTimeout(() => {
    const now = Date.now();
    if (invalidTokenCache.has(token) && invalidTokenCache.get(token) < now) {
      invalidTokenCache.delete(token);
    }
  }, INVALID_TOKEN_CACHE_EXPIRY);
}

// Helper function to check if a token is in the invalid token cache
function isTokenInvalid(token) {
  if (!invalidTokenCache.has(token)) {
    return false;
  }
  
  const expiry = invalidTokenCache.get(token);
  const now = Date.now();
  
  if (expiry < now) {
    // Token cache entry has expired, remove it
    invalidTokenCache.delete(token);
    return false;
  }
  
  return true;
}

// Initialize Firebase Admin SDK
let serviceAccount;
try {
  // Try to load from environment variable first
  // This is for production where the service account is stored as an environment variable
  // On Render we use the copy-firebase-service-account.js script to copy the service account file to the config directory
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } else {
    // Load from file using the path from environment variable
    const path = require('path');
    const serviceAccountFile = process.env.FIREBASE_SERVICE_ACCOUNT_FILE || 'firebase-service-account.json';
    const serviceAccountPath = path.join(__dirname, '../config', serviceAccountFile);
    console.log(`Loading Firebase service account from: ${serviceAccountPath}`);
    serviceAccount = require(serviceAccountPath);
  }

  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log('Firebase Admin SDK initialized successfully');
  } else {
    console.log('Firebase Admin SDK already initialized');
  }
} catch (error) {
  console.error('Error initializing Firebase Admin SDK:', error);
}

/**
 * Send a notification to a user
 * @param {string} userId - The recipient user ID
 * @param {string} type - Notification type (FRIEND_REQUEST, FRIEND_ACCEPTED, etc.)
 * @param {object} notification - The notification object with title and body
 * @param {object} data - Additional data to include with the notification
 * @returns {Promise<object>} - Result of the notification send operation
 */
const sendNotification = async (userId, type, notification, data = {}) => {
  try {
    console.log(`Attempting to send ${type} notification to user ${userId}`);
    
    const user = await User.findById(userId);
    
    // Check if user exists
    if (!user) {
      console.warn(`Failed to send notification: User ${userId} not found`);
      return { success: false, error: 'User not found' };
    }
    
    // Check user preferences if they exist
    let preferenceKey = type;
    
    // For calendar event subtypes, we use the calendarEvents preference
    if (type === 'CALENDAR_EVENT' && data.subtype) {
      console.log(`Processing calendar event with subtype: ${data.subtype}`);
      preferenceKey = 'calendarEvents';
    }
    
    if (user.notificationPreferences && user.notificationPreferences[preferenceKey] === false) {
      console.log(`User ${userId} has disabled ${preferenceKey} notifications`);
      return { success: false, error: 'User has disabled this notification type' };
    }
    
    // Create notification in database
    const newNotification = new Notification({
      recipient: userId,
      type,
      title: notification.title,
      body: notification.body,
      data,
      createdAt: new Date()
    });
    
    await newNotification.save();
    console.log(`Saved notification to database with ID: ${newNotification._id}`);
    
    // Check if Firebase is properly initialized
    if (!admin.apps.length) {
      console.error('Firebase Admin SDK not initialized, cannot send push notifications');
      return {
        success: true,
        notification: newNotification,
        pushSuccess: false,
        error: 'Firebase Admin SDK not initialized'
      };
    }
    
    // Send push notification if user has FCM tokens
    if (user.fcmTokens && user.fcmTokens.length > 0) {
      console.log(`User ${userId} has ${user.fcmTokens.length} FCM tokens. Sending push notification...`);
      
      // Log the actual tokens (first few characters only for security)
      console.log('FCM tokens available:', user.fcmTokens.map(t => ({
        tokenPreview: t.token.substring(0, 8) + '...',
        device: t.device,
        lastUsed: t.lastUsed
      })));
      
      // Filter out tokens that haven't been used in the last 30 days
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      
      // Get all tokens as strings and deduplicate them
      const allTokens = user.fcmTokens.map(t => t.token);
      
      // Filter for valid tokens (must be strings with reasonable length)
      // and deduplicate them using a Set
      // Also filter out tokens that are in the invalid token cache
      const uniqueValidTokens = [...new Set(
        allTokens.filter(token => {
          // Basic validation
          if (typeof token !== 'string' || token.length < 20) {
            return false;
          }
          
          // Check if token is in the invalid token cache
          if (isTokenInvalid(token)) {
            console.log(`Skipping previously invalid token: ${token.substring(0, 8)}...`);
            return false;
          }
          
          return true;
        })
      )];
      
      console.log(`User has ${allTokens.length} total tokens, ${uniqueValidTokens.length} unique valid tokens (after filtering invalid tokens)`);
      
      // Store the deduplicated tokens for use later
      const validTokens = uniqueValidTokens;
      
      if (validTokens.length === 0) {
        console.warn(`User ${userId} has no valid FCM tokens`);
        return {
          success: true,
          notification: newNotification,
          pushSuccess: false,
          error: 'No valid FCM tokens'
        };
      }
      
      // Update the lastUsed date for all tokens
      await User.updateMany(
        { _id: userId, 'fcmTokens.token': { $in: validTokens } },
        { $set: { 'fcmTokens.$.lastUsed': new Date() } }
      );
      
      // Ensure all data fields are strings for FCM compatibility
      const stringifiedData = {};
      Object.keys(data).forEach(key => {
        stringifiedData[key] = typeof data[key] === 'object' ? 
          JSON.stringify(data[key]) : 
          String(data[key] || '');
      });
      
      // Add a timestamp to use for cooldown mechanism to prevent duplicate notifications
      const timestamp = Date.now();
      const cooldownKey = `notification_${type}_${timestamp}`;
      
      // Construct the FCM message with both notification and data payloads
      // This ensures compatibility across all platforms (web, Android, iOS)
      const message = {
        // Notification payload for foreground notifications on web and Android
        notification: {
          title: notification.title,
          body: notification.body
        },
        // Data payload for background handling and custom actions
        data: {
          ...stringifiedData,
          title: notification.title, // Include title in data for Android compatibility
          body: notification.body,   // Include body in data for Android compatibility
          type: String(type),
          id: String(newNotification._id),
          notificationId: String(newNotification._id),
          createdAt: newNotification.createdAt.toISOString(),
          timestamp: String(timestamp), // Add timestamp for cooldown mechanism
          cooldownKey: cooldownKey,     // Add cooldown key for deduplication
          clickAction: 'FLUTTER_NOTIFICATION_CLICK' // For Flutter apps
        },
        // Android specific configuration
        android: {
          priority: 'high',
          notification: {
            clickAction: 'FLUTTER_NOTIFICATION_CLICK',
            sound: 'default'
          }
        },
        tokens: validTokens
      };
      
      // Log the message being sent (without tokens for security)
      console.log('Sending FCM message:', {
        notification: message.notification,
        data: message.data,
        tokenCount: validTokens.length
      });
      
      try {
        console.log('Sending FCM message with Firebase Admin SDK...');
        
        // Send messages individually and collect responses
        const responses = [];
        let successCount = 0;
        let failureCount = 0;
        
        // Create a message template without the token
        const messageTemplate = {
          notification: message.notification,
          data: message.data,
          android: message.android,
          apns: message.apns,
          webpush: message.webpush
        };
        
        console.log(`Sending to ${validTokens.length} tokens individually...`);
        
        // Send to each token individually
        for (const token of validTokens) {
          try {
            const singleMessage = { ...messageTemplate, token };
            const result = await admin.messaging().send(singleMessage);
            console.log(`Successfully sent message to token: ${token.substring(0, 8)}...`);
            responses.push({ success: true, messageId: result });
            successCount++;
          } catch (err) {
            console.error(`Error sending to token ${token.substring(0, 8)}...`, err);
            
            // Check if this is a token registration error
            const errorCode = err.code || (err.errorInfo && err.errorInfo.code) || 'unknown-error';
            const errorMessage = err.message || (err.errorInfo && err.errorInfo.message) || 'Unknown error';
            
            // Add to invalid token cache if it's a registration error
            if (errorCode === 'messaging/registration-token-not-registered') {
              console.log(`Adding invalid token to cache: ${token.substring(0, 8)}...`);
              addToInvalidTokenCache(token);
            }
            
            responses.push({ 
              success: false, 
              error: { 
                code: errorCode,
                message: errorMessage
              }
            });
            failureCount++;
          }
        }
        
        // Create a response object similar to sendMulticast
        const response = {
          successCount,
          failureCount,
          responses
        };
        
        console.log(`FCM response: ${response.successCount} successful, ${response.failureCount} failed`);
        
        // Clean up invalid tokens
        if (response.failureCount > 0) {
          const invalidTokens = [];
          
          response.responses.forEach((resp, idx) => {
            if (!resp.success) {
              const errorCode = resp.error ? resp.error.code : 'unknown';
              const errorMessage = resp.error ? resp.error.message : 'Unknown error';
              console.warn(`FCM token failure: ${errorCode} - ${errorMessage}`);
              
              invalidTokens.push(validTokens[idx]);
            }
          });
          
          if (invalidTokens.length > 0) {
            console.log(`Removing ${invalidTokens.length} invalid FCM tokens for user ${userId}`);
            
            await User.updateOne(
              { _id: userId },
              { $pull: { fcmTokens: { token: { $in: invalidTokens } } } }
            );
          }
        }
        
        return {
          success: true,
          notification: newNotification,
          pushSuccess: response.successCount > 0,
          successCount: response.successCount,
          failureCount: response.failureCount
        };
      } catch (fcmError) {
        console.error('Error sending FCM notification:', fcmError);
        
        // Still return success since we saved to database
        return {
          success: true,
          notification: newNotification,
          pushSuccess: false,
          error: fcmError.message
        };
      }
    }
    
    // Return success if we saved to database but didn't send push
    return {
      success: true,
      notification: newNotification,
      pushSuccess: false
    };
  } catch (error) {
    console.error('Error sending notification:', error);
    return { success: false, error: error.message };
  }
};

/**
 * Send a notification to multiple users
 * @param {Array<string>} userIds - Array of recipient user IDs
 * @param {string} type - Notification type
 * @param {object} notification - The notification object with title and body
 * @param {object} data - Additional data to include with the notification
 * @returns {Promise<object>} - Result of the batch notification operation
 */
const sendBatchNotifications = async (userIds, type, notification, data = {}) => {
  const results = {
    total: userIds.length,
    success: 0,
    failed: 0,
    errors: []
  };
  
  for (const userId of userIds) {
    try {
      const result = await sendNotification(userId, type, notification, data);
      if (result.success) {
        results.success++;
      } else {
        results.failed++;
        results.errors.push({ userId, error: result.error });
      }
    } catch (error) {
      results.failed++;
      results.errors.push({ userId, error: error.message });
    }
  }
  
  return results;
};

/**
 * Send a system-wide notification to all users
 * @param {object} notification - The notification object with title and body
 * @param {object} data - Additional data to include with the notification
 * @returns {Promise<object>} - Result of the system notification operation
 */
const sendSystemNotification = async (notification, data = {}) => {
  try {
    // Find all users with FCM tokens
    const users = await User.find({ 'fcmTokens.0': { $exists: true } });
    const userIds = users.map(user => user._id);
    
    return await sendBatchNotifications(userIds, 'SYSTEM', notification, data);
  } catch (error) {
    console.error('Error sending system notification:', error);
    return { success: false, error: error.message };
  }
};

module.exports = {
  sendNotification,
  sendBatchNotifications,
  sendSystemNotification
};
