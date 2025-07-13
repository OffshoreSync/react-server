// server/utils/notificationUtils.js
const notificationService = require('../services/notificationService');
const { safeLog } = require('./logger');

/**
 * Send a friend request notification
 * @param {string} recipientId - The recipient user ID
 * @param {object} sender - The sender user object
 * @returns {Promise<object>} - Result of the notification operation
 */
const sendFriendRequestNotification = async (recipientId, sender) => {
  try {
    safeLog(`Sending friend request notification from ${sender.fullName} to user ${recipientId}`);
    
    // Enhanced payload with more data for better client-side handling
    const result = await notificationService.sendNotification(
      recipientId,
      'FRIEND_REQUEST',
      {
        title: 'New Friend Request',
        body: `${sender.fullName} sent you a friend request`
      },
      {
        senderId: sender._id.toString(),
        senderName: sender.fullName,
        senderPicture: sender.profilePicture || null,
        timestamp: new Date().toISOString(),
        actionType: 'FRIEND_REQUEST',
        priority: 'high'
      }
    );
    
    // Log the result for debugging
    safeLog(`Friend request notification result:`, {
      success: result.success,
      pushSuccess: result.pushSuccess,
      successCount: result.successCount,
      failureCount: result.failureCount
    });
    
    return result;
  } catch (error) {
    safeLog('Error sending friend request notification:', error);
    return { success: false, error: error.message };
  }
};

/**
 * Send a friend request accepted notification
 * @param {string} recipientId - The recipient user ID
 * @param {object} accepter - The user who accepted the request
 * @returns {Promise<object>} - Result of the notification operation
 */
const sendFriendAcceptedNotification = async (recipientId, accepter) => {
  try {
    return await notificationService.sendNotification(
      recipientId,
      'FRIEND_ACCEPTED',
      {
        title: 'Friend Request Accepted',
        body: `${accepter.fullName} accepted your friend request`
      },
      {
        accepterId: accepter._id.toString(),
        accepterName: accepter.fullName,
        accepterPicture: accepter.profilePicture || null
      }
    );
  } catch (error) {
    safeLog('Error sending friend accepted notification:', error);
    return { success: false, error: error.message };
  }
};

/**
 * Send a work cycle update notification
 * @param {string} recipientId - The recipient user ID
 * @param {object} cycleData - The work cycle data
 * @returns {Promise<object>} - Result of the notification operation
 */
const sendWorkCycleUpdateNotification = async (recipientId, cycleData) => {
  try {
    const cycleType = cycleData.type === 'OnBoard' ? 'on-board' : 'off-board';
    const startDate = new Date(cycleData.startDate).toLocaleDateString();
    
    return await notificationService.sendNotification(
      recipientId,
      'WORK_CYCLE_UPDATE',
      {
        title: 'Work Cycle Update',
        body: `Your ${cycleType} cycle starting on ${startDate} has been updated`
      },
      {
        cycleId: cycleData._id.toString(),
        cycleType: cycleData.type,
        startDate: cycleData.startDate,
        endDate: cycleData.endDate
      }
    );
  } catch (error) {
    safeLog('Error sending work cycle update notification:', error);
    return { success: false, error: error.message };
  }
};

// sendCalendarEventNotification function removed - all calendar notifications are now either reminders or invites

/**
 * Send a calendar event reminder notification
 * @param {string} recipientId - The recipient user ID
 * @param {object} eventData - The calendar event data
 * @param {number} minutesBefore - Minutes before the event to send the reminder
 * @returns {Promise<object>} - Result of the notification operation
 */
const sendEventReminderNotification = async (recipientId, eventData, minutesBefore = 30) => {
  try {
    const eventDate = new Date(eventData.start).toLocaleDateString();
    const eventTime = new Date(eventData.start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    let reminderText;
    if (minutesBefore >= 60) {
      const hours = Math.floor(minutesBefore / 60);
      reminderText = `${hours} hour${hours > 1 ? 's' : ''}`;
    } else {
      reminderText = `${minutesBefore} minute${minutesBefore > 1 ? 's' : ''}`;
    }
    
    // Create a direct link to open the event
    const eventLink = `/dashboard?openEvent=${eventData.id}`;
    
    safeLog(`Creating event reminder with direct link: ${eventLink}`);
    
    return await notificationService.sendNotification(
      recipientId,
      'CALENDAR_EVENT',
      {
        title: 'Event Reminder',
        body: `${eventData.title} starts in ${reminderText} (${eventTime})`
      },
      {
        eventId: eventData.id,
        eventTitle: eventData.title,
        eventStart: eventData.start,
        eventEnd: eventData.end,
        eventDate: new Date(eventData.start).toISOString().split('T')[0], // YYYY-MM-DD format for URL params
        subtype: 'REMINDER',
        minutesBefore,
        // Add direct link to open the event
        link: eventLink,
        clickAction: 'OPEN_EVENT'
      }
    );
  } catch (error) {
    safeLog('Error sending event reminder notification:', error);
    return { success: false, error: error.message };
  }
};

/**
 * Send a calendar event invite notification
 * @param {string} recipientId - The recipient user ID
 * @param {object} eventData - The calendar event data
 * @param {object} sender - The user who sent the invite
 * @returns {Promise<object>} - Result of the notification operation
 */
const sendEventInviteNotification = async (recipientId, eventData, sender) => {
  try {
    const eventDate = new Date(eventData.start).toLocaleDateString();
    
    // Create a direct link to open the event
    const eventLink = `/dashboard?openEvent=${eventData.id}`;
    
    safeLog(`Creating event invitation with direct link: ${eventLink}`);
    
    return await notificationService.sendNotification(
      recipientId,
      'CALENDAR_EVENT',
      {
        title: 'Event Invitation',
        body: `${sender.fullName} invited you to "${eventData.title}" on ${eventDate}`
      },
      {
        eventId: eventData.id,
        eventTitle: eventData.title,
        eventStart: eventData.start,
        eventEnd: eventData.end,
        eventDate: new Date(eventData.start).toISOString().split('T')[0], // YYYY-MM-DD format for URL params
        subtype: 'INVITE',
        senderId: sender._id.toString(),
        senderName: sender.fullName,
        // Add direct link to open the event
        link: eventLink,
        clickAction: 'OPEN_EVENT'
      }
    );
  } catch (error) {
    safeLog('Error sending event invite notification:', error);
    return { success: false, error: error.message };
  }
};

/**
 * Send an app update notification to all users
 * @param {string} version - The new app version
 * @param {string} details - Update details
 * @returns {Promise<object>} - Result of the notification operation
 */
const sendAppUpdateNotification = async (version, details = '') => {
  try {
    return await notificationService.sendSystemNotification(
      {
        title: 'App Update Available',
        body: details || `Version ${version} is now available`
      },
      {
        type: 'APP_UPDATE',
        version
      }
    );
  } catch (error) {
    safeLog('Error sending app update notification:', error);
    return { success: false, error: error.message };
  }
};

/**
 * Send a system announcement to all users
 * @param {string} title - Announcement title
 * @param {string} body - Announcement body
 * @param {object} data - Additional data
 * @returns {Promise<object>} - Result of the notification operation
 */
const sendSystemAnnouncement = async (title, body, data = {}) => {
  try {
    return await notificationService.sendSystemNotification(
      {
        title,
        body
      },
      {
        type: 'SYSTEM',
        ...data
      }
    );
  } catch (error) {
    safeLog('Error sending system announcement:', error);
    return { success: false, error: error.message };
  }
};

module.exports = {
  sendFriendRequestNotification,
  sendFriendAcceptedNotification,
  sendWorkCycleUpdateNotification,
  sendEventReminderNotification,
  sendEventInviteNotification,
  sendAppUpdateNotification,
  sendSystemAnnouncement
};
