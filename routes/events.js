const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const auth = require('../middleware/auth');
const Event = require('../models/Event');
const User = require('../models/User');
const { sendEventInviteNotification } = require('../utils/notificationUtils');

/**
 * @route   GET /api/events
 * @desc    Get all events for the current user (including shared events)
 * @access  Private
 */
router.get('/', auth, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    // Base query: get events created by the user or shared with them
    let query = {
      $or: [
        { userId: req.user.id },
        { 'sharedWith.userId': req.user.id }
      ]
    };
    
    // Add date filtering if provided
    if (startDate && endDate) {
      query.$and = [
        { startDate: { $lte: new Date(endDate) } },
        { endDate: { $gte: new Date(startDate) } }
      ];
    }

    const events = await Event.find(query)
      .populate('userId', 'username firstName lastName')
      .populate('sharedWith.userId', 'username firstName lastName')
      .sort({ startDate: 1 });

    res.json(events);
  } catch (err) {
    console.error('Error fetching events:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

/**
 * @route   GET /api/events/:id
 * @desc    Get a single event by ID
 * @access  Private
 */
router.get('/:id', auth, async (req, res) => {
  try {
    console.log(`[DEBUG] Fetching event with ID: ${req.params.id} for user: ${req.user.id}`);
    
    const event = await Event.findById(req.params.id)
      .populate('userId', 'username fullName email profilePicture')
      .populate('sharedWith.userId', 'username fullName email profilePicture');
    
    if (!event) {
      console.log(`[DEBUG] Event not found with ID: ${req.params.id}`);
      return res.status(404).json({ message: 'Event not found' });
    }
    
    // Check if user has permission to view this event
    const isOwner = event.userId._id.toString() === req.user.id;
    const isSharedWithUser = event.sharedWith.some(share => 
      share.userId._id.toString() === req.user.id
    );
    
    console.log(`[DEBUG] Event details:`);
    console.log(`- Title: ${event.title}`);
    console.log(`- Owner: ${event.userId.fullName || event.userId.username}`);
    console.log(`- Start Date: ${event.startDate}`);
    console.log(`- End Date: ${event.endDate}`);
    console.log(`- All Day: ${event.isAllDay}`);
    console.log(`- Location: ${event.location || 'Not specified'}`);
    console.log(`- Event Type: ${event.eventType}`);
    console.log(`- Shared with: ${event.sharedWith.length} users`);
    console.log(`- Current user is owner: ${isOwner}`);
    console.log(`- Current user is shared with: ${isSharedWithUser}`);
    
    // Log reminders information
    console.log(`[DEBUG] Reminders:`);
    if (event.reminders) {
      // Check if reminders is an array (old format) or an object (new format)
      if (Array.isArray(event.reminders)) {
        console.log(`- Reminders array: ${JSON.stringify(event.reminders)}`);
      } else {
        // Object format
        console.log(`- Week before: ${event.reminders.weekBefore || false}`);
        console.log(`- Day before: ${event.reminders.dayBefore || false}`);
        console.log(`- 12 hours before: ${event.reminders.hours12 || false}`);
        console.log(`- 6 hours before: ${event.reminders.hours6 || false}`);
        console.log(`- 1 hour before: ${event.reminders.hour1 || false}`);
      }
    } else {
      console.log(`- No reminders set`);
    }
    
    // Log shared users details
    if (event.sharedWith.length > 0) {
      console.log(`[DEBUG] Shared users details:`);
      event.sharedWith.forEach((share, index) => {
        console.log(`  ${index + 1}. User: ${share.userId.fullName || share.userId.username}, Permission: ${share.permission}, Status: ${share.status || 'pending'}`);
      });
    }
    
    if (!isOwner && !isSharedWithUser) {
      console.log(`[DEBUG] Permission denied for user: ${req.user.id}`);
      return res.status(403).json({ message: 'You do not have permission to view this event' });
    }
    
    res.json(event);
  } catch (err) {
    console.error('Error fetching event:', err);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

/**
 * @route   POST /api/events
 * @desc    Create a new event
 * @access  Private
 */
router.post('/', auth, async (req, res) => {
  try {
    const { 
      title, 
      description, 
      startDate, 
      endDate, 
      location, 
      eventType, 
      color, 
      isAllDay, 
      sharedWith, 
      recurrence,
      reminders 
    } = req.body;

    // Validate dates
    if (new Date(startDate) > new Date(endDate)) {
      return res.status(400).json({ message: 'Start date must be before end date' });
    }

    // Process shared users if provided
    let processedSharedWith = [];
    if (sharedWith && sharedWith.length > 0) {
      // Process user IDs directly
      processedSharedWith = sharedWith.map(share => ({
        userId: share.userId,
        permission: share.permission || 'view',
        status: 'pending'
      }));
    }

    // Process reminders with defaults if not provided
    const defaultReminders = {
      weekBefore: false,
      dayBefore: false,
      hours12: false,
      hours6: false,
      hour1: false
    };

    const eventReminders = reminders ? { ...defaultReminders, ...reminders } : defaultReminders;

    const newEvent = new Event({
      userId: req.user.id,
      title,
      description,
      startDate,
      endDate,
      location,
      eventType: eventType || 'offboard',
      color,
      isAllDay: isAllDay || false,
      sharedWith: processedSharedWith,
      recurrence,
      reminders: eventReminders
    });

    const savedEvent = await newEvent.save();
    
    // Populate user references for response
    const populatedEvent = await Event.findById(savedEvent._id)
      .populate('userId', 'username fullName email profilePicture')
      .populate('sharedWith.userId', 'username fullName email profilePicture');
    
    // Send notifications to invited friends
    if (processedSharedWith && processedSharedWith.length > 0) {
      // Get the current user's information for the notification
      const currentUser = await User.findById(req.user.id).select('fullName email profilePicture');
      
      // Prepare event data for notification
      const eventData = {
        id: savedEvent._id.toString(),
        title: savedEvent.title,
        start: savedEvent.startDate,
        end: savedEvent.endDate,
        location: savedEvent.location || ''
      };
      
      // Send notifications to each invited friend
      for (const share of processedSharedWith) {
        await sendEventInviteNotification(
          share.userId.toString(),
          eventData,
          currentUser
        );
      }
    }
    
    res.status(201).json(populatedEvent);
  } catch (err) {
    console.error('Error creating event:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

/**
 * @route   PUT /api/events/:id
 * @desc    Update an event
 * @access  Private
 */
router.put('/:id', auth, async (req, res) => {
  try {
    const { 
      title, 
      description, 
      startDate, 
      endDate, 
      location, 
      eventType, 
      color, 
      isAllDay, 
      sharedWith, 
      recurrence,
      reminders 
    } = req.body;
    
    // Find the event
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    
    // Check permissions
    const isOwner = event.userId.toString() === req.user.id;
    const sharedUserInfo = event.sharedWith.find(share => 
      share.userId.toString() === req.user.id && share.permission === 'edit'
    );
    
    if (!isOwner && !sharedUserInfo) {
      return res.status(403).json({ message: 'You do not have permission to edit this event' });
    }
    
    // Validate dates if provided
    if (startDate && endDate && new Date(startDate) > new Date(endDate)) {
      return res.status(400).json({ message: 'Start date must be before end date' });
    }
    
    // Update fields if provided
    if (title) event.title = title;
    if (description !== undefined) event.description = description;
    if (startDate) event.startDate = startDate;
    if (endDate) event.endDate = endDate;
    if (location !== undefined) event.location = location;
    if (eventType) event.eventType = eventType;
    if (color) event.color = color;
    if (isAllDay !== undefined) event.isAllDay = isAllDay;
    if (recurrence !== undefined) event.recurrence = recurrence;
    
    // Update reminders if provided
    if (reminders) {
      event.reminders = {
        ...event.reminders,
        ...reminders
      };
    }
    
    // Only the owner can update sharing settings
    if (isOwner && sharedWith) {
      console.log('[DEBUG] Processing shared users in update route:', sharedWith);
      
      // Handle direct userId objects from client
      let processedSharedWith = [];
      
      // Check if we're receiving userId directly or username
      if (sharedWith[0] && sharedWith[0].userId) {
        // Direct userId format from client
        processedSharedWith = sharedWith.map(share => {
          // Check if this user was already shared with to preserve their status
          const existingShare = event.sharedWith.find(existing => 
            (existing.userId._id ? existing.userId._id.toString() : existing.userId.toString()) === share.userId.toString()
          );
          
          return {
            userId: share.userId,
            permission: share.permission || 'view',
            // Preserve existing status for users who were already shared with
            status: existingShare ? existingShare.status : 'pending'
          };
        });
        
        console.log('[DEBUG] Processed shared users with direct IDs:', processedSharedWith);
      } else if (sharedWith[0] && sharedWith[0].username) {
        // Legacy username format
        const usernames = sharedWith.map(share => share.username);
        const users = await User.find({ username: { $in: usernames } }, '_id username');
        
        const userMap = {};
        users.forEach(user => {
          userMap[user.username] = user._id;
        });
        
        processedSharedWith = sharedWith
          .filter(share => userMap[share.username])
          .map(share => ({
            userId: userMap[share.username],
            permission: share.permission || 'view',
            status: 'pending' // Set status to pending for new invites
          }));
          
        console.log('[DEBUG] Processed shared users with usernames:', processedSharedWith);
      }
      
      // Find new users who weren't previously shared with
      const existingUserIds = event.sharedWith.map(share => 
        typeof share.userId === 'object' ? share.userId.toString() : share.userId.toString()
      );
      
      const newSharedUsers = processedSharedWith.filter(share => 
        !existingUserIds.includes(share.userId.toString())
      );
      
      console.log('[DEBUG] Existing user IDs:', existingUserIds);
      console.log('[DEBUG] New shared users:', newSharedUsers);
      
      // Send notifications to newly added friends
      if (newSharedUsers.length > 0) {
        // Get the current user's information for the notification
        const currentUser = await User.findById(req.user.id).select('fullName email profilePicture');
        
        // Prepare event data for notification
        const eventData = {
          id: event._id.toString(),
          title: event.title,
          start: event.startDate,
          end: event.endDate,
          location: event.location || ''
        };
        
        // Send notifications to each newly invited friend
        for (const share of newSharedUsers) {
          await sendEventInviteNotification(
            share.userId.toString(),
            eventData,
            currentUser
          );
        }
      }
      
      event.sharedWith = processedSharedWith;
    }
    
    // Reset Google Calendar sync flag if important details changed
    if (event.isSyncedWithGoogle && (title || description || startDate || endDate || location)) {
      event.isSyncedWithGoogle = false;
    }
    
    const updatedEvent = await event.save();
    
    // Populate user references for response
    const populatedEvent = await Event.findById(updatedEvent._id)
      .populate('userId', 'username fullName email profilePicture')
      .populate('sharedWith.userId', 'username fullName email profilePicture');
    
    res.json(populatedEvent);
  } catch (err) {
    console.error('Error updating event:', err);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

/**
 * @route   DELETE /api/events/:id
 * @desc    Delete an event
 * @access  Private
 */
router.delete('/:id', auth, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    
    // Only the owner can delete an event
    if (event.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'You do not have permission to delete this event' });
    }
    
    await event.deleteOne();
    
    res.json({ message: 'Event deleted successfully' });
  } catch (err) {
    console.error('Error deleting event:', err);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

/**
 * @route   POST /api/events/sync-google
 * @desc    Mark an event as synced with Google Calendar
 * @access  Private
 */
router.post('/sync-google', auth, async (req, res) => {
  try {
    const { eventId, googleCalendarEventId } = req.body;
    
    if (!eventId || !googleCalendarEventId) {
      return res.status(400).json({ message: 'Event ID and Google Calendar Event ID are required' });
    }
    
    const event = await Event.findById(eventId);
    
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    
    // Only the owner can mark an event as synced
    if (event.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'You do not have permission to sync this event' });
    }
    
    event.googleCalendarEventId = googleCalendarEventId;
    event.isSyncedWithGoogle = true;
    
    await event.save();
    
    res.json({ message: 'Event marked as synced with Google Calendar' });
  } catch (err) {
    console.error('Error syncing event with Google Calendar:', err);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

/**
 * @route   POST /api/events/:id/respond
 * @desc    Respond to an event invitation (accept or decline)
 * @access  Private
 */
router.post('/:id/respond', auth, async (req, res) => {
  try {
    const { response } = req.body;
    
    if (!response || !['accepted', 'declined'].includes(response)) {
      return res.status(400).json({ message: 'Valid response (accepted or declined) is required' });
    }
    
    const event = await Event.findById(req.params.id);
    
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    
    // Check if the user is invited to this event
    const shareIndex = event.sharedWith.findIndex(
      share => share.userId.toString() === req.user.id
    );
    
    if (shareIndex === -1) {
      return res.status(403).json({ message: 'You are not invited to this event' });
    }
    
    // Update the invitation status
    event.sharedWith[shareIndex].status = response;
    
    // Save the updated event
    await event.save();
    
    // Get the event owner for notification purposes
    const eventOwner = await User.findById(event.userId).select('_id');
    
    // Notify the event owner about the response (could be implemented later)
    // For now, we'll just return success
    
    res.json({ 
      message: `Event invitation ${response}`,
      event: {
        _id: event._id,
        title: event.title,
        startDate: event.startDate,
        endDate: event.endDate,
        status: response
      }
    });
  } catch (err) {
    console.error('Error responding to event invitation:', err);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

module.exports = router;
