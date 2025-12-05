const express = require('express');
const router = express.Router();
const User = require('../models/User');
const auth = require('../middleware/auth');
const rateLimit = require('express-rate-limit');
const cloudinary = require('../services/cloudinaryService');
const { moderateImageFromUrl } = require('../services/moderationService');
const { safeLog } = require('../utils/logger');

// Rate limiter for upload endpoints
const uploadRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Max 3 uploads per hour per user
  message: { 
    error: 'Too many upload attempts. Please try again later.',
    retryAfter: '1 hour'
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Use userId from authenticated request (always present after auth middleware)
  keyGenerator: (req) => `user_${req.user.id}`
});

// 🔒 PROTECTED: Upload profile picture
router.post('/profile-picture/upload', 
  auth,
  uploadRateLimiter,
  async (req, res) => {
    try {
      const { image } = req.body;
      const userId = req.user.id;

      if (!image) {
        return res.status(400).json({ message: 'No image provided' });
      }

      // Validate user exists
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      safeLog(`📸 Profile picture upload initiated for user: ${user.username}`);

      // 1. Upload to Cloudinary
      safeLog('☁️  Uploading to Cloudinary...');
      const uploadResult = await cloudinary.uploader.upload(image, {
        folder: 'profile-pictures',
        public_id: `user_${userId}_${Date.now()}`,
        transformation: [
          { width: 400, height: 400, crop: 'fill', gravity: 'face' },
          { quality: 'auto:good' },
          { fetch_format: 'auto' }
        ],
        resource_type: 'image',
        allowed_formats: ['jpg', 'jpeg', 'png', 'webp']
      });

      const cloudinaryUrl = uploadResult.secure_url;
      const publicId = uploadResult.public_id;

      safeLog(`✅ Uploaded to Cloudinary: ${publicId}`);

      // 2. Moderate with AWS Rekognition
      safeLog('🔍 Starting content moderation...');
      const moderationResult = await moderateImageFromUrl(cloudinaryUrl);

      if (!moderationResult.approved) {
        // Delete from Cloudinary if rejected
        safeLog(`❌ Image failed moderation. Deleting from Cloudinary...`);
        await cloudinary.uploader.destroy(publicId);

        return res.status(400).json({
          message: 'Image failed content moderation',
          violations: moderationResult.violations.map(v => v.category),
          approved: false
        });
      }

      safeLog('✅ Image passed moderation checks');

      // 3. Delete old Cloudinary image if exists
      if (user.cloudinaryProfilePicture?.publicId) {
        safeLog(`🗑️  Deleting old profile picture: ${user.cloudinaryProfilePicture.publicId}`);
        try {
          await cloudinary.uploader.destroy(user.cloudinaryProfilePicture.publicId);
        } catch (deleteError) {
          // Log but don't fail - old image might already be deleted
          safeLog('Warning: Failed to delete old profile picture:', deleteError.message);
        }
      }

      // 4. Update user profile
      user.cloudinaryProfilePicture = {
        url: cloudinaryUrl,
        publicId: publicId,
        moderationStatus: 'approved',
        uploadedAt: new Date(),
        moderationDetails: moderationResult.moderationLabels
      };

      await user.save();

      safeLog(`✅ Profile picture updated successfully for ${user.username}`);

      res.json({
        message: 'Profile picture updated successfully',
        profilePicture: cloudinaryUrl,
        approved: true
      });

    } catch (error) {
      safeLog('❌ Profile picture upload error:', error.message);
      res.status(500).json({ 
        message: 'Failed to upload profile picture',
        error: error.message 
      });
    }
});

// 🔒 PROTECTED: Delete custom profile picture
router.delete('/profile-picture', 
  auth,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Delete from Cloudinary if exists
      if (user.cloudinaryProfilePicture?.publicId) {
        safeLog(`🗑️  Deleting profile picture for ${user.username}: ${user.cloudinaryProfilePicture.publicId}`);
        try {
          await cloudinary.uploader.destroy(user.cloudinaryProfilePicture.publicId);
          safeLog('✅ Deleted from Cloudinary');
        } catch (deleteError) {
          safeLog('Warning: Failed to delete from Cloudinary:', deleteError.message);
        }
      }

      // Clear Cloudinary picture from user
      user.cloudinaryProfilePicture = undefined;
      await user.save();

      // Determine what picture to use as fallback
      const fallbackPicture = user.isGoogleUser && user.profilePicture 
        ? user.profilePicture 
        : null;

      safeLog(`✅ Profile picture deleted for ${user.username}`);

      res.json({ 
        message: 'Profile picture deleted successfully',
        fallbackPicture,
        hasGooglePicture: user.isGoogleUser && !!user.profilePicture,
        useDefaultAvatar: !fallbackPicture
      });

    } catch (error) {
      safeLog('❌ Profile picture delete error:', error.message);
      res.status(500).json({ 
        message: 'Failed to delete profile picture',
        error: error.message 
      });
    }
});

// 🔒 PROTECTED: Get profile picture status
router.get('/profile-picture/status', 
  auth,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const user = await User.findById(userId).select('cloudinaryProfilePicture profilePicture isGoogleUser');

      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      res.json({
        hasCustomPicture: !!user.cloudinaryProfilePicture?.url,
        hasGooglePicture: user.isGoogleUser && !!user.profilePicture,
        status: user.cloudinaryProfilePicture?.moderationStatus || 'none',
        uploadedAt: user.cloudinaryProfilePicture?.uploadedAt,
        url: user.cloudinaryProfilePicture?.url
      });

    } catch (error) {
      safeLog('❌ Profile picture status error:', error.message);
      res.status(500).json({ error: error.message });
    }
});

module.exports = router;
