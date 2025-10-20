const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Friend = require('../models/Friend');
const { safeLog } = require('../utils/logger');

/**
 * @route   GET /api/stats/public
 * @desc    Get public stats for landing page (no auth required)
 * @access  Public
 */
router.get('/public', async (req, res) => {
  try {
    // Count total users
    const userCount = await User.countDocuments();

    // Count total accepted connections (each connection is stored twice, so divide by 2)
    const connectionCount = await Friend.countDocuments({ status: 'ACCEPTED' });
    const totalConnections = Math.floor(connectionCount / 2);

    safeLog('info', 'Public stats fetched', { userCount, totalConnections });

    res.json({
      users: userCount,
      connections: totalConnections
    });
  } catch (error) {
    safeLog('error', 'Error fetching public stats', { error: error.message });
    res.status(500).json({ 
      message: 'Error fetching statistics',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;
