/**
 * Event color mapping utility for custom user events
 * Provides consistent color schemes across the application
 */

// Light mode colors for custom events
const lightModeColors = {
  onboard: '#D32F2F', // Red (matching work cycle onboard color)
  offboard: '#1976D2'  // Blue (matching work cycle offboard color)
};

// Dark mode colors for custom events
const darkModeColors = {
  onboard: '#F87171', // Lighter Red (matching work cycle onboard color in dark mode)
  offboard: '#70B7F1'  // Lighter Blue (matching work cycle offboard color in dark mode)
};

/**
 * Get the color for an event type based on the theme mode
 * @param {string} eventType - The type of event (onboard, offboard)
 * @param {string} mode - 'light' or 'dark'
 * @returns {string} - Hex color code
 */
const getEventColor = (eventType, mode = 'light') => {
  const colors = mode === 'dark' ? darkModeColors : lightModeColors;
  return colors[eventType.toLowerCase()] || colors.offboard;
};

/**
 * Get all event colors for a specific mode
 * @param {string} mode - 'light' or 'dark'
 * @returns {Object} - Object with event types as keys and colors as values
 */
const getAllEventColors = (mode = 'light') => {
  return mode === 'dark' ? darkModeColors : lightModeColors;
};

module.exports = {
  getEventColor,
  getAllEventColors,
  lightModeColors,
  darkModeColors
};
