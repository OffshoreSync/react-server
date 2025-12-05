const { RekognitionClient, DetectModerationLabelsCommand } = require('@aws-sdk/client-rekognition');
const axios = require('axios');

// Initialize AWS Rekognition client
const rekognitionClient = new RekognitionClient({
  region: process.env.AWS_REKOGNITION_REGION || process.env.AWS_SES_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_REKOGNITION_ACCESS_KEY_ID || process.env.AWS_SES_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_REKOGNITION_SECRET_ACCESS_KEY || process.env.AWS_SES_SECRET_ACCESS_KEY
  }
});

// Moderation confidence thresholds by category
// Higher threshold = stricter (less likely to flag)
// Lower threshold = more lenient (more likely to flag)
const MODERATION_THRESHOLDS = {
  'Explicit Nudity': 60,      // Explicit nudity - strict
  'Suggestive': 75,            // Suggestive content - moderate
  'Violence': 70,              // Violence/gore - moderate
  'Visually Disturbing': 70,   // Disturbing content - moderate
  'Rude Gestures': 70,         // Offensive gestures - moderate
  'Drugs': 70,                 // Drugs/tobacco/alcohol - moderate
  'Tobacco': 75,               // Tobacco products - moderate
  'Alcohol': 80,               // Alcohol - lenient
  'Gambling': 80,              // Gambling - lenient
  'Hate Symbols': 60           // Hate symbols - strict
};

/**
 * Moderate an image from a URL using AWS Rekognition
 * @param {string} imageUrl - The URL of the image to moderate
 * @returns {Promise<{approved: boolean, violations: Array, moderationLabels: Array, error?: string}>}
 */
async function moderateImageFromUrl(imageUrl) {
  try {
    console.log('🔍 Starting image moderation for URL:', imageUrl.substring(0, 50) + '...');

    // Download image as buffer
    const response = await axios.get(imageUrl, { 
      responseType: 'arraybuffer',
      timeout: 10000,
      maxContentLength: 10 * 1024 * 1024 // 10MB max
    });
    
    const imageBytes = Buffer.from(response.data);
    console.log(`📦 Image downloaded: ${imageBytes.length} bytes`);

    // Call AWS Rekognition
    const command = new DetectModerationLabelsCommand({
      Image: { Bytes: imageBytes },
      MinConfidence: 50 // Detect anything above 50% confidence
    });

    const result = await rekognitionClient.send(command);
    const moderationLabels = result.ModerationLabels || [];
    
    console.log(`📊 Rekognition found ${moderationLabels.length} potential moderation labels`);

    // Analyze results against our thresholds
    const violations = [];

    for (const label of moderationLabels) {
      const category = label.ParentName || label.Name;
      const threshold = MODERATION_THRESHOLDS[category] || 70; // Default threshold

      console.log(`   - ${label.Name} (${category}): ${label.Confidence.toFixed(1)}% (threshold: ${threshold}%)`);

      if (label.Confidence >= threshold) {
        violations.push({
          category: category,
          label: label.Name,
          confidence: label.Confidence.toFixed(2)
        });
      }
    }

    const approved = violations.length === 0;
    
    if (approved) {
      console.log('✅ Image approved - no violations detected');
    } else {
      console.log(`❌ Image rejected - ${violations.length} violation(s) detected:`, 
        violations.map(v => `${v.label} (${v.confidence}%)`).join(', '));
    }

    return {
      approved,
      violations,
      moderationLabels: moderationLabels.map(l => ({
        name: l.Name,
        confidence: parseFloat(l.Confidence.toFixed(2)),
        parent: l.ParentName || null
      }))
    };

  } catch (error) {
    console.error('❌ Moderation error:', error.message);
    
    // Fail-safe: if moderation service fails, reject the image to be safe
    return {
      approved: false,
      violations: [{ 
        category: 'Error', 
        label: 'Moderation service error',
        confidence: 0 
      }],
      moderationLabels: [],
      error: error.message
    };
  }
}

/**
 * Verify AWS Rekognition configuration on startup
 */
const verifyModerationConfig = () => {
  const hasAccessKey = !!(process.env.AWS_REKOGNITION_ACCESS_KEY_ID || process.env.AWS_SES_ACCESS_KEY_ID);
  const hasSecretKey = !!(process.env.AWS_REKOGNITION_SECRET_ACCESS_KEY || process.env.AWS_SES_SECRET_ACCESS_KEY);
  
  if (!hasAccessKey || !hasSecretKey) {
    console.warn('⚠️  AWS Rekognition credentials not configured. Image moderation will not work.');
    return false;
  }
  
  console.log('✅ AWS Rekognition configured successfully');
  console.log(`   Region: ${process.env.AWS_REKOGNITION_REGION || process.env.AWS_SES_REGION || 'us-east-1'}`);
  return true;
};

// Initialize on module load
verifyModerationConfig();

module.exports = { 
  moderateImageFromUrl,
  MODERATION_THRESHOLDS
};
