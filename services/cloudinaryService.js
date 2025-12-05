const cloudinary = require('cloudinary').v2;

// Configure Cloudinary
// The CLOUDINARY_URL environment variable is automatically parsed by the SDK
// Format: cloudinary://API_KEY:API_SECRET@CLOUD_NAME
cloudinary.config({
  cloudinary_url: process.env.CLOUDINARY_URL
});

// Alternatively, you can configure manually:
// cloudinary.config({
//   cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
//   api_key: process.env.CLOUDINARY_API_KEY,
//   api_secret: process.env.CLOUDINARY_API_SECRET
// });

// Verify configuration on startup
const verifyCloudinaryConfig = () => {
  if (!process.env.CLOUDINARY_URL) {
    console.warn('⚠️  CLOUDINARY_URL is not set. Cloudinary uploads will not work.');
    return false;
  }
  
  console.log('✅ Cloudinary configured successfully');
  console.log(`   Cloud Name: ${cloudinary.config().cloud_name}`);
  return true;
};

// Initialize on module load
verifyCloudinaryConfig();

module.exports = cloudinary;
