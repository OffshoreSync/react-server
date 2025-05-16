/**
 * Script to copy Firebase service account file from Render secrets to the config directory
 * This ensures the service account file is available without exposing sensitive information in the repository
 */

const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config({ path: path.join(__dirname, '../.env') });


console.log("Running copy-firebase-service-account.js")

// Get the filename from the environment variable
const serviceAccountFileName = process.env.FIREBASE_SERVICE_ACCOUNT_FILE;

// Exit early if the filename is not defined
if (!serviceAccountFileName) {
  console.error('Error: FIREBASE_SERVICE_ACCOUNT_FILE environment variable is not defined');
  console.log('Please set the FIREBASE_SERVICE_ACCOUNT_FILE environment variable to the name of your Firebase service account file');
  process.exit(1);
}

// Define paths
let secretPath;
if (process.env.NODE_ENV === 'development') {
  // First check if the file exists directly in the server/config directory
  const localConfigPath = path.join(__dirname, '../config', serviceAccountFileName);
  if (fs.existsSync(localConfigPath)) {
    secretPath = localConfigPath;
    console.log(`Found service account file in local config directory: ${localConfigPath}`);
  } else {
    // Then check in the secrets directory
    secretPath = path.join(__dirname, '../../secrets', serviceAccountFileName);
    console.log(`Looking for service account file in secrets directory: ${secretPath}`);
  }
} else {
  // For production
  secretPath = path.join('/etc/secrets', serviceAccountFileName);
  console.log(`Looking for service account file in Render secrets: ${secretPath}`);
}

const targetDir = path.join(__dirname, '../config');
const targetPath = path.join(targetDir, serviceAccountFileName);

// Create function to handle the copy process
function copyFirebaseServiceAccount() {
  console.log('Checking for Firebase service account file...');

  try {
    // Check if the secret file exists
    if (fs.existsSync(secretPath)) {
      // Create the target directory if it doesn't exist
      if (!fs.existsSync(targetDir)) {
        console.log(`Creating directory: ${targetDir}`);
        fs.mkdirSync(targetDir, { recursive: true });
      }

      // Only copy if source and target are different paths
      if (secretPath !== targetPath) {
        // Copy the file
        fs.copyFileSync(secretPath, targetPath);
        console.log(`Successfully copied Firebase service account file to ${targetPath}`);
      } else {
        console.log(`Service account file already exists at the target location. No need to copy.`);
      }
    } else {
      console.log(`No Firebase service account file found at ${secretPath}. Skipping.`);
    }
  } catch (error) {
    console.error('Error copying Firebase service account file:', error);
  }
}

// Check if we're in development mode and the file already exists in the target directory
if (process.env.NODE_ENV === 'development' && fs.existsSync(targetPath)) {
  console.log(`Firebase service account file already exists at ${targetPath}`);
  console.log('Skipping copy operation in development mode.');
} else {
  // Execute the function
  copyFirebaseServiceAccount();
}