const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');  // Add path module
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests from your frontend domains
    const allowedOrigins = [
      process.env.REACT_APP_FRONTEND_URL,  // Your Render frontend URL
      'https://your-app-name.onrender.com', // Render's default URL
      'http://localhost:3000',   // Local development
      undefined                  // Allow undefined origin for local development
    ].filter(Boolean); // Remove any falsy values
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());

// Serve static files from React app
const buildPath = path.join(__dirname, '../client/build');
app.use(express.static(buildPath));

// Catch-all route to serve index.html for client-side routing
app.get('*', (req, res) => {
  res.sendFile(path.join(buildPath, 'index.html'));
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost/mern_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const connection = mongoose.connection;
connection.once('open', () => {
  console.log('MongoDB database connection established successfully');
});

// Routes
const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

// Root route
app.get('/', (req, res) => {
  res.send('Welcome to the Offshore Sync Application');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port: ${PORT}`);
});
