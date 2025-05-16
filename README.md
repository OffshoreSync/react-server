# OffshoreSync Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.7-blue.svg)](https://semver.org)

This is the backend server for OffshoreSync, providing the API and database management for the offshore work schedule management system.

## Features

- RESTful API built with Express.js
- MongoDB database with Mongoose ODM
- JWT-based authentication with refresh tokens
- Google OAuth integration
- Email verification system
- Friend management system
- Schedule synchronization
- Google Calendar API integration

## Prerequisites

- Node.js (v14 or later)
- MongoDB
- Google Cloud Platform account for OAuth and Calendar API
- Email service credentials (for verification emails)

## Environment Setup

Create a `.env` file in the root directory with:

```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/offshoresync
JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_refresh_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
EMAIL_SERVICE=your_email_service
EMAIL_USER=your_email_user
EMAIL_PASSWORD=your_email_password
```

## Available Scripts

### `npm start`

Starts the server in production mode.

### `npm run dev`

Runs the server in development mode with nodemon for auto-reloading.

## Project Structure

```
server/
├── config/         # Configuration files
├── controllers/    # Route controllers
├── middleware/     # Custom middleware
├── models/         # Mongoose models
├── routes/         # API routes
├── services/       # Business logic
├── utils/          # Utility functions
└── server.js       # Main entry point
```

## API Documentation

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout user

### User Management
- `GET /api/users/profile` - Get user profile
- `PUT /api/users/profile` - Update user profile
- `GET /api/users/search` - Search users

### Friend Management
- `POST /api/friends/request` - Send friend request
- `PUT /api/friends/accept` - Accept friend request
- `GET /api/friends/list` - Get friends list

### Calendar
- `POST /api/calendar/events` - Create calendar event
- `GET /api/calendar/events` - Get user's events
- `PUT /api/calendar/events/:id` - Update event
- `DELETE /api/calendar/events/:id` - Delete event

## Contributing

We welcome contributions! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
