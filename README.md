# Authentication Backend API

Node.js + Express backend with Oracle DB for authentication system.

## Features

- User registration and login
- JWT access tokens (15 min expiry)
- Refresh tokens (7 days expiry, stored in DB)
- HttpOnly cookies for refresh tokens
- Password hashing with bcrypt
- Oracle DB connection pooling
- Protected routes with JWT middleware

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Configure environment variables:**
   - Copy `.env.example` to `.env`
   - Update Oracle DB credentials
   - Set JWT_SECRET (use a strong random string)
   - Configure CORS_ORIGIN (Angular app URL)

3. **Ensure Oracle tables are created:**
   - Run `database/schema.sql` in your Oracle database
   - Tables: `HMS_USERS`, `HMS_REFRESH_TOKENS`

4. **Start server:**
   ```bash
   npm start
   # or for development with auto-reload:
   npm run dev
   ```

## API Endpoints

### POST /auth/register
Register a new user.

**Request Body:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": 1,
      "username": "john_doe",
      "email": "john@example.com",
      "createdAt": "2026-01-27T10:00:00.000Z"
    }
  }
}
```

### POST /auth/login
Login user and get tokens.

**Request Body:**
```json
{
  "username": "john_doe",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": 1,
      "username": "john_doe",
      "email": "john@example.com"
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

**Note:** Refresh token is set as HttpOnly cookie automatically.

### POST /auth/refresh
Refresh access token using refresh token from cookie.

**Response:**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "user": {
      "id": 1,
      "username": "john_doe",
      "email": "john@example.com"
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

### POST /auth/logout
Logout user and revoke refresh token.

**Response:**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

### GET /auth/me
Get current user info (protected route).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": 1,
      "username": "john_doe",
      "email": "john@example.com",
      "createdAt": "2026-01-27T10:00:00.000Z",
      "updatedAt": "2026-01-27T10:00:00.000Z"
    }
  }
}
```

## Project Structure

```
backend/
├── controllers/       # Request handlers
├── routes/           # Route definitions
├── services/         # Business logic
├── middleware/       # Express middleware
├── db/              # Database connection
├── utils/           # Utility functions
├── server.js        # Main server file
└── package.json     # Dependencies
```

## Security Features

- Passwords hashed with bcrypt (10 salt rounds)
- JWT tokens with expiration
- Refresh tokens stored in database
- HttpOnly cookies for refresh tokens
- CORS configuration
- SQL injection prevention (bind variables)
- Error handling without exposing sensitive info
