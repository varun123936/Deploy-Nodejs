const bcrypt = require('bcrypt');
const { executeQuery } = require('../db/connection');
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken
} = require('../utils/jwt');

const SALT_ROUNDS = 10;

/**
 * Register a new user
 */
async function registerUser(userData) {
  const { username, email, password } = userData;

  // 1️⃣ Check if user already exists
  const checkUserSql = `
    SELECT ID, USERNAME, EMAIL
    FROM HMS_USERS
    WHERE USERNAME = :username OR EMAIL = :email
  `;

  const existingUsers = await executeQuery(checkUserSql, { username, email });

  if (existingUsers.length > 0) {
    const existing = existingUsers[0];
    if (existing.USERNAME === username) {
      throw new Error('Username already exists');
    }
    if (existing.EMAIL === email) {
      throw new Error('Email already exists');
    }
  }

  // 2️⃣ Hash password
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  // 3️⃣ Insert user
  const insertUserSql = `
    INSERT INTO HMS_USERS (USERNAME, EMAIL, PASSWORD_HASH, CREATED_AT, UPDATED_AT)
    VALUES (:username, :email, :passwordHash, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `;

  await executeQuery(insertUserSql, {
    username,
    email,
    passwordHash
  });

  // 4️⃣ Fetch created user
  const getUserSql = `
    SELECT ID, USERNAME, EMAIL, CREATED_AT
    FROM HMS_USERS
    WHERE USERNAME = :username
  `;

  const users = await executeQuery(getUserSql, { username });

  if (users.length === 0) {
    throw new Error('Failed to create user');
  }

  const user = users[0];

  return {
    id: user.ID,
    username: user.USERNAME,
    email: user.EMAIL,
    createdAt: user.CREATED_AT
  };
}

/**
 * Login user
 */
async function loginUser(credentials) {
  const { username, password } = credentials;

  const getUserSql = `
    SELECT ID, USERNAME, EMAIL, PASSWORD_HASH
    FROM HMS_USERS
    WHERE USERNAME = :username OR EMAIL = :username
  `;

  const users = await executeQuery(getUserSql, { username });

  if (users.length === 0) {
    throw new Error('Invalid credentials');
  }

  const user = users[0];

  const isPasswordValid = await bcrypt.compare(password, user.PASSWORD_HASH);
  if (!isPasswordValid) {
    throw new Error('Invalid credentials');
  }

  // Tokens
  const accessToken = generateAccessToken({
    userId: user.ID,
    username: user.USERNAME,
    email: user.EMAIL
  });

  const refreshToken = generateRefreshToken({
    userId: user.ID
  });

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);

  const insertTokenSql = `
    INSERT INTO HMS_REFRESH_TOKENS
      (USER_ID, TOKEN, EXPIRES_AT, CREATED_AT, IS_REVOKED)
    VALUES
      (:userId, :token, :expiresAt, CURRENT_TIMESTAMP, 0)
  `;

  await executeQuery(insertTokenSql, {
    userId: user.ID,
    token: refreshToken,
    expiresAt
  });

  return {
    user: {
      id: user.ID,
      username: user.USERNAME,
      email: user.EMAIL
    },
    accessToken,
    refreshToken
  };
}

/**
 * Refresh access token
 */
async function refreshAccessToken(refreshToken) {
  if (!refreshToken) {
    throw new Error('Refresh token is required');
  }

  try {
    verifyRefreshToken(refreshToken);
  } catch {
    throw new Error('Invalid or expired refresh token');
  }

  const checkTokenSql = `
    SELECT
      U.ID AS USER_ID,
      U.USERNAME,
      U.EMAIL
    FROM HMS_REFRESH_TOKENS RT
    JOIN HMS_USERS U ON RT.USER_ID = U.ID
    WHERE RT.TOKEN = :token
      AND RT.IS_REVOKED = 0
      AND RT.EXPIRES_AT > CURRENT_TIMESTAMP
  `;

  const tokens = await executeQuery(checkTokenSql, { token: refreshToken });

  if (tokens.length === 0) {
    throw new Error('Invalid or expired refresh token');
  }

  const tokenData = tokens[0];

  const accessToken = generateAccessToken({
    userId: tokenData.USER_ID,
    username: tokenData.USERNAME,
    email: tokenData.EMAIL
  });

  return {
    accessToken,
    user: {
      id: tokenData.USER_ID,
      username: tokenData.USERNAME,
      email: tokenData.EMAIL
    }
  };
}

/**
 * Logout user
 */
async function logoutUser(refreshToken) {
  if (!refreshToken) return;

  const revokeSql = `
    UPDATE HMS_REFRESH_TOKENS
    SET IS_REVOKED = 1
    WHERE TOKEN = :token AND IS_REVOKED = 0
  `;

  await executeQuery(revokeSql, { token: refreshToken });
}

/**
 * Get user by ID
 */
async function getUserById(userId) {
  const getUserSql = `
    SELECT ID, USERNAME, EMAIL, CREATED_AT, UPDATED_AT
    FROM HMS_USERS
    WHERE ID = :userId
  `;

  const users = await executeQuery(getUserSql, { userId });

  if (users.length === 0) {
    throw new Error('User not found');
  }

  const user = users[0];

  return {
    id: user.ID,
    username: user.USERNAME,
    email: user.EMAIL,
    createdAt: user.CREATED_AT,
    updatedAt: user.UPDATED_AT
  };
}

module.exports = {
  registerUser,
  loginUser,
  refreshAccessToken,
  logoutUser,
  getUserById
};
