const mysql = require('mysql2/promise');
require('dotenv').config();

let pool;

/**
 * Create MySQL connection pool
 */
async function initializePool() {
  try {
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,

      waitForConnections: true,
      connectionLimit: Number(process.env.DB_POOL_MAX) || 10,
      queueLimit: 0,

      // 🔴 IMPORTANT: Enable Oracle-like named binds
      namedPlaceholders: true
    });

    console.log('✅ MySQL connection pool created');
    return pool;
  } catch (error) {
    console.error('❌ Error creating MySQL pool:', error);
    throw error;
  }
}

/**
 * Get connection from pool
 */
async function getConnection() {
  if (!pool) {
    await initializePool();
  }
  return pool.getConnection();
}

/**
 * Close pool
 */
async function closePool() {
  if (pool) {
    await pool.end();
    pool = null;
    console.log('✅ MySQL pool closed');
  }
}

/**
 * Execute a query using named placeholders
 * @param {string} sql - SQL with :named parameters
 * @param {object} params - Named bind values
 */
async function executeQuery(sql, params = {}) {
  let connection;
  try {
    connection = await getConnection();
    const [rows] = await connection.execute(sql, params);
    return rows;
  } catch (error) {
    console.error('❌ Query execution error:', error);
    throw error;
  } finally {
    if (connection) {
      connection.release();
    }
  }
}

/**
 * Execute multiple queries in a transaction
 * @param {Function} callback
 */
async function executeTransaction(callback) {
  let connection;
  try {
    connection = await getConnection();
    await connection.beginTransaction();

    await callback(connection);

    await connection.commit();
  } catch (error) {
    if (connection) {
      await connection.rollback();
    }
    throw error;
  } finally {
    if (connection) {
      connection.release();
    }
  }
}

module.exports = {
  initializePool,
  getConnection,
  closePool,
  executeQuery,
  executeTransaction
};
