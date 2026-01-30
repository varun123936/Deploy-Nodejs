/**
 * Global error handler middleware
 */
function errorHandler(err, req, res, next) {
  console.error('Error:', err);

  // Default error
  let statusCode = 500;
  let message = 'Internal server error';

  // Handle specific error types
  if (err.message) {
    message = err.message;
  }

  // Oracle DB errors
  if (err.errorNum) {
    // Unique constraint violation
    if (err.errorNum === 1) {
      statusCode = 409;
      if (err.message.includes('USERNAME')) {
        message = 'Username already exists';
      } else if (err.message.includes('EMAIL')) {
        message = 'Email already exists';
      } else if (err.message.includes('TOKEN')) {
        message = 'Token already exists';
      } else {
        message = 'Duplicate entry';
      }
    }
    // Foreign key constraint violation
    else if (err.errorNum === 2291) {
      statusCode = 400;
      message = 'Invalid reference';
    }
    // Not null constraint violation
    else if (err.errorNum === 1400) {
      statusCode = 400;
      message = 'Required field is missing';
    }
  }

  // Validation errors
  if (err.message.includes('already exists') || err.message.includes('Invalid credentials')) {
    statusCode = 400;
  }

  // Authentication errors
  if (err.message.includes('token') || err.message.includes('Invalid') || err.message.includes('expired')) {
    statusCode = 401;
  }

  res.status(statusCode).json({
    success: false,
    message: message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
}

module.exports = errorHandler;
