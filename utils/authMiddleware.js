const jwt = require('jsonwebtoken');

/**
 * Middleware to extract and verify JWT tokens
 */
const extractToken = (req) => {
  let token = null;
  console.log('Extracting token from request...');
  // Check Authorization header
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    console.log('Token found in Authorization header');
    token = req.headers.authorization.substring(7);
  }
  // Check query parameter
  else if (req.query && req.query.token) {
    console.log('Token found in query parameter');
    token = req.query.token;
  }
  // Check cookies - try multiple possible cookie names
  else if (req.cookies) {
    console.log('Checking cookies for token');
    // Try pluriell_token first (our app's cookie)
    if (req.cookies.pluriell_token) {
      console.log('Token found in pluriell_token cookie');
      token = req.cookies.pluriell_token;
    }
    // Try pluriell-specific client token
    else if (req.cookies.pluriell_token_client) {
      console.log('Token found in pluriell_token_client cookie');
      token = req.cookies.pluriell_token_client;
    }
    // Try access_token (from SSO Gateway)
    else if (req.cookies.access_token) {
      console.log('Token found in access_token cookie');
      token = req.cookies.access_token;
    }
    // Try shared SSO tokens
    else if (req.cookies.sso_token_client) {
      console.log('Token found in sso_token_client cookie');
      token = req.cookies.sso_token_client;
    }
    else if (req.cookies.sso_token) {
      console.log('Token found in sso_token cookie');
      token = req.cookies.sso_token;
    }
  }
  console.log('Token after cookie check:', token);
  // Check localStorage via client-side script (this won't work server-side)
  // This is handled by auth-helper.js on the client side

  return token;
};

/**
 * Middleware to verify JWT tokens from SSO Gateway
 */
const verifyToken = (req, res, next) => {
  try {
    const token = extractToken(req);
    console.log('Extracted Token:', token);
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access token is required',
        redirectTo: `${process.env.SSO_GATEWAY_URL}/auth/login?productId=${process.env.SSO_GATEWAY_PRODUCT_ID}&returnTo=${encodeURIComponent(req.originalUrl)}`
      });
    }

    // Verify token
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (error) {
    console.error('Token verification failed:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Token expired',
        redirectTo: `${process.env.SSO_GATEWAY_URL}/auth/login?productId=${process.env.SSO_GATEWAY_PRODUCT_ID}&returnTo=${encodeURIComponent(req.originalUrl)}`
      });
    }
    
    return res.status(401).json({
      success: false,
      error: 'Invalid token',
      redirectTo: `${process.env.SSO_GATEWAY_URL}/auth/login?productId=${process.env.SSO_GATEWAY_PRODUCT_ID}&returnTo=${encodeURIComponent(req.originalUrl)}`
    });
  }
};

/**
 * Generate custom JWT token for Pluriell
 */
const generateToken = (payload, expiresIn = process.env.JWT_EXPIRES_IN || '24h') => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn,
    issuer: 'pluriell-simulator',
  });
};

/**
 * Middleware to check if user is authenticated via session or token
 */
const requireAuth = (req, res, next) => {
  // Check if user is authenticated via session
  if (req.session && req.session.user) {
    return next();
  }

  // Check for JWT token
  const token = extractToken(req);
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      return next();
    } catch (error) {
      console.error('Token verification failed:', error);
    }
  }

  return res.status(401).json({
    success: false,
    error: 'Authentication required',
    redirectTo: '/auth/login'
  });
};

module.exports = {
  verifyToken,
  requireAuth,
  generateToken,
  extractToken
};
