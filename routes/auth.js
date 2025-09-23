const express = require('express');
const jwt = require('jsonwebtoken');
const { generateToken, verifyToken, extractToken } = require('../utils/authMiddleware');
const router = express.Router();
const cookieParser = require('cookie-parser');

// Add cookie parser middleware
router.use(cookieParser());

// Login route - redirect to SSO Gateway
router.get('/login', (req, res) => {
  // Always redirect to SSO Gateway for login
  const returnTo = req.query.returnTo || process.env.BASE_URL || 'http://localhost:3002';
  return res.redirect(`${process.env.SSO_GATEWAY_URL}/auth/login?productId=receipt&returnTo=${encodeURIComponent(returnTo)}`);
});

// Logout route
router.get('/logout', (req, res) => {
  // Clear all possible token cookies
  res.clearCookie('pluriell_token');
  res.clearCookie('pluriell_token_client');
  res.clearCookie('access_token');
  res.clearCookie('sso_token');
  
  // Clear session
  if (req.session) {
    req.session.destroy();
  }
  
  // Get the SSO Gateway logout URL with global logout parameter
  const returnTo = req.query.returnTo || process.env.BASE_URL || 'http://localhost:3002';
  const logoutUrl = `${process.env.SSO_GATEWAY_URL}/auth/logout?global=true&returnTo=${encodeURIComponent(returnTo)}`;
  
  console.log(`Global logout initiated, redirecting to SSO Gateway: ${logoutUrl}`);
  
  // Redirect to SSO Gateway for global logout
  return res.redirect(logoutUrl);
});

// SSO Callback route - handle token from SSO Gateway
router.get('/sso-callback', (req, res) => {
  // Check for token in different possible URL parameters
  const token = req.query.token || req.query.access_token || req.query.id_token;
  
  if (!token) {
    console.error('No token provided in callback');
    return res.status(400).json({
      success: false,
      error: 'No token provided in callback'
    });
  }
  
  // Log token info (first few characters only for security)
  const tokenPreview = token.substring(0, 10) + '...';
  console.log(`SSO callback - Received token: ${tokenPreview}`);
  
  // Log JWT_SECRET info (first few characters only for security)
  const secretPreview = process.env.JWT_SECRET ? process.env.JWT_SECRET.substring(0, 5) + '...' : 'undefined';
  console.log(`SSO callback - Using JWT_SECRET: ${secretPreview}, NODE_ENV: ${process.env.NODE_ENV}`);
  
  // Try to decode token without verification to see payload
  try {
    const decoded = jwt.decode(token);
    if (decoded) {
      console.log('Token payload (decoded without verification):', {
        sub: decoded.sub,
        email: decoded.email,
        iss: decoded.iss,
        iat: decoded.iat,
        exp: decoded.exp
      });
    }
  } catch (decodeError) {
    console.error('Error decoding token:', decodeError);
  }
  
  try {
    console.log('Attempting to verify token from SSO Gateway');
    // Verify the token from SSO Gateway
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Token verified successfully, payload:', { sub: payload.sub, email: payload.email });
    
    // Generate a Pluriell-specific token
    const pluriellTokenPayload = {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      roles: payload.roles || [],
      permissions: payload.permissions || [],
      source: 'sso-gateway',
      productId: 'pluriell'
    };
    
    const pluriellToken = generateToken(pluriellTokenPayload);
    
    // Set token as HTTP-only cookie with cross-domain support
    res.cookie('pluriell_token', pluriellToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // Use 'none' in production for cross-domain
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    // Also set a non-httpOnly cookie for client-side access
    res.cookie('pluriell_token_client', pluriellToken, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    // Store user info in session
    req.session.user = {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      roles: payload.roles || [],
      permissions: payload.permissions || [],
      loginTime: new Date().toISOString()
    };
    
    // Always use client-side token storage as fallback in production
    const useClientStorage = req.query.clientStorage === 'true' || process.env.NODE_ENV === 'production';
    
    if (useClientStorage) {
      console.log('Using client-side token storage');
      // Redirect with token in URL for client-side storage (will be handled by auth-helper.js)
      return res.redirect(`/?token=${pluriellToken}`);
    } else {
      console.log('Using server-side token storage only');
      // Standard redirect to dashboard or home page
      return res.redirect('/');
    }
  } catch (error) {
    console.error('SSO callback error:', error);
    res.status(401).send(`<html>
      <head>
        <title>Authentication Error</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Authentication Error</h1>
          </div>
          <div class="main-content">
            <div class="welcome">
              <h2>SSO Authentication Failed</h2>
              <p>There was an error processing your SSO token. This could be due to an invalid or expired token.</p>
              <p>Error details: ${error.message}</p>
              <div class="login-options">
                <a href="/" class="btn btn-primary">Return to Home</a>
                <a href="/auth/login" class="btn btn-secondary">Try Again</a>
              </div>
            </div>
          </div>
        </div>
      </body>
    </html>`);
  }
});

// Profile route - requires authentication
router.get('/profile', verifyToken, (req, res) => {
  // Check for JWT token or session authentication
  const user = req.user || req.session.user;
  
  if (!user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required',
      redirectTo: '/auth/login'
    });
  }
  
  res.json({
    user: user,
    isAuthenticated: true
  });
});

// Check authentication status
router.get('/status', (req, res) => {
  // Check for JWT token authentication
  const token = extractToken(req);
  let isTokenAuthenticated = false;
  let tokenUser = null;
  
  if (token) {
    try {
      tokenUser = jwt.verify(token, process.env.JWT_SECRET);
      isTokenAuthenticated = true;
    } catch (error) {
      console.error('Token verification failed:', error);
    }
  }
  
  // Check for session authentication
  const isSessionAuthenticated = req.session && req.session.user;
  const sessionUser = req.session.user;
  
  const isAuthenticated = isTokenAuthenticated || isSessionAuthenticated;
  const user = tokenUser || sessionUser;
  
  res.json({
    isAuthenticated: isAuthenticated,
    user: user,
    authMethod: isTokenAuthenticated ? 'jwt' : (isSessionAuthenticated ? 'session' : 'none')
  });
});

// Generate JWT token for client use
router.post('/token', (req, res) => {
  try {
    // First check for token in Authorization header (for token refresh)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      try {
        // Verify the token
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Token refresh request with valid token');
        
        // Generate a new token with the same payload but extended expiration
        const newToken = generateToken({
          sub: payload.sub,
          email: payload.email,
          name: payload.name,
          picture: payload.picture,
          roles: payload.roles || [],
          permissions: payload.permissions || [],
          source: payload.source || 'pluriell-refresh',
          productId: 'pluriell'
        });
        
        // Set the new token as HTTP-only cookie
        res.cookie('pluriell_token', newToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
          maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        
        // Also set a non-httpOnly cookie for client-side access
        res.cookie('pluriell_token_client', newToken, {
          httpOnly: false,
          secure: process.env.NODE_ENV === 'production',
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
          maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        
        return res.json({
          success: true,
          accessToken: newToken,
          tokenType: 'Bearer',
          expiresIn: process.env.JWT_EXPIRES_IN || '24h',
          user: payload
        });
      } catch (error) {
        console.error('Token refresh failed:', error);
        // Continue to session-based token generation
      }
    }
    
    // Check for session authentication
    const sessionUser = req.session && req.session.user;
    
    if (!sessionUser) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        redirectTo: '/auth/login'
      });
    }
    
    const tokenPayload = {
      sub: sessionUser.sub,
      email: sessionUser.email,
      name: sessionUser.name,
      picture: sessionUser.picture,
      roles: sessionUser.roles || [],
      permissions: sessionUser.permissions || [],
      source: 'pluriell-direct',
      productId: 'pluriell'
    };
    
    const accessToken = generateToken(tokenPayload);
    
    // Set token as HTTP-only cookie
    res.cookie('pluriell_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    // Also set a non-httpOnly cookie for client-side access
    res.cookie('pluriell_token_client', accessToken, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    res.json({
      success: true,
      accessToken,
      tokenType: 'Bearer',
      expiresIn: process.env.JWT_EXPIRES_IN || '24h',
      user: tokenPayload,
    });
  } catch (error) {
    console.error('Token generation error:', error);
    res.status(500).json({
      success: false,
      error: 'Token generation failed',
    });
  }
});

/**
 * GET /auth/debug
 * Debug endpoint to check authentication state
 */
router.get('/debug', (req, res) => {
  // Collect all possible authentication information
  const authInfo = {
    headers: {
      authorization: req.headers.authorization ? 'Present (not shown for security)' : 'Not present',
      cookie: req.headers.cookie ? 'Present (not shown for security)' : 'Not present'
    },
    cookies: {
      names: Object.keys(req.cookies || {}),
      pluriell_token: req.cookies?.pluriell_token ? 'Present (not shown for security)' : 'Not present',
      pluriell_token_client: req.cookies?.pluriell_token_client ? 'Present (not shown for security)' : 'Not present',
      access_token: req.cookies?.access_token ? 'Present (not shown for security)' : 'Not present',
      sso_token: req.cookies?.sso_token ? 'Present (not shown for security)' : 'Not present'
    },
    session: {
      exists: !!req.session,
      user: req.session?.user ? {
        sub: req.session.user.sub,
        email: req.session.user.email,
        name: req.session.user.name,
        // Other fields omitted for security
      } : null
    },
    token: {
      extracted: false,
      valid: false,
      payload: null,
      source: null
    },
    environment: {
      NODE_ENV: process.env.NODE_ENV,
      SSO_GATEWAY_URL: process.env.SSO_GATEWAY_URL,
      SSO_GATEWAY_PRODUCT_ID: process.env.SSO_GATEWAY_PRODUCT_ID,
      BASE_URL: process.env.BASE_URL
    }
  };
  
  // Try to extract and verify token
  const token = extractToken(req);
  if (token) {
    authInfo.token.extracted = true;
    authInfo.token.source = 'Unknown';
    
    // Determine token source
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      authInfo.token.source = 'Authorization header';
    } else if (req.query && req.query.token) {
      authInfo.token.source = 'Query parameter';
    } else if (req.cookies) {
      if (req.cookies.pluriell_token) {
        authInfo.token.source = 'pluriell_token cookie';
      } else if (req.cookies.access_token) {
        authInfo.token.source = 'access_token cookie';
      } else if (req.cookies.sso_token) {
        authInfo.token.source = 'sso_token cookie';
      }
    }
    
    try {
      // Verify token
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      authInfo.token.valid = true;
      authInfo.token.payload = {
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
        productId: payload.productId,
        source: payload.source,
        iat: payload.iat,
        exp: payload.exp,
        iss: payload.iss
      };
    } catch (error) {
      authInfo.token.error = {
        name: error.name,
        message: error.message
      };
    }
  }
  
  res.json({
    success: true,
    authInfo
  });
});

module.exports = router;
