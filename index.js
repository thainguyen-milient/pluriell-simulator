const express = require('express');
const path = require('path');
const { auth, requiresAuth } = require('express-openid-connect');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { verifyToken, extractToken } = require('./utils/authMiddleware');

const scimRoutes = require('./routes/scim');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 3002;

// Security middleware
app.use(helmet());

// CORS configuration for cross-domain authentication
const corsOptions = {
  origin: function (origin, callback) {
    const defaultOrigins = process.env.NODE_ENV === 'production' 
      ? ['https://sso.receipt-flow.io.vn', 'https://pluriell.receipt-flow.io.vn', 'https://receipt.receipt-flow.io.vn']
      : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:3002'];
    
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || defaultOrigins;
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`CORS blocked request from origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};

app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Logging
app.use(morgan('combined'));

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Static file serving for CSS, JS, and other assets
app.use('/public', express.static(path.join(__dirname, 'public')));

// Explicit route for CSS file to ensure it works on Vercel
app.get('/styles.css', (req, res) => {
  res.setHeader('Content-Type', 'text/css');
  res.setHeader('Cache-Control', 'public, max-age=31536000');
  const fs = require('fs');
  const cssPath = path.join(__dirname, 'public', 'styles.css');
  
  if (fs.existsSync(cssPath)) {
    res.sendFile(cssPath);
  } else {
    res.status(404).send('CSS file not found');
  }
});

// Session middleware for storing user data
const session = require('express-session');
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'pluriell-session-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
};

// In production, set domain for cross-subdomain session sharing
if (process.env.NODE_ENV === 'production') {
  sessionConfig.cookie.domain = '.receipt-flow.io.vn';
}

app.use(session(sessionConfig));

// Routes
app.use('/auth', authRoutes);
app.use('/scim/v2', scimRoutes);

// Home route - serve HTML page
app.get('/', (req, res) => {
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
  
  // Check if user is in session
  const isSessionAuthenticated = req.session && req.session.user;
  const sessionUser = req.session.user;
  
  const isAuthenticated = isTokenAuthenticated || isSessionAuthenticated;
  const user = tokenUser || sessionUser;
  
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Pluriell with SSO Gateway</title>
        <link rel="stylesheet" href="/styles.css">
        <script src="/public/session-auth-helper.js"></script>
    </head>
    <body>
        <div class="container">
            <header class="header">
                <h1>🔐 Pluriell simulator with SSO Gateway Integration</h1>
                <div class="auth-status ${isAuthenticated ? 'authenticated' : 'not-authenticated'}">
                    ${isAuthenticated ? '✅ Authenticated' : '❌ Not Authenticated'}
                </div>
            </header>
            
            <main class="main-content">
                ${isAuthenticated ? `
                    <div class="user-info">
                        <h2>Welcome, ${user.name || user.email || 'User'}!</h2>
                        <div class="user-details">
                            <p><strong>Email:</strong> ${user.email || 'N/A'}</p>
                            <p><strong>User ID:</strong> ${user.sub || 'N/A'}</p>
                        </div>
                    </div>
                    
                    <div class="actions">
                        <div class="product-switch">
                            <h3>Switch Product</h3>
                            <a href="${process.env.NODE_ENV === 'production' ? 'https://receipt.receipt-flow.io.vn' : 'http://localhost:3001'}" class="btn btn-primary">Go to Receipt Flow</a>
                        </div>
                        <div class="logout-options">
                            <a href="/auth/logout" class="btn btn-secondary">Logout (Direct)</a>
                            <a href="/auth/logout?sso=true" class="btn btn-danger">Logout via SSO Gateway</a>
                        </div>
                    </div>
                ` : `
                    <div class="welcome">
                        <h2>Welcome to the Pluriell simulator</h2>
                        <p>Please log in to access the SCIM endpoints and manage users and groups.</p>
                        <div class="login-options">
                            <a href="/auth/login" class="btn btn-primary">Login with Auth0 (Direct)</a>
                            <a href="/auth/login?sso=true" class="btn btn-secondary">Login via SSO Gateway</a>
                        </div>
                        <div class="product-switch" style="margin-top: 20px;">
                            <h3>Switch Product</h3>
                            <a href="${process.env.NODE_ENV === 'production' ? 'https://receipt.receipt-flow.io.vn' : 'http://localhost:3001'}" class="btn btn-outline-primary">Go to Receipt Flow</a>
                        </div>
                    </div>
                `}
                
                <div class="api-endpoints">
                    <h3>Available Endpoints</h3>
                    <div class="endpoints-grid">
                        <div class="endpoint-group">
                            <h4>Authentication</h4>
                            <ul>
                                <li><code>GET /auth/login</code> - Direct Login</li>
                                <li><code>GET /auth/login?sso=true</code> - SSO Gateway Login</li>
                                <li><code>GET /auth/logout</code> - Direct Logout</li>
                                <li><code>GET /auth/logout?sso=true</code> - SSO Gateway Logout</li>
                                <li><code>GET /auth/sso-callback</code> - SSO Gateway Callback</li>
                                <li><code>GET /auth/profile</code> - User Profile</li>
                                <li><code>GET /auth/status</code> - Auth Status</li>
                                <li><code>POST /auth/token</code> - Generate JWT Token</li>
                            </ul>
                        </div>
                        
                        <div class="endpoint-group">
                            <h4>SCIM v2 Users</h4>
                            <ul>
                                <li><code>GET /scim/v2/Users</code> - List Users</li>
                                <li><code>POST /scim/v2/Users</code> - Create User</li>
                                <li><code>GET /scim/v2/Users/:id</code> - Get User</li>
                                <li><code>PUT /scim/v2/Users/:id</code> - Update User</li>
                                <li><code>PATCH /scim/v2/Users/:id</code> - Patch User</li>
                                <li><code>DELETE /scim/v2/Users/:id</code> - Delete User</li>
                            </ul>
                        </div>
                        
                        <div class="endpoint-group">
                            <h4>SCIM v2 Groups</h4>
                            <ul>
                                <li><code>GET /scim/v2/Groups</code> - List Groups</li>
                                <li><code>POST /scim/v2/Groups</code> - Create Group</li>
                                <li><code>GET /scim/v2/Groups/:id</code> - Get Group</li>
                                <li><code>PUT /scim/v2/Groups/:id</code> - Update Group</li>
                                <li><code>DELETE /scim/v2/Groups/:id</code> - Delete Group</li>
                            </ul>
                        </div>
                        
                        <div class="endpoint-group">
                            <h4>SCIM v2 Discovery</h4>
                            <ul>
                                <li><code>GET /scim/v2/ServiceProviderConfig</code></li>
                                <li><code>GET /scim/v2/ResourceTypes</code></li>
                                <li><code>GET /scim/v2/Schemas</code></li>
                            </ul>
                        </div>
                    </div>
                </div>
            </main>
            
            <footer class="footer">
                <p>Built with Express.js, Auth0, and SCIM v2 compliance</p>
            </footer>
        </div>
        
    <script>
        // Handle Enhanced Session authentication
        document.addEventListener('DOMContentLoaded', function() {
            // Check if SessionAuthHelper is available
            if (window.SessionAuthHelper) {
                // Try to handle SSO callback with token in URL
                const tokenHandled = window.SessionAuthHelper.handleTokenFromUrl();
                
                if (tokenHandled) {
                    console.log('Session data synced from SSO Gateway');
                    // Refresh the page to update authentication status
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000); // Give more time for session sync
                } else {
                    // Check if user is already authenticated via session
                    if (window.SessionAuthHelper.isAuthenticated()) {
                        console.log('User already authenticated via session');
                        // Optionally refresh to show authenticated state
                        if (!${isAuthenticated}) {
                            // Try to sync session data first
                            window.SessionAuthHelper.syncSessionFromSSO().then(() => {
                                window.location.reload();
                            });
                        }
                    } else if (!${isAuthenticated}) {
                        // Try to sync session from SSO Gateway
                        window.SessionAuthHelper.syncSessionFromSSO().then((sessionData) => {
                            if (sessionData && sessionData.authenticated) {
                                console.log('Session restored from SSO Gateway');
                                window.location.reload();
                            }
                        });
                    }
                }
            }
        });
    </script>
    </body>
    </html>
  `);
});

// Back-channel session creation endpoint (called by SSO Gateway)
app.post('/api/sessions', express.json(), async (req, res) => {
  try {
    // Verify request is from SSO Gateway
    const authHeader = req.headers.authorization;
    const ssoGatewayHeader = req.headers['x-sso-gateway'];
    
    if (!authHeader || !authHeader.startsWith('Bearer ') || !ssoGatewayHeader) {
      return res.status(401).json({
        success: false,
        error: 'Unauthorized - invalid SSO Gateway request'
      });
    }

    const gatewayToken = authHeader.substring(7);
    if (gatewayToken !== process.env.SSO_GATEWAY_SECRET) {
      return res.status(401).json({
        success: false,
        error: 'Unauthorized - invalid gateway token'
      });
    }

    const { jws, user, code } = req.body;
    
    if (!jws || !user || !code) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameters'
      });
    }

    // Verify JWS from SSO Gateway
    let jwtPayload;
    try {
      jwtPayload = jwt.verify(jws, process.env.SSO_GATEWAY_SECRET);
    } catch (error) {
      return res.status(401).json({
        success: false,
        error: 'Invalid JWS signature'
      });
    }

    // Validate JWS payload
    if (jwtPayload.code !== code || jwtPayload.aud !== 'pluriell-api') {
      return res.status(401).json({
        success: false,
        error: 'Invalid JWS payload'
      });
    }

    // Store one-time code and user data temporarily (5 minutes)
    const sessionData = {
      user: user,
      token: jwtPayload.token,
      createdAt: Date.now(),
      expiresAt: Date.now() + (5 * 60 * 1000) // 5 minutes
    };

    // In production, use Redis or database. For now, use memory store
    global.oneTimeCodes = global.oneTimeCodes || new Map();
    global.oneTimeCodes.set(code, sessionData);

    // Clean up expired codes
    for (const [key, value] of global.oneTimeCodes.entries()) {
      if (Date.now() > value.expiresAt) {
        global.oneTimeCodes.delete(key);
      }
    }

    logger.info('Back-channel session created', {
      userId: user.sub,
      code: code.substring(0, 8) + '...' // Log partial code for security
    });

    res.json({
      success: true,
      message: 'Session prepared for handoff'
    });

  } catch (error) {
    logger.error('Session creation error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Back-channel callback endpoint (handles one-time code from browser)
app.get('/auth/callback', (req, res) => {
  const { code, error } = req.query;

  if (error) {
    return res.status(400).send(`
      <html>
        <body>
          <h1>Authentication Error</h1>
          <p>Error: ${error}</p>
          <a href="/">Return to Home</a>
        </body>
      </html>
    `);
  }

  if (!code) {
    return res.status(400).send(`
      <html>
        <body>
          <h1>Missing Code</h1>
          <p>No authentication code provided</p>
          <a href="/">Return to Home</a>
        </body>
      </html>
    `);
  }

  // Retrieve session data using one-time code
  global.oneTimeCodes = global.oneTimeCodes || new Map();
  const sessionData = global.oneTimeCodes.get(code);

  if (!sessionData) {
    return res.status(401).send(`
      <html>
        <body>
          <h1>Invalid or Expired Code</h1>
          <p>The authentication code is invalid or has expired</p>
          <a href="/">Return to Home</a>
        </body>
      </html>
    `);
  }

  // Check if code has expired
  if (Date.now() > sessionData.expiresAt) {
    global.oneTimeCodes.delete(code);
    return res.status(401).send(`
      <html>
        <body>
          <h1>Expired Code</h1>
          <p>The authentication code has expired</p>
          <a href="/">Return to Home</a>
        </body>
      </html>
    `);
  }

  // Create secure session cookie for this application
  const sessionCookie = jwt.sign({
    user: sessionData.user,
    loginTime: new Date().toISOString(),
    sessionId: crypto.randomBytes(16).toString('hex')
  }, process.env.JWT_SECRET, {
    expiresIn: '24h'
  });

  // Set secure session cookie
  res.cookie('pluriell_session', sessionCookie, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    domain: process.env.NODE_ENV === 'production' ? 'pluriell.receipt-flow.io.vn' : undefined
  });

  // Store user in server session as well
  if (req.session) {
    req.session.user = sessionData.user;
    req.session.authenticated = true;
    req.session.loginTime = new Date().toISOString();
  }

  // Clean up one-time code
  global.oneTimeCodes.delete(code);

  logger.info('Back-channel authentication completed', {
    userId: sessionData.user.sub,
    email: sessionData.user.email
  });

  // Redirect to main application
  res.redirect('/');
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'pluriell-simulator'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong!'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', message: 'The requested resource was not found' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
