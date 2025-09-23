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

// Trust proxy - required for Vercel deployment and express-rate-limit to work correctly
// This is needed because Vercel uses proxies that add X-Forwarded-For headers
app.set('trust proxy', 1);

// Security middleware
app.use(helmet());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // The following ensures proper IP detection behind proxies like Vercel
  // This works in conjunction with app.set('trust proxy', 1)
  trustProxy: true
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
app.use(session({
  secret: process.env.SESSION_SECRET || 'pluriell-session-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Routes
app.use('/auth', authRoutes);
app.use('/scim/v2', scimRoutes);

// Home route - serve HTML page
app.get('/', (req, res) => {
  // Check for JWT token authentication
  const token = req.cookies.access_token;
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
        <meta name="sso-gateway-url" content="${process.env.SSO_GATEWAY_URL || 'https://sso.receipt-flow.io.vn'}">
        <title>Pluriell with SSO Gateway</title>
        <link rel="stylesheet" href="/styles.css">
        <script src="/public/auth-helper.js"></script>
        <script src="/public/test-auth.js"></script>
        <!-- Ensure auth-helper.js is loaded properly -->
        <script>
            // Check if AuthHelper is available
            document.addEventListener('DOMContentLoaded', function() {
                if (!window.AuthHelper) {
                    console.error('AuthHelper not loaded properly!');
                    // Try to load it again
                    var script = document.createElement('script');
                    script.src = '/public/auth-helper.js';
                    document.head.appendChild(script);
                } else {
                    console.log('AuthHelper loaded successfully');
                }
            });
        </script>
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
                            <a href="https://receipt.receipt-flow.io.vn" class="btn btn-primary">Go to Receipt Flow</a>
                        </div>
                        <div class="logout-options">
                            <a href="/auth/logout?global=true" class="btn btn-danger">Global Logout (All Systems)</a>
                            <button onclick="window.AuthHelper.globalLogout()" class="btn btn-secondary">Client-Side Global Logout</button>
                        </div>
                        <div class="debug-options" style="margin-top: 20px;">
                            <a href="/token-test" class="btn btn-info">Token Test Page</a>
                            <a href="/auth/debug" class="btn btn-info">Auth Debug Info</a>
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
                            <a href="https://receipt.receipt-flow.io.vn" class="btn btn-outline-primary">Go to Receipt Flow</a>
                        </div>
                        <div class="debug-options" style="margin-top: 20px;">
                            <h3>Debug Tools</h3>
                            <a href="/token-test" class="btn btn-outline-info">Token Test Page</a>
                            <a href="/auth/debug" class="btn btn-outline-info">Auth Debug Info</a>
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
                                <li><code>GET /auth/debug</code> - <a href="/auth/debug" target="_blank">Debug Auth State</a></li>
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
        // Handle token in URL if present (for cross-domain authentication)
        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM loaded, checking for tokens');
            // Check if AuthHelper is available
            if (window.AuthHelper) {
                console.log('AuthHelper found, attempting to handle SSO callback');
                // Try to handle SSO callback with token in URL
                const tokenHandled = window.AuthHelper.handleSSOCallback();
                
                if (tokenHandled) {
                    console.log('Token successfully stored in localStorage/sessionStorage');
                    // Get user info from token
                    const userInfo = window.AuthHelper.getUserInfo();
                    if (userInfo) {
                        console.log('User info from token:', { 
                            sub: userInfo.sub,
                            email: userInfo.email,
                            name: userInfo.name,
                            productId: userInfo.productId
                        });
                    }
                    // Refresh the page to update authentication status
                    setTimeout(() => {
                        window.location.reload();
                    }, 100);
                } else {
                    console.log('No token found in URL, checking other sources');
                    // Check if we're authenticated
                    if (window.AuthHelper.isAuthenticated()) {
                        console.log('User is already authenticated');
                        // Validate the token
                        const token = window.AuthHelper.getToken();
                        if (window.AuthHelper.isTokenValid(token)) {
                            console.log('Token is valid');
                            // Check if token needs refreshing
                            window.AuthHelper.refreshTokenIfNeeded()
                                .then(() => console.log('Token refreshed or still valid'))
                                .catch(err => console.error('Error refreshing token:', err));
                        } else {
                            console.log('Token is invalid, clearing and redirecting to login');
                            window.AuthHelper.clearToken();
                            setTimeout(() => {
                                window.location.reload();
                            }, 100);
                        }
                    } else {
                        console.log('User is not authenticated');
                        // Check for token in cookies that might be accessible to JS
                        const cookies = document.cookie.split(';');
                        for (let i = 0; i < cookies.length; i++) {
                            const cookie = cookies[i].trim();
                            if (cookie.startsWith('pluriell_token_client=')) {
                                const token = cookie.substring('pluriell_token_client='.length, cookie.length);
                                console.log('Found token in client cookie, validating');
                                if (window.AuthHelper.isTokenValid(token)) {
                                    console.log('Token from cookie is valid, storing in localStorage');
                                    window.AuthHelper.storeToken(token);
                                    setTimeout(() => {
                                        window.location.reload();
                                    }, 100);
                                } else {
                                    console.log('Token from cookie is invalid');
                                }
                                break;
                            }
                        }
                    }
                }
            } else {
                console.error('AuthHelper not available!');
            }
        });
    </script>
    </body>
    </html>
  `);
});

// Token test page
app.get('/token-test', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'token-test.html'));
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
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
