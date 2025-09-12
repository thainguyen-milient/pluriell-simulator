const express = require('express');
const path = require('path');
const { auth, requiresAuth } = require('express-openid-connect');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
require('dotenv').config();

const scimRoutes = require('./routes/scim');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 3002;

// Security middleware
app.use(helmet());
app.use(cors());

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

// Static file serving for CSS, JS, and other assets
app.use(express.static('public'));

// Explicit route for CSS file to ensure it works on Vercel
app.get('/styles.css', (req, res) => {
  res.setHeader('Content-Type', 'text/css');
  res.sendFile(path.join(__dirname, 'public', 'styles.css'));
});

// Auth0 configuration
const config = {
  authRequired: false,
  auth0Logout: true,
  secret: process.env.AUTH0_SECRET,
  baseURL: process.env.AUTH0_BASE_URL || 'http://localhost:3002',
  clientID: process.env.AUTH0_CLIENT_ID,
  issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
};

// Auth0 middleware
app.use(auth(config));

// Routes
app.use('/auth', authRoutes);
app.use('/scim/v2', scimRoutes);

// Home route - serve HTML page
app.get('/', (req, res) => {
  const isAuthenticated = req.oidc.isAuthenticated();
  const user = req.oidc.user;
  
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Pluriell with Auth0</title>
        <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
        <div class="container">
            <header class="header">
                <h1>🔐Pluriell simulator with Auth0 Authentication</h1>
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
                        <a href="/auth/logout" class="btn btn-secondary">Logout</a>
                    </div>
                ` : `
                    <div class="welcome">
                        <h2>Welcome to the Pluriell simulator</h2>
                        <p>Please log in to access the SCIM endpoints and manage users and groups.</p>
                        <a href="/auth/login" class="btn btn-primary">Login with Auth0</a>
                    </div>
                `}
                
                <div class="api-endpoints">
                    <h3>Available Endpoints</h3>
                    <div class="endpoints-grid">
                        <div class="endpoint-group">
                            <h4>Authentication</h4>
                            <ul>
                                <li><code>GET /auth/login</code> - Login</li>
                                <li><code>GET /auth/logout</code> - Logout</li>
                                <li><code>GET /auth/profile</code> - User Profile</li>
                                <li><code>GET /auth/status</code> - Auth Status</li>
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
        
    </body>
    </html>
  `);
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
