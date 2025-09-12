const express = require('express');
const { requiresAuth } = require('express-openid-connect');
const router = express.Router();

// Login route (handled by Auth0 middleware)
router.get('/login', (req, res) => {
  res.oidc.login({
    returnTo: process.env.AUTH0_BASE_URL || 'http://localhost:3000'
  });
});

// Logout route (handled by Auth0 middleware)
router.get('/logout', (req, res) => {
  res.oidc.logout({
    returnTo: process.env.AUTH0_BASE_URL || 'http://localhost:3000'
  });
});

// Profile route - requires authentication
router.get('/profile', requiresAuth(), (req, res) => {
  res.json({
    user: req.oidc.user,
    isAuthenticated: req.oidc.isAuthenticated()
  });
});

// Check authentication status
router.get('/status', (req, res) => {
  res.json({
    isAuthenticated: req.oidc.isAuthenticated(),
    user: req.oidc.isAuthenticated() ? req.oidc.user : null
  });
});

module.exports = router;
