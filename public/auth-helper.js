/**
 * Auth Helper Functions for Pruiell Simulator
 * Provides client-side authentication utilities for token management
 */

// Store token in localStorage
function storeToken(token) {
  localStorage.setItem('pruiell_token', token);
}

// Get token from multiple possible storage locations
function getToken() {
  // Try localStorage first
  const localToken = localStorage.getItem('pruiell_token');
  if (localToken) {
    console.log('Found token in localStorage');
    return localToken;
  }
  
  // Try sessionStorage as fallback
  const sessionToken = sessionStorage.getItem('pruiell_token');
  if (sessionToken) {
    console.log('Found token in sessionStorage');
    return sessionToken;
  }
  
  // Try to get from cookie (this won't work directly in JS due to httpOnly)
  // but we include it for client-accessible cookies
  try {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.startsWith('pluriell_token_client=')) {
        console.log('Found token in pluriell_token_client cookie');
        return cookie.substring('pluriell_token_client='.length, cookie.length);
      }
      if (cookie.startsWith('pluriell_token=')) {
        console.log('Found token in pluriell_token cookie');
        return cookie.substring('pluriell_token='.length, cookie.length);
      }
    }
  } catch (e) {
    console.error('Error checking cookies:', e);
  }
  
  return null;
}

// Check if token is from SSO Gateway
function isFromSsoGateway(token) {
  if (!token) return false;
  
  try {
    // Decode the token without verification
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    
    const payload = JSON.parse(atob(parts[1]));
    
    // Check for SSO Gateway indicators
    if (payload.iss && (payload.iss.includes('sso-gateway') || payload.iss === 'https://sso.receipt-flow.io.vn')) {
      return true;
    }
    
    if (payload.source && payload.source.includes('sso-gateway')) {
      return true;
    }
    
    return false;
  } catch (e) {
    console.error('Error checking if token is from SSO Gateway:', e);
    return false;
  }
}

// Clear all tokens from all storage locations
function clearToken() {
  console.log('Clearing all tokens from client storage');
  
  // Clear from localStorage - all possible token names
  localStorage.removeItem('pruiell_token');
  localStorage.removeItem('access_token');
  localStorage.removeItem('sso_token');
  localStorage.removeItem('id_token');
  localStorage.removeItem('auth_token');
  
  // Clear from sessionStorage - all possible token names
  sessionStorage.removeItem('pruiell_token');
  sessionStorage.removeItem('access_token');
  sessionStorage.removeItem('sso_token');
  sessionStorage.removeItem('id_token');
  sessionStorage.removeItem('auth_token');
  
  // Try to clear cookies (may not work for httpOnly cookies)
  const cookiesToClear = [
    'pluriell_token',
    'pluriell_token_client',
    'access_token',
    'sso_token',
    'id_token',
    'auth_token'
  ];
  
  try {
    cookiesToClear.forEach(cookieName => {
      document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
      // Also try with domain attribute
      document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=${window.location.hostname};`;
    });
  } catch (e) {
    console.error('Error clearing cookies:', e);
  }
  
  console.log('All tokens cleared from client storage');
}

// Add token to API requests
function addAuthHeader(headers = {}) {
  const token = getToken();
  if (token) {
    return {
      ...headers,
      'Authorization': `Bearer ${token}`
    };
  }
  return headers;
}

// Check if user is authenticated
function isAuthenticated() {
  return !!getToken();
}

// Handle SSO callback with token in URL
function handleSSOCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  
  // Check for token in different possible URL parameters
  const token = urlParams.get('token') || urlParams.get('access_token') || urlParams.get('id_token');
  
  if (token) {
    console.log('Token found in URL parameters');
    
    // Validate the token format
    if (!isTokenValid(token)) {
      console.error('Token from URL is invalid');
      return false;
    }
    
    // Check if token is from SSO Gateway
    if (isFromSsoGateway(token)) {
      console.log('Token is from SSO Gateway');
    } else {
      console.log('Token is not from SSO Gateway, but we will still use it');
    }
    
    // Store the token
    storeToken(token);
    
    // Remove token from URL to prevent security issues
    const cleanUrl = window.location.pathname;
    window.history.replaceState({}, document.title, cleanUrl);
    
    // Also store in sessionStorage as a backup
    try {
      sessionStorage.setItem('pruiell_token', token);
    } catch (e) {
      console.error('Failed to store token in sessionStorage:', e);
    }
    
    return true;
  }
  
  // Check if we have a token in sessionStorage (as a fallback)
  const sessionToken = sessionStorage.getItem('pruiell_token');
  if (sessionToken && !getToken()) {
    console.log('Token found in sessionStorage');
    if (isTokenValid(sessionToken)) {
      storeToken(sessionToken);
      return true;
    } else {
      console.log('Token from sessionStorage is invalid, clearing it');
      sessionStorage.removeItem('pruiell_token');
    }
  }
  
  // Check for token in cookies
  try {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.startsWith('pluriell_token_client=')) {
        const cookieToken = cookie.substring('pluriell_token_client='.length, cookie.length);
        console.log('Found token in pluriell_token_client cookie');
        if (isTokenValid(cookieToken)) {
          storeToken(cookieToken);
          return true;
        } else {
          console.log('Token from cookie is invalid');
        }
      }
    }
  } catch (e) {
    console.error('Error checking cookies:', e);
  }
  
  return false;
}

// Redirect to login
function redirectToLogin() {
  window.location.href = '/auth/login';
}

// Global logout - logs out from all systems
function globalLogout() {
  console.log('Initiating global logout');
  
  // First clear all local tokens
  clearToken();
  
  // Then redirect to the SSO Gateway logout endpoint with global=true
  const ssoGatewayUrl = getSsoGatewayUrl();
  const returnTo = window.location.origin;
  window.location.href = `${ssoGatewayUrl}/auth/logout?global=true&returnTo=${encodeURIComponent(returnTo)}`;
}

// Get SSO Gateway URL from meta tag or use default
function getSsoGatewayUrl() {
  // Try to get from meta tag
  const metaTag = document.querySelector('meta[name="sso-gateway-url"]');
  if (metaTag && metaTag.content) {
    return metaTag.content;
  }
  
  // Default fallback
  return 'http://localhost:3000';
}

// Check token validity
function isTokenValid(token) {
  if (!token) {
    console.log('No token provided');
    return false;
  }
  
  try {
    // Simple check for JWT format (header.payload.signature)
    const parts = token.split('.');
    if (parts.length !== 3) {
      console.log('Token does not have three parts (header.payload.signature)');
      return false;
    }
    
    // Try to decode the header
    try {
      const header = JSON.parse(atob(parts[0]));
      console.log('Token header:', header);
    } catch (headerError) {
      console.error('Error decoding token header:', headerError);
    }
    
    // Try to decode the payload
    const payload = JSON.parse(atob(parts[1]));
    console.log('Token payload:', {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      iss: payload.iss,
      iat: new Date(payload.iat * 1000).toISOString(),
      exp: new Date(payload.exp * 1000).toISOString(),
      productId: payload.productId
    });
    
    // Check if token is expired
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      console.log('Token is expired - expiry:', new Date(payload.exp * 1000).toISOString(), 'current time:', new Date().toISOString());
      return false;
    }
    
    return true;
  } catch (e) {
    console.error('Error validating token:', e);
    return false;
  }
}

// Get user info from token
function getUserInfo() {
  const token = getToken();
  if (!token) return null;
  
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    return JSON.parse(atob(parts[1]));
  } catch (e) {
    console.error('Error getting user info from token:', e);
    return null;
  }
}

// Refresh token if needed
function refreshTokenIfNeeded() {
  const token = getToken();
  if (!token) return Promise.reject('No token available');
  
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return Promise.reject('Invalid token format');
    
    const payload = JSON.parse(atob(parts[1]));
    
    // If token expires in less than 5 minutes, refresh it
    const expiresIn = payload.exp * 1000 - Date.now();
    if (expiresIn < 5 * 60 * 1000) {
      console.log('Token expires soon, refreshing...');
      return fetch('/auth/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      })
      .then(response => {
        if (!response.ok) throw new Error('Failed to refresh token');
        return response.json();
      })
      .then(data => {
        if (data.accessToken) {
          storeToken(data.accessToken);
          return data.accessToken;
        }
        throw new Error('No token in response');
      });
    }
    
    return Promise.resolve(token);
  } catch (e) {
    console.error('Error refreshing token:', e);
    return Promise.reject(e);
  }
}

// Export functions for use in other scripts
window.AuthHelper = {
  storeToken,
  getToken,
  clearToken,
  addAuthHeader,
  isAuthenticated,
  handleSSOCallback,
  redirectToLogin,
  isTokenValid,
  getUserInfo,
  refreshTokenIfNeeded,
  isFromSsoGateway,
  globalLogout,
  getSsoGatewayUrl
};
