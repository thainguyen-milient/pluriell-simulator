/**
 * Test Authentication Flow
 * This script helps diagnose authentication issues
 */

// Function to test authentication
async function testAuthentication() {
  console.log('Starting authentication test...');
  
  // Step 1: Check if AuthHelper is available
  if (!window.AuthHelper) {
    console.error('AuthHelper not available!');
    return {
      success: false,
      error: 'AuthHelper not available'
    };
  }
  
  console.log('AuthHelper is available');
  
  // Step 2: Check if user is authenticated
  const isAuthenticated = window.AuthHelper.isAuthenticated();
  console.log(`User is authenticated: ${isAuthenticated}`);
  
  if (isAuthenticated) {
    // Step 3: Get user info from token
    const userInfo = window.AuthHelper.getUserInfo();
    console.log('User info from token:', userInfo);
    
    // Step 4: Check token validity
    const token = window.AuthHelper.getToken();
    const isValid = window.AuthHelper.isTokenValid(token);
    console.log(`Token is valid: ${isValid}`);
    
    if (!isValid) {
      console.log('Token is invalid, clearing');
      window.AuthHelper.clearToken();
      return {
        success: false,
        error: 'Invalid token'
      };
    }
    
    // Step 5: Try to refresh token if needed
    try {
      await window.AuthHelper.refreshTokenIfNeeded();
      console.log('Token refreshed or still valid');
    } catch (error) {
      console.error('Error refreshing token:', error);
    }
    
    // Step 6: Fetch auth status from server
    try {
      const response = await fetch('/auth/status', {
        headers: window.AuthHelper.addAuthHeader()
      });
      const data = await response.json();
      console.log('Auth status from server:', data);
      
      return {
        success: true,
        isAuthenticated: true,
        userInfo,
        serverStatus: data
      };
    } catch (error) {
      console.error('Error fetching auth status:', error);
      return {
        success: false,
        error: 'Error fetching auth status'
      };
    }
  } else {
    // Not authenticated
    console.log('User is not authenticated');
    
    // Check for token in cookies
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.startsWith('pluriell_token_client=')) {
        console.log('Found token in client cookie');
        const token = cookie.substring('pluriell_token_client='.length, cookie.length);
        if (window.AuthHelper.isTokenValid(token)) {
          console.log('Token from cookie is valid, storing in localStorage');
          window.AuthHelper.storeToken(token);
          return {
            success: true,
            message: 'Token found in cookie and stored in localStorage'
          };
        } else {
          console.log('Token from cookie is invalid');
        }
      }
    }
    
    // Try to fetch debug info
    try {
      const response = await fetch('/auth/debug');
      const data = await response.json();
      console.log('Debug info from server:', data);
      
      return {
        success: false,
        isAuthenticated: false,
        debugInfo: data
      };
    } catch (error) {
      console.error('Error fetching debug info:', error);
      return {
        success: false,
        error: 'Error fetching debug info'
      };
    }
  }
}

// Add test button to page
function addTestButton() {
  const button = document.createElement('button');
  button.textContent = 'Test Authentication';
  button.style.position = 'fixed';
  button.style.bottom = '10px';
  button.style.right = '10px';
  button.style.zIndex = '9999';
  button.style.padding = '10px';
  button.style.backgroundColor = '#007bff';
  button.style.color = 'white';
  button.style.border = 'none';
  button.style.borderRadius = '5px';
  button.style.cursor = 'pointer';
  
  button.addEventListener('click', async () => {
    const result = await testAuthentication();
    console.log('Test result:', result);
    
    // Show result in alert
    alert(JSON.stringify(result, null, 2));
  });
  
  document.body.appendChild(button);
}

// Run when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('Adding test button');
  addTestButton();
});
