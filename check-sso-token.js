/**
 * SSO Token Checker
 * This script makes a request to the SSO Gateway to get a token and checks if we can verify it
 */

require('dotenv').config();
const axios = require('axios');
const jwt = require('jsonwebtoken');

// Configuration
const SSO_GATEWAY_URL = process.env.SSO_GATEWAY_URL || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET;

console.log('SSO Token Checker');
console.log('================');
console.log(`SSO Gateway URL: ${SSO_GATEWAY_URL}`);
console.log(`JWT Secret (first 5 chars): ${JWT_SECRET ? JWT_SECRET.substring(0, 5) + '...' : 'not set'}`);
console.log(`NODE_ENV: ${process.env.NODE_ENV || 'not set'}`);

// Function to fetch a test token from the SSO Gateway
async function fetchTestToken() {
  try {
    console.log('\nAttempting to fetch a test token from SSO Gateway...');
    const response = await axios.get(`${SSO_GATEWAY_URL}/api/test-token`, {
      timeout: 5000
    });
    
    if (response.data && response.data.token) {
      console.log('Successfully received test token');
      return response.data.token;
    } else {
      console.error('Response did not contain a token:', response.data);
      return null;
    }
  } catch (error) {
    console.error('Error fetching test token:', error.message);
    
    // If the endpoint doesn't exist, provide instructions
    if (error.response && error.response.status === 404) {
      console.log('\nThe /api/test-token endpoint does not exist on the SSO Gateway.');
      console.log('You need to add this endpoint to the SSO Gateway to generate test tokens.');
      console.log('Add the following route to your SSO Gateway:');
      console.log(`
// Test token endpoint - for debugging only
app.get('/api/test-token', (req, res) => {
  // Generate a test token
  const token = jwt.sign(
    { 
      sub: 'test-user',
      email: 'test@example.com',
      name: 'Test User',
      productId: 'pluriell'
    }, 
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
  
  res.json({ token });
});
`);
    }
    
    return null;
  }
}

// Main function
async function main() {
  // Try to fetch a test token
  const token = await fetchTestToken();
  
  if (!token) {
    console.log('\nCould not get a test token from the SSO Gateway.');
    console.log('Please check that the SSO Gateway is running and accessible.');
    return;
  }
  
  // Decode the token without verification
  try {
    console.log('\nDecoding token without verification:');
    const decoded = jwt.decode(token, { complete: true });
    
    if (!decoded) {
      console.error('Failed to decode token. It may not be a valid JWT format.');
      return;
    }
    
    console.log('\nHeader:');
    console.log(JSON.stringify(decoded.header, null, 2));
    
    console.log('\nPayload:');
    console.log(JSON.stringify(decoded.payload, null, 2));
    
    // Try to verify with our JWT_SECRET
    if (JWT_SECRET) {
      try {
        jwt.verify(token, JWT_SECRET);
        console.log('\nToken is valid with our JWT_SECRET');
        console.log('This means the SSO Gateway and pruiell-simulator are using the same JWT_SECRET');
      } catch (error) {
        console.log('\nToken is NOT valid with our JWT_SECRET');
        console.log('Error:', error.message);
        console.log('\nThis means the SSO Gateway and pruiell-simulator are using DIFFERENT JWT_SECRETs');
        console.log('Make sure both applications have the exact same JWT_SECRET value in their .env files');
      }
    } else {
      console.log('\nJWT_SECRET is not set, cannot verify token');
    }
    
  } catch (error) {
    console.error('Error processing token:', error);
  }
}

// Run the main function
main().catch(console.error);
