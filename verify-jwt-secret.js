/**
 * JWT Secret Verification Script
 * This script helps diagnose JWT verification issues by checking if the JWT_SECRET is consistent
 */

require('dotenv').config();
const jwt = require('jsonwebtoken');

console.log('JWT Secret Verification');
console.log('======================');

// Check if JWT_SECRET is defined
if (!process.env.JWT_SECRET) {
  console.error('ERROR: JWT_SECRET is not defined in environment variables');
  process.exit(1);
}

// Log JWT_SECRET info (first few characters only for security)
const secretPreview = process.env.JWT_SECRET.substring(0, 5) + '...';
console.log(`Using JWT_SECRET: ${secretPreview}`);
console.log(`JWT_SECRET length: ${process.env.JWT_SECRET.length} characters`);
console.log(`NODE_ENV: ${process.env.NODE_ENV || 'not set'}`);

// Create a test token
const payload = {
  sub: 'test-user',
  email: 'test@example.com',
  name: 'Test User',
  productId: process.env.SSO_GATEWAY_PRODUCT_ID || 'pluriell'
};

try {
  // Sign a token with our secret
  const token = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: '1h',
    issuer: 'pluriell-simulator-verify-script'
  });
  
  console.log('\nTest token created successfully');
  console.log(`Token: ${token.substring(0, 20)}...`);
  
  // Verify the token we just created
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    console.log('\nToken verification successful');
    console.log('Verified payload:', {
      sub: verified.sub,
      email: verified.email,
      name: verified.name,
      iss: verified.iss,
      iat: new Date(verified.iat * 1000).toISOString(),
      exp: new Date(verified.exp * 1000).toISOString()
    });
    
    console.log('\nJWT_SECRET is working correctly for token signing and verification');
  } catch (verifyError) {
    console.error('\nERROR: Failed to verify the token we just created');
    console.error('This indicates a serious issue with the JWT implementation');
    console.error('Error details:', verifyError);
  }
} catch (signError) {
  console.error('\nERROR: Failed to create test token');
  console.error('Error details:', signError);
}

console.log('\nTo fix JWT verification issues:');
console.log('1. Ensure the JWT_SECRET is exactly the same in both SSO-Gateway and pruiell-simulator');
console.log('2. Check for any special characters or spaces in the JWT_SECRET');
console.log('3. Verify that the token was created with the same secret used for verification');
console.log('4. Make sure the NODE_ENV is consistent with your expectations');
