/**
 * Token Decoder Script
 * This script decodes a JWT token without verification to inspect its contents
 * 
 * Usage: node decode-token.js <token>
 */

const jwt = require('jsonwebtoken');

// Get token from command line argument
const token = process.argv[2];

if (!token) {
  console.error('Please provide a token as a command line argument');
  console.error('Usage: node decode-token.js <token>');
  process.exit(1);
}

console.log('Token Decoder');
console.log('=============');
console.log(`Token: ${token.substring(0, 20)}...`);

// Decode token without verification
try {
  const decoded = jwt.decode(token, { complete: true });
  
  if (!decoded) {
    console.error('Failed to decode token. It may not be a valid JWT format.');
    process.exit(1);
  }
  
  console.log('\nHeader:');
  console.log(JSON.stringify(decoded.header, null, 2));
  
  console.log('\nPayload:');
  console.log(JSON.stringify(decoded.payload, null, 2));
  
  // Show human-readable dates for iat and exp
  if (decoded.payload.iat) {
    console.log('\nIssued At:', new Date(decoded.payload.iat * 1000).toISOString());
  }
  
  if (decoded.payload.exp) {
    console.log('Expires At:', new Date(decoded.payload.exp * 1000).toISOString());
    
    // Check if token is expired
    const now = Math.floor(Date.now() / 1000);
    if (decoded.payload.exp < now) {
      console.log('Token is EXPIRED');
    } else {
      const timeLeft = decoded.payload.exp - now;
      console.log(`Token expires in ${timeLeft} seconds (${Math.floor(timeLeft / 60)} minutes)`);
    }
  }
  
  // Try to verify with our JWT_SECRET
  require('dotenv').config();
  if (process.env.JWT_SECRET) {
    try {
      jwt.verify(token, process.env.JWT_SECRET);
      console.log('\nToken is valid with our JWT_SECRET');
    } catch (error) {
      console.log('\nToken is NOT valid with our JWT_SECRET');
      console.log('Error:', error.message);
    }
  }
  
} catch (error) {
  console.error('Error decoding token:', error);
}
