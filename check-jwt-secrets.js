/**
 * JWT Secret Comparison Script
 * This script helps diagnose JWT verification issues by comparing JWT_SECRET values
 */

require('dotenv').config();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

console.log('JWT Secret Comparison');
console.log('====================');

// Get JWT_SECRET from pruiell-simulator
const pruiellJwtSecret = process.env.JWT_SECRET;
if (!pruiellJwtSecret) {
  console.error('ERROR: JWT_SECRET is not defined in pruiell-simulator environment variables');
  process.exit(1);
}

// Calculate hash of pruiell-simulator JWT_SECRET
const pruiellHash = crypto.createHash('sha256').update(pruiellJwtSecret).digest('hex');
console.log(`pruiell-simulator JWT_SECRET hash: ${pruiellHash}`);
console.log(`pruiell-simulator JWT_SECRET length: ${pruiellJwtSecret.length} characters`);
console.log(`pruiell-simulator NODE_ENV: ${process.env.NODE_ENV || 'not set'}`);

// Try to read SSO-Gateway .env file
try {
  const ssoGatewayEnvPath = path.join(__dirname, '..', 'SSO-Gateway', '.env');
  if (fs.existsSync(ssoGatewayEnvPath)) {
    const envContent = fs.readFileSync(ssoGatewayEnvPath, 'utf8');
    const jwtSecretMatch = envContent.match(/JWT_SECRET=(.+)/);
    
    if (jwtSecretMatch && jwtSecretMatch[1]) {
      const ssoGatewayJwtSecret = jwtSecretMatch[1].trim();
      const ssoGatewayHash = crypto.createHash('sha256').update(ssoGatewayJwtSecret).digest('hex');
      
      console.log(`\nSSO-Gateway JWT_SECRET hash: ${ssoGatewayHash}`);
      console.log(`SSO-Gateway JWT_SECRET length: ${ssoGatewayJwtSecret.length} characters`);
      
      // Compare hashes
      if (pruiellHash === ssoGatewayHash) {
        console.log('\n✅ JWT_SECRET values match between pruiell-simulator and SSO-Gateway');
      } else {
        console.log('\n❌ JWT_SECRET values DO NOT match between pruiell-simulator and SSO-Gateway');
        console.log('This is likely the cause of the "invalid signature" error');
      }
    } else {
      console.log('\nCould not find JWT_SECRET in SSO-Gateway .env file');
    }
  } else {
    console.log('\nSSO-Gateway .env file not found or not accessible');
  }
} catch (error) {
  console.error('\nError reading SSO-Gateway .env file:', error.message);
}

// Try to read windsurf-project .env file
try {
  const windsurfEnvPath = path.join(__dirname, '..', 'CascadeProjects', 'windsurf-project', '.env');
  if (fs.existsSync(windsurfEnvPath)) {
    const envContent = fs.readFileSync(windsurfEnvPath, 'utf8');
    const jwtSecretMatch = envContent.match(/JWT_SECRET=(.+)/);
    
    if (jwtSecretMatch && jwtSecretMatch[1]) {
      const windsurfJwtSecret = jwtSecretMatch[1].trim();
      const windsurfHash = crypto.createHash('sha256').update(windsurfJwtSecret).digest('hex');
      
      console.log(`\nwindsurf-project JWT_SECRET hash: ${windsurfHash}`);
      console.log(`windsurf-project JWT_SECRET length: ${windsurfJwtSecret.length} characters`);
      
      // Compare hashes
      if (pruiellHash === windsurfHash) {
        console.log('\n✅ JWT_SECRET values match between pruiell-simulator and windsurf-project');
      } else {
        console.log('\n❌ JWT_SECRET values DO NOT match between pruiell-simulator and windsurf-project');
      }
    } else {
      console.log('\nCould not find JWT_SECRET in windsurf-project .env file');
    }
  } else {
    console.log('\nwindsurf-project .env file not found or not accessible');
  }
} catch (error) {
  console.error('\nError reading windsurf-project .env file:', error.message);
}

console.log('\nTo fix JWT verification issues:');
console.log('1. Ensure the JWT_SECRET is exactly the same in all applications');
console.log('2. Check for any special characters or spaces in the JWT_SECRET');
console.log('3. Verify that the token was created with the same secret used for verification');
console.log('4. Make sure the NODE_ENV is consistent with your expectations');
