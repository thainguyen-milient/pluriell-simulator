# Pluriell SSO Gateway Integration

This document explains how the Pluriell simulator has been integrated with the SSO Gateway for single sign-on authentication.

## Overview

The integration allows users to:
1. Login to Pluriell via the SSO Gateway using Auth0
2. Receive a Pluriell-specific JWT token after successful authentication
3. Use the JWT token for API access
4. Logout via the SSO Gateway

## Configuration

### Environment Variables

The following environment variables must be set in the `.env` file:

```
# SSO Gateway Configuration
SSO_GATEWAY_URL=http://localhost:3000
SSO_GATEWAY_PRODUCT_ID=pluriell
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRES_IN=24h
SESSION_SECRET=pluriell-session-secret-key
BASE_URL=http://localhost:3002
```

**Note:** The `JWT_SECRET` must match the one used in the SSO Gateway for token validation.

### SSO Gateway Configuration

The SSO Gateway must be configured to recognize Pluriell as a product:

1. Add Pluriell to the allowed products in the SSO Gateway
2. Set the Pluriell URL in the SSO Gateway's `.env` file:
   ```
   PLURIELL_URL=http://localhost:3002
   ```

## Authentication Flow

### Login Flow

1. User clicks "Login" on the Pluriell homepage
2. User is redirected to the SSO Gateway login page
3. After successful authentication with Auth0, the SSO Gateway generates a JWT token
4. User is redirected to Pluriell's SSO callback endpoint with the token
5. Pluriell validates the token and creates its own JWT token
6. The Pluriell token is stored as an HTTP-only cookie and user information is stored in session
7. User is now authenticated in Pluriell

### Logout Flow

1. User clicks "Logout" on the Pluriell homepage
2. Pluriell clears its token cookie and session
3. User is redirected to the SSO Gateway logout endpoint
4. SSO Gateway logs the user out of Auth0
5. User is redirected back to Pluriell

## Authentication Methods

The Pluriell simulator uses two authentication methods:

1. **JWT Token**: Stored as an HTTP-only cookie and used for API authentication
2. **Session**: Stores user information for server-side authentication

## API Authentication

The Pluriell API endpoints can be accessed using the JWT token in one of three ways:

1. **Authorization Header**: `Authorization: Bearer <token>`
2. **Query Parameter**: `?token=<token>`
3. **Cookie**: The token is automatically included in requests as an HTTP-only cookie

## Testing the Integration

To test the SSO integration:

1. Start the SSO Gateway:
   ```
   cd ../SSO-Gateway
   npm run dev
   ```

2. Start the Pluriell simulator:
   ```
   cd ../pruiell-simulator
   npm run dev
   ```

3. Open a browser and navigate to `http://localhost:3002`
4. Click "Login"
5. Complete the Auth0 login process
6. You should be redirected back to Pluriell and be authenticated

## Endpoints

### Authentication Endpoints

- `GET /auth/login` - Redirect to SSO Gateway login
- `GET /auth/logout` - Logout and redirect to SSO Gateway logout
- `GET /auth/sso-callback` - Handle SSO Gateway callback with token
- `GET /auth/profile` - Get user profile (requires authentication)
- `GET /auth/status` - Check authentication status
- `POST /auth/token` - Generate JWT token (requires authentication)

### SCIM Endpoints

All SCIM endpoints require authentication:

- `GET /scim/v2/Users` - List users
- `POST /scim/v2/Users` - Create user
- `GET /scim/v2/Users/:id` - Get user
- `PUT /scim/v2/Users/:id` - Update user
- `PATCH /scim/v2/Users/:id` - Patch user
- `DELETE /scim/v2/Users/:id` - Delete user
- `GET /scim/v2/Groups` - List groups
- `POST /scim/v2/Groups` - Create group
- `GET /scim/v2/Groups/:id` - Get group
- `PUT /scim/v2/Groups/:id` - Update group
- `DELETE /scim/v2/Groups/:id` - Delete group

## Troubleshooting

If you encounter issues with the SSO integration:

1. Check that both services are running
2. Verify that the `JWT_SECRET` matches between the two services
3. Check the console logs for error messages
4. Ensure the SSO Gateway is properly configured to recognize Pluriell as a product
5. Verify that the callback URL is correctly set up in the SSO Gateway

## Security Considerations

- The JWT token is stored as an HTTP-only cookie to prevent XSS attacks
- HTTPS should be used in production to prevent token interception
- Token expiration is set to 24 hours by default
- The JWT secret should be a strong, random string
- Session data is stored server-side for additional security
