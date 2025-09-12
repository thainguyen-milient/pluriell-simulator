# SCIM v2 API with Auth0 Authentication

A Node.js Express application that provides SCIM v2 endpoints with Auth0 authentication and JSON file storage, ready for Vercel deployment.

## Features

- 🔐 Auth0 authentication with login/logout
- 👥 SCIM v2 compliant User and Group management
- 📁 JSON file-based storage
- 🚀 Ready for Vercel deployment
- 🛡️ Security middleware (Helmet, CORS, Rate limiting)
- ✅ Input validation with Joi
- 🎨 Beautiful responsive UI with modern CSS
- 📱 Mobile-friendly design

## Setup Instructions

### 1. Install Dependencies

```bash
npm install
```

### 2. Auth0 Configuration

1. Create an Auth0 account at [auth0.com](https://auth0.com)
2. Create a new Regular Web Application
3. Configure the following settings in your Auth0 application:
   - **Allowed Callback URLs**: `http://localhost:3002/callback`, `https://your-vercel-domain.vercel.app/callback`
   - **Allowed Logout URLs**: `http://localhost:3002`, `https://your-vercel-domain.vercel.app`
   - **Allowed Web Origins**: `http://localhost:3002`, `https://your-vercel-domain.vercel.app`

### 3. Environment Variables

Copy `.env.example` to `.env` and fill in your Auth0 credentials:

```bash
cp .env.example .env
```

Update the following variables:
- `AUTH0_SECRET`: A long, random string (you can generate one with `openssl rand -hex 32`)
- `AUTH0_CLIENT_ID`: Your Auth0 application's Client ID
- `AUTH0_ISSUER_BASE_URL`: Your Auth0 domain (e.g., `https://your-domain.auth0.com`)
- `AUTH0_BASE_URL`: Your application URL (`http://localhost:3002` for local development)

### 4. Run Locally

```bash
# Development mode with auto-reload
npm run dev

# Production mode
npm start
```

The application will be available at `http://localhost:3002`

## API Endpoints

### Authentication
- `GET /` - Home page with authentication status
- `GET /auth/login` - Login with Auth0
- `GET /auth/logout` - Logout
- `GET /auth/profile` - Get user profile (requires authentication)
- `GET /auth/status` - Check authentication status

### SCIM v2 Endpoints (All require authentication)
- `GET /scim/v2/Users` - List users with optional filtering and pagination
- `GET /scim/v2/Users/:id` - Get specific user
- `POST /scim/v2/Users` - Create new user
- `PUT /scim/v2/Users/:id` - Update user (full replacement)
- `PATCH /scim/v2/Users/:id` - Partial update user
- `DELETE /scim/v2/Users/:id` - Delete user

- `GET /scim/v2/Groups` - List groups
- `GET /scim/v2/Groups/:id` - Get specific group
- `POST /scim/v2/Groups` - Create new group
- `PUT /scim/v2/Groups/:id` - Update group
- `DELETE /scim/v2/Groups/:id` - Delete group

### SCIM v2 Discovery Endpoints
- `GET /scim/v2/ServiceProviderConfig` - Service provider configuration
- `GET /scim/v2/ResourceTypes` - Available resource types
- `GET /scim/v2/Schemas` - SCIM schemas

## Example SCIM Requests

### Create a User
```bash
curl -X POST http://localhost:3002/scim/v2/Users \
  -H "Content-Type: application/json" \
  -H "Cookie: appSession=your-session-cookie" \
  -d '{
    "userName": "john.doe",
    "name": {
      "givenName": "John",
      "familyName": "Doe"
    },
    "displayName": "John Doe",
    "emails": [{
      "value": "john.doe@example.com",
      "primary": true
    }],
    "active": true
  }'
```

### List Users with Filtering
```bash
curl "http://localhost:3002/scim/v2/Users?filter=userName eq \"john.doe\"&startIndex=1&count=10" \
  -H "Cookie: appSession=your-session-cookie"
```

### Update User (PATCH)
```bash
curl -X PATCH http://localhost:3002/scim/v2/Users/user-id \
  -H "Content-Type: application/json" \
  -H "Cookie: appSession=your-session-cookie" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [{
      "op": "replace",
      "path": "active",
      "value": false
    }]
  }'
```

## Vercel Deployment

### 1. Install Vercel CLI
```bash
npm i -g vercel
```

### 2. Deploy
```bash
vercel
```

### 3. Set Environment Variables
After deployment, set your environment variables in the Vercel dashboard:
- `AUTH0_SECRET`
- `AUTH0_CLIENT_ID`
- `AUTH0_ISSUER_BASE_URL`
- `AUTH0_BASE_URL` (set to your Vercel deployment URL)

### 4. Update Auth0 Settings
Update your Auth0 application settings to include your Vercel deployment URL in the allowed URLs.

## Data Storage

User and group data is stored in JSON files:
- `data/users.json` - User data
- `data/groups.json` - Group data

The files are automatically created when the application starts.

## Security Features

- **Helmet**: Security headers
- **CORS**: Cross-origin resource sharing
- **Rate Limiting**: 100 requests per 15 minutes per IP
- **Input Validation**: Joi schema validation for all inputs
- **Authentication**: All SCIM endpoints require Auth0 authentication

## SCIM v2 Compliance

This implementation follows the SCIM v2 specification (RFC 7644) and includes:
- Standard SCIM error responses
- Proper HTTP status codes
- SCIM resource schemas
- Filtering and pagination support
- PATCH operations support
- Service provider configuration endpoint

## Development

### Project Structure
```
├── index.js              # Main application file
├── routes/
│   ├── auth.js           # Authentication routes
│   └── scim.js           # SCIM v2 endpoints
├── utils/
│   ├── userStorage.js    # JSON file storage utilities
│   └── scimValidation.js # SCIM validation schemas
├── data/                 # JSON data files (auto-created)
├── package.json
├── vercel.json          # Vercel deployment configuration
└── README.md
```

### Adding New Features
1. Add new routes in the `routes/` directory
2. Add validation schemas in `utils/scimValidation.js`
3. Extend storage utilities in `utils/userStorage.js`

## Troubleshooting

### Common Issues
1. **Authentication not working**: Check Auth0 configuration and environment variables
2. **CORS errors**: Ensure your domain is properly configured in Auth0
3. **File permission errors**: Ensure the application has write permissions for the `data/` directory

### Logs
Check the console output for detailed error messages and request logs.

## License

MIT
