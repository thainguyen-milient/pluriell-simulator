const express = require('express');
const { UserStorage, GroupStorage } = require('../utils/userStorage');
const { userSchema, groupSchema, patchSchema, querySchema } = require('../utils/scimValidation');
const { requireAuth } = require('../utils/authMiddleware');
const router = express.Router();

// Middleware to require authentication for all SCIM endpoints
router.use(requireAuth);

// SCIM Error response helper
function scimError(res, status, scimType, detail) {
  return res.status(status).json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
    scimType: scimType,
    detail: detail,
    status: status.toString()
  });
}

// SCIM List response helper
function scimListResponse(resources, startIndex = 1, count = 20, totalResults = 0) {
  return {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: totalResults,
    startIndex: startIndex,
    itemsPerPage: resources.length,
    Resources: resources
  };
}

// GET /Users - List users with optional filtering
router.get('/Users', async (req, res) => {
  try {
    const { error, value } = querySchema.validate(req.query);
    if (error) {
      return scimError(res, 400, 'invalidFilter', error.details[0].message);
    }

    const { filter, sortBy, sortOrder, startIndex, count } = value;
    let users = await UserStorage.getAllUsers();

    // Apply filtering if provided
    if (filter) {
      // Simple filter implementation for userName
      if (filter.includes('userName eq')) {
        const userName = filter.match(/userName eq "([^"]+)"/)?.[1];
        if (userName) {
          users = users.filter(user => user.userName === userName);
        }
      }
    }

    // Apply sorting
    if (sortBy) {
      users.sort((a, b) => {
        const aVal = a[sortBy] || '';
        const bVal = b[sortBy] || '';
        const comparison = aVal.localeCompare(bVal);
        return sortOrder === 'descending' ? -comparison : comparison;
      });
    }

    // Apply pagination
    const totalResults = users.length;
    const start = startIndex - 1;
    const paginatedUsers = users.slice(start, start + count);

    res.json(scimListResponse(paginatedUsers, startIndex, count, totalResults));
  } catch (error) {
    console.error('Error listing users:', error);
    scimError(res, 500, 'internalError', 'Internal server error');
  }
});

// GET /Users/:id - Get specific user
router.get('/Users/:id', async (req, res) => {
  try {
    const user = await UserStorage.getUserById(req.params.id);
    if (!user) {
      return scimError(res, 404, 'resourceNotFound', 'User not found');
    }
    res.json(user);
  } catch (error) {
    console.error('Error getting user:', error);
    scimError(res, 500, 'internalError', 'Internal server error');
  }
});

// POST /Users - Create new user
router.post('/Users', async (req, res) => {
  try {
    const { error, value } = userSchema.validate(req.body);
    if (error) {
      return scimError(res, 400, 'invalidValue', error.details[0].message);
    }

    const newUser = await UserStorage.createUser(value);
    res.status(201).json(newUser);
  } catch (error) {
    if (error.message === 'User already exists') {
      return scimError(res, 409, 'uniqueness', 'User with this userName already exists');
    }
    console.error('Error creating user:', error);
    scimError(res, 500, 'internalError', 'Internal server error');
  }
});

// PUT /Users/:id - Update user (full replacement)
router.put('/Users/:id', async (req, res) => {
  try {
    const { error, value } = userSchema.validate(req.body);
    if (error) {
      return scimError(res, 400, 'invalidValue', error.details[0].message);
    }

    const updatedUser = await UserStorage.updateUser(req.params.id, value);
    if (!updatedUser) {
      return scimError(res, 404, 'resourceNotFound', 'User not found');
    }

    res.json(updatedUser);
  } catch (error) {
    console.error('Error updating user:', error);
    scimError(res, 500, 'internalError', 'Internal server error');
  }
});

// PATCH /Users/:id - Partial update user
router.patch('/Users/:id', async (req, res) => {
  try {
    const { error, value } = patchSchema.validate(req.body);
    if (error) {
      return scimError(res, 400, 'invalidValue', error.details[0].message);
    }

    const updatedUser = await UserStorage.patchUser(req.params.id, value.Operations);
    if (!updatedUser) {
      return scimError(res, 404, 'resourceNotFound', 'User not found');
    }

    res.json(updatedUser);
  } catch (error) {
    console.error('Error patching user:', error);
    scimError(res, 500, 'internalError', 'Internal server error');
  }
});

// DELETE /Users/:id - Delete user
router.delete('/Users/:id', async (req, res) => {
  try {
    const deleted = await UserStorage.deleteUser(req.params.id);
    if (!deleted) {
      return scimError(res, 404, 'resourceNotFound', 'User not found');
    }
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting user:', error);
    scimError(res, 500, 'internalError', 'Internal server error');
  }
});

// GET /Groups - List groups
router.get('/Groups', async (req, res) => {
  try {
    const { error, value } = querySchema.validate(req.query);
    if (error) {
      return scimError(res, 400, 'invalidFilter', error.details[0].message);
    }

    const { startIndex, count } = value;
    let groups = await GroupStorage.getAllGroups();

    // Apply pagination
    const totalResults = groups.length;
    const start = startIndex - 1;
    const paginatedGroups = groups.slice(start, start + count);

    res.json(scimListResponse(paginatedGroups, startIndex, count, totalResults));
  } catch (error) {
    console.error('Error listing groups:', error);
    scimError(res, 500, 'internalError', 'Internal server error');
  }
});

// GET /Groups/:id - Get specific group
router.get('/Groups/:id', async (req, res) => {
  try {
    const group = await GroupStorage.getGroupById(req.params.id);
    if (!group) {
      return scimError(res, 404, 'resourceNotFound', 'Group not found');
    }
    res.json(group);
  } catch (error) {
    console.error('Error getting group:', error);
    scimError(res, 500, 'internalError', 'Internal server error');
  }
});

// POST /Groups - Create new group
router.post('/Groups', async (req, res) => {
  try {
    const { error, value } = groupSchema.validate(req.body);
    if (error) {
      return scimError(res, 400, 'invalidValue', error.details[0].message);
    }

    const newGroup = await GroupStorage.createGroup(value);
    res.status(201).json(newGroup);
  } catch (error) {
    console.error('Error creating group:', error);
    scimError(res, 500, 'internalError', 'Internal server error');
  }
});

// PUT /Groups/:id - Update group
router.put('/Groups/:id', async (req, res) => {
  try {
    const { error, value } = groupSchema.validate(req.body);
    if (error) {
      return scimError(res, 400, 'invalidValue', error.details[0].message);
    }

    const updatedGroup = await GroupStorage.updateGroup(req.params.id, value);
    if (!updatedGroup) {
      return scimError(res, 404, 'resourceNotFound', 'Group not found');
    }

    res.json(updatedGroup);
  } catch (error) {
    console.error('Error updating group:', error);
    scimError(res, 500, 'internalError', 'Internal server error');
  }
});

// DELETE /Groups/:id - Delete group
router.delete('/Groups/:id', async (req, res) => {
  try {
    const deleted = await GroupStorage.deleteGroup(req.params.id);
    if (!deleted) {
      return scimError(res, 404, 'resourceNotFound', 'Group not found');
    }
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting group:', error);
    scimError(res, 500, 'internalError', 'Internal server error');
  }
});

// GET /ServiceProviderConfig - SCIM service provider configuration
router.get('/ServiceProviderConfig', (req, res) => {
  res.json({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    documentationUri: 'https://tools.ietf.org/html/rfc7644',
    patch: {
      supported: true
    },
    bulk: {
      supported: false,
      maxOperations: 0,
      maxPayloadSize: 0
    },
    filter: {
      supported: true,
      maxResults: 200
    },
    changePassword: {
      supported: false
    },
    sort: {
      supported: true
    },
    etag: {
      supported: false
    },
    authenticationSchemes: [
      {
        name: 'OAuth Bearer Token',
        description: 'Authentication scheme using the OAuth Bearer Token Standard',
        specUri: 'http://www.rfc-editor.org/info/rfc6750',
        documentationUri: 'http://example.com/help/oauth.html',
        type: 'oauthbearertoken',
        primary: true
      }
    ],
    meta: {
      location: '/scim/v2/ServiceProviderConfig',
      resourceType: 'ServiceProviderConfig',
      created: new Date().toISOString(),
      lastModified: new Date().toISOString()
    }
  });
});

// GET /ResourceTypes - SCIM resource types
router.get('/ResourceTypes', (req, res) => {
  res.json([
    {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
      id: 'User',
      name: 'User',
      endpoint: '/Users',
      description: 'User Account',
      schema: 'urn:ietf:params:scim:schemas:core:2.0:User',
      meta: {
        location: '/scim/v2/ResourceTypes/User',
        resourceType: 'ResourceType'
      }
    },
    {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
      id: 'Group',
      name: 'Group',
      endpoint: '/Groups',
      description: 'Group',
      schema: 'urn:ietf:params:scim:schemas:core:2.0:Group',
      meta: {
        location: '/scim/v2/ResourceTypes/Group',
        resourceType: 'ResourceType'
      }
    }
  ]);
});

// GET /Schemas - SCIM schemas
router.get('/Schemas', (req, res) => {
  res.json([
    {
      id: 'urn:ietf:params:scim:schemas:core:2.0:User',
      name: 'User',
      description: 'User Account',
      attributes: [
        {
          name: 'userName',
          type: 'string',
          multiValued: false,
          description: 'Unique identifier for the User',
          required: true,
          caseExact: false,
          mutability: 'readWrite',
          returned: 'default',
          uniqueness: 'server'
        }
      ]
    },
    {
      id: 'urn:ietf:params:scim:schemas:core:2.0:Group',
      name: 'Group',
      description: 'Group',
      attributes: [
        {
          name: 'displayName',
          type: 'string',
          multiValued: false,
          description: 'A human-readable name for the Group',
          required: false,
          caseExact: false,
          mutability: 'readWrite',
          returned: 'default',
          uniqueness: 'none'
        }
      ]
    }
  ]);
});

module.exports = router;
