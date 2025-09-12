const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const USERS_FILE = path.join(__dirname, '../data/users.json');
const GROUPS_FILE = path.join(__dirname, '../data/groups.json');

// Ensure data directory exists
async function ensureDataDirectory() {
  const dataDir = path.dirname(USERS_FILE);
  try {
    await fs.access(dataDir);
  } catch (error) {
    await fs.mkdir(dataDir, { recursive: true });
  }
}

// Initialize files if they don't exist
async function initializeFiles() {
  await ensureDataDirectory();
  
  try {
    await fs.access(USERS_FILE);
  } catch (error) {
    await fs.writeFile(USERS_FILE, JSON.stringify({ users: [] }, null, 2));
  }
  
  try {
    await fs.access(GROUPS_FILE);
  } catch (error) {
    await fs.writeFile(GROUPS_FILE, JSON.stringify({ groups: [] }, null, 2));
  }
}

// User operations
class UserStorage {
  static async getAllUsers() {
    await initializeFiles();
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data).users;
  }

  static async getUserById(id) {
    const users = await this.getAllUsers();
    return users.find(user => user.id === id);
  }

  static async getUserByUserName(userName) {
    const users = await this.getAllUsers();
    return users.find(user => user.userName === userName);
  }

  static async createUser(userData) {
    const users = await this.getAllUsers();
    
    // Check if user already exists
    const existingUser = users.find(u => u.userName === userData.userName);
    if (existingUser) {
      throw new Error('User already exists');
    }

    const newUser = {
      id: uuidv4(),
      userName: userData.userName,
      name: userData.name || {},
      displayName: userData.displayName || userData.userName,
      emails: userData.emails || [],
      active: userData.active !== undefined ? userData.active : true,
      meta: {
        resourceType: 'User',
        created: new Date().toISOString(),
        lastModified: new Date().toISOString(),
        location: `/scim/v2/Users/${userData.id || uuidv4()}`
      },
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User']
    };

    users.push(newUser);
    await fs.writeFile(USERS_FILE, JSON.stringify({ users }, null, 2));
    return newUser;
  }

  static async updateUser(id, userData) {
    const users = await this.getAllUsers();
    const userIndex = users.findIndex(user => user.id === id);
    
    if (userIndex === -1) {
      return null;
    }

    const updatedUser = {
      ...users[userIndex],
      ...userData,
      id: id, // Ensure ID doesn't change
      meta: {
        ...users[userIndex].meta,
        lastModified: new Date().toISOString()
      }
    };

    users[userIndex] = updatedUser;
    await fs.writeFile(USERS_FILE, JSON.stringify({ users }, null, 2));
    return updatedUser;
  }

  static async deleteUser(id) {
    const users = await this.getAllUsers();
    const userIndex = users.findIndex(user => user.id === id);
    
    if (userIndex === -1) {
      return false;
    }

    users.splice(userIndex, 1);
    await fs.writeFile(USERS_FILE, JSON.stringify({ users }, null, 2));
    return true;
  }

  static async patchUser(id, operations) {
    const user = await this.getUserById(id);
    if (!user) {
      return null;
    }

    let updatedUser = { ...user };

    for (const operation of operations) {
      const { op, path, value } = operation;

      switch (op.toLowerCase()) {
        case 'replace':
          if (path === 'active') {
            updatedUser.active = value;
          } else if (path === 'displayName') {
            updatedUser.displayName = value;
          } else if (path.startsWith('name.')) {
            const nameField = path.split('.')[1];
            updatedUser.name = updatedUser.name || {};
            updatedUser.name[nameField] = value;
          }
          break;
        case 'add':
          if (path === 'emails') {
            updatedUser.emails = updatedUser.emails || [];
            updatedUser.emails.push(value);
          }
          break;
        case 'remove':
          if (path === 'emails') {
            updatedUser.emails = [];
          }
          break;
      }
    }

    updatedUser.meta.lastModified = new Date().toISOString();
    return await this.updateUser(id, updatedUser);
  }
}

// Group operations
class GroupStorage {
  static async getAllGroups() {
    await initializeFiles();
    const data = await fs.readFile(GROUPS_FILE, 'utf8');
    return JSON.parse(data).groups;
  }

  static async getGroupById(id) {
    const groups = await this.getAllGroups();
    return groups.find(group => group.id === id);
  }

  static async createGroup(groupData) {
    const groups = await this.getAllGroups();
    
    const newGroup = {
      id: uuidv4(),
      displayName: groupData.displayName,
      members: groupData.members || [],
      meta: {
        resourceType: 'Group',
        created: new Date().toISOString(),
        lastModified: new Date().toISOString(),
        location: `/scim/v2/Groups/${groupData.id || uuidv4()}`
      },
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group']
    };

    groups.push(newGroup);
    await fs.writeFile(GROUPS_FILE, JSON.stringify({ groups }, null, 2));
    return newGroup;
  }

  static async updateGroup(id, groupData) {
    const groups = await this.getAllGroups();
    const groupIndex = groups.findIndex(group => group.id === id);
    
    if (groupIndex === -1) {
      return null;
    }

    const updatedGroup = {
      ...groups[groupIndex],
      ...groupData,
      id: id,
      meta: {
        ...groups[groupIndex].meta,
        lastModified: new Date().toISOString()
      }
    };

    groups[groupIndex] = updatedGroup;
    await fs.writeFile(GROUPS_FILE, JSON.stringify({ groups }, null, 2));
    return updatedGroup;
  }

  static async deleteGroup(id) {
    const groups = await this.getAllGroups();
    const groupIndex = groups.findIndex(group => group.id === id);
    
    if (groupIndex === -1) {
      return false;
    }

    groups.splice(groupIndex, 1);
    await fs.writeFile(GROUPS_FILE, JSON.stringify({ groups }, null, 2));
    return true;
  }
}

module.exports = { UserStorage, GroupStorage };
