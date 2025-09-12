const Joi = require('joi');

// SCIM User schema validation
const userSchema = Joi.object({
  userName: Joi.string().required(),
  name: Joi.object({
    formatted: Joi.string(),
    familyName: Joi.string(),
    givenName: Joi.string(),
    middleName: Joi.string(),
    honorificPrefix: Joi.string(),
    honorificSuffix: Joi.string()
  }),
  displayName: Joi.string(),
  nickName: Joi.string(),
  profileUrl: Joi.string().uri(),
  title: Joi.string(),
  userType: Joi.string(),
  preferredLanguage: Joi.string(),
  locale: Joi.string(),
  timezone: Joi.string(),
  active: Joi.boolean(),
  password: Joi.string(),
  emails: Joi.array().items(
    Joi.object({
      value: Joi.string().email().required(),
      display: Joi.string(),
      type: Joi.string().valid('work', 'home', 'other'),
      primary: Joi.boolean()
    })
  ),
  phoneNumbers: Joi.array().items(
    Joi.object({
      value: Joi.string().required(),
      display: Joi.string(),
      type: Joi.string().valid('work', 'home', 'mobile', 'fax', 'pager', 'other'),
      primary: Joi.boolean()
    })
  ),
  addresses: Joi.array().items(
    Joi.object({
      formatted: Joi.string(),
      streetAddress: Joi.string(),
      locality: Joi.string(),
      region: Joi.string(),
      postalCode: Joi.string(),
      country: Joi.string(),
      type: Joi.string().valid('work', 'home', 'other'),
      primary: Joi.boolean()
    })
  ),
  groups: Joi.array().items(
    Joi.object({
      value: Joi.string().required(),
      $ref: Joi.string(),
      display: Joi.string(),
      type: Joi.string().valid('direct', 'indirect')
    })
  ),
  entitlements: Joi.array().items(
    Joi.object({
      value: Joi.string().required(),
      display: Joi.string(),
      type: Joi.string(),
      primary: Joi.boolean()
    })
  ),
  roles: Joi.array().items(
    Joi.object({
      value: Joi.string().required(),
      display: Joi.string(),
      type: Joi.string(),
      primary: Joi.boolean()
    })
  ),
  x509Certificates: Joi.array().items(
    Joi.object({
      value: Joi.string().required(),
      display: Joi.string(),
      type: Joi.string(),
      primary: Joi.boolean()
    })
  )
});

// SCIM Group schema validation
const groupSchema = Joi.object({
  displayName: Joi.string().required(),
  members: Joi.array().items(
    Joi.object({
      value: Joi.string().required(),
      $ref: Joi.string(),
      display: Joi.string(),
      type: Joi.string().valid('User', 'Group')
    })
  )
});

// SCIM Patch operation schema
const patchSchema = Joi.object({
  schemas: Joi.array().items(Joi.string().valid('urn:ietf:params:scim:api:messages:2.0:PatchOp')).required(),
  Operations: Joi.array().items(
    Joi.object({
      op: Joi.string().valid('add', 'remove', 'replace').required(),
      path: Joi.string(),
      value: Joi.alternatives().try(
        Joi.string(),
        Joi.number(),
        Joi.boolean(),
        Joi.object(),
        Joi.array()
      )
    })
  ).required()
});

// Query parameters validation
const querySchema = Joi.object({
  filter: Joi.string(),
  sortBy: Joi.string(),
  sortOrder: Joi.string().valid('ascending', 'descending'),
  startIndex: Joi.number().integer().min(1).default(1),
  count: Joi.number().integer().min(0).default(20)
});

module.exports = {
  userSchema,
  groupSchema,
  patchSchema,
  querySchema
};
