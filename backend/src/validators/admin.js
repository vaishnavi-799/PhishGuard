const {z,pubId,email}=require('./common'),{ROLES}=require('../config/rbac');
exports.updateUser={params:z.object({id:pubId('U')}),body:z.object({role:z.enum(ROLES).optional(),status:z.enum(['Active','Pending','Suspended','Inactive']).optional()}).refine(o=>Object.keys(o).length>0,'Nothing to update')};
exports.invite={body:z.object({email,role:z.enum(ROLES).default('user')})};
