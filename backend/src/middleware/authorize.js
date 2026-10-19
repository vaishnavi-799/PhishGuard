// Pure authorization middleware (no I/O). Must run AFTER authenticate, which sets req.user.
const ApiError=require('../utils/ApiError'),{can,ADMIN_ROLES}=require('../config/rbac');
const guard=ok=>(req,res,next)=>!req.user?next(new ApiError(401,'Authentication required','UNAUTHENTICATED')):ok(req.user)?next():next(new ApiError(403,'You do not have permission to perform this action','FORBIDDEN'));
exports.authorize=(...roles)=>guard(u=>roles.includes(u.role));            // authorize('admin','super_admin')
exports.adminOnly=exports.authorize(...ADMIN_ROLES);                       // admin-tier roles only
exports.requirePermission=perm=>guard(u=>can(u.role,perm));                // fine-grained permission
