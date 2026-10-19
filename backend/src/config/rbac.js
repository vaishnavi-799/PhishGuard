// Keep in sync with frontend/src/auth/rbac.js
// Two privilege levels: ADMIN_ROLES (admin, super_admin) and everyone else (user). 'analyst' has no admin privileges.
const ADMIN_ROLES=['super_admin','admin'];
const PERMISSIONS={'admin:access':ADMIN_ROLES,'users:read':ADMIN_ROLES,'users:write':ADMIN_ROLES,'users:role':['super_admin'],'users:delete':['super_admin'],'scans:read':ADMIN_ROLES,'scans:manage':ADMIN_ROLES,'scans:delete':ADMIN_ROLES,'logs:read':ADMIN_ROLES,'logs:export':ADMIN_ROLES,'threats:read':ADMIN_ROLES,'threats:write':ADMIN_ROLES};
module.exports={ROLES:['super_admin','admin','analyst','user'],ADMIN_ROLES,PERMISSIONS,can:(role,perm)=>(PERMISSIONS[perm]||[]).includes(role)};
