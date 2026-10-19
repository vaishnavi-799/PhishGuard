// Central RBAC definition. Later: load the user's role/permissions from GET /me and keep the same can() API.
export const ROLES={super_admin:'Super Admin',admin:'Admin',analyst:'Analyst',user:'User'};
const A=['super_admin','admin'],M=['super_admin','admin'];
export const PERMISSIONS={'admin:access':A,'users:read':M,'users:write':M,'users:role':['super_admin'],'users:delete':['super_admin'],'scans:read':A,'scans:manage':A,'scans:delete':M,'logs:read':M,'logs:export':M,'threats:read':A,'threats:write':A};
export const can=(role,perm)=>(PERMISSIONS[perm]||[]).includes(role);
