const r=require('express').Router(),c=require('../controllers/auditController'),v=require('../validators/audit'),validate=require('../middleware/validate'),{authenticate,adminOnly,requirePermission}=require('../middleware/auth');
r.get('/',authenticate,adminOnly,requirePermission('logs:read'),validate(v.list),c.list);module.exports=r;
