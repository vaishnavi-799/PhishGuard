const r=require('express').Router(),c=require('../controllers/adminController'),v=require('../validators/admin'),t=require('../validators/threat'),{idParam}=require('../validators/common'),validate=require('../middleware/validate'),{authenticate,adminOnly,requirePermission:P}=require('../middleware/auth');
r.use(authenticate,adminOnly); // every /api/admin route is admin-tier only; fine-grained permissions below
r.get('/overview',c.overview);
r.get('/users',P('users:read'),c.users);r.post('/users',P('users:write'),validate(v.invite),c.invite);
r.patch('/users/:id',P('users:write'),validate(v.updateUser),c.updateUser);r.delete('/users/:id',P('users:delete'),validate(idParam('U')),c.deleteUser);
r.get('/scans',P('scans:read'),c.scans);r.patch('/scans/:id/review',P('scans:manage'),validate(idParam('S')),c.reviewScan);r.delete('/scans/:id',P('scans:delete'),validate(idParam('S')),c.deleteScan);
r.get('/threats',P('threats:read'),c.threats);r.post('/threats',P('threats:write'),validate(t.add),c.addIndicator);
r.patch('/threats/:id',P('threats:write'),validate({...idParam('T'),...t.update}),c.updateIndicator);r.delete('/threats/:id',P('threats:write'),validate(idParam('T')),c.removeIndicator);
r.patch('/threat-feeds/:id',P('threats:write'),validate(t.feedUpdate),c.updateFeed);r.post('/threat-feeds/:id/sync',P('threats:write'),validate(t.feedParam),c.syncFeed);
module.exports=r;
