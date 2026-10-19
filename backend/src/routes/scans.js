const r=require('express').Router(),c=require('../controllers/scansController'),v=require('../validators/scans'),{idParam}=require('../validators/common'),validate=require('../middleware/validate'),{authenticate}=require('../middleware/auth'),{scanLimiter}=require('../middleware/rateLimit');
const id=validate(idParam('S'));
r.use(authenticate);r.get('/',c.list);r.get('/overview',c.overview);r.post('/',scanLimiter,validate(v.create),c.create);
r.get('/:id/status',id,c.status);r.post('/:id/cancel',id,c.cancel);r.get('/:id',id,c.get);r.delete('/:id',id,c.remove);module.exports=r;
