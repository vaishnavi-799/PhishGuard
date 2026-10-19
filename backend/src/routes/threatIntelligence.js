const r=require('express').Router(),c=require('../controllers/threatController'),v=require('../validators/threat'),validate=require('../middleware/validate'),{authenticate}=require('../middleware/auth'),{scanLimiter}=require('../middleware/rateLimit');
r.use(authenticate);r.get('/overview',c.overview);r.get('/lookup',scanLimiter,validate(v.lookup),c.lookup);module.exports=r;
