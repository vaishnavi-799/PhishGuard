const r=require('express').Router(),c=require('../controllers/analysisController'),{idParam}=require('../validators/common'),validate=require('../middleware/validate'),{authenticate}=require('../middleware/auth');
r.use(authenticate);r.get('/:id',validate(idParam('S')),c.detail);r.get('/:id/report',validate(idParam('S')),c.report);module.exports=r;
