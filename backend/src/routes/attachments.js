const r=require('express').Router(),c=require('../controllers/attachmentController'),upload=require('../middleware/upload'),{authenticate}=require('../middleware/auth'),{scanLimiter}=require('../middleware/rateLimit');
r.use(authenticate);r.post('/',scanLimiter,upload.single('file'),c.analyze);module.exports=r;
