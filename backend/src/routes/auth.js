const r=require('express').Router(),c=require('../controllers/authController'),v=require('../validators/auth'),validate=require('../middleware/validate'),{authenticate}=require('../middleware/auth'),{loginLimiter,registerLimiter}=require('../middleware/rateLimit');
r.use((req,res,next)=>{res.set('Cache-Control','no-store');next()}); // never cache tokens or session data
r.post('/register',registerLimiter,validate(v.register),c.register);r.post('/login',loginLimiter,validate(v.login),c.login);
r.get('/me',authenticate,c.me);r.post('/logout',authenticate,c.logout);r.post('/logout-all',authenticate,c.logoutAll);module.exports=r;
