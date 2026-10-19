const r=require('express').Router();
r.get('/health',(req,res)=>res.json({success:true,data:{status:'ok',time:new Date().toISOString()}}));
r.use('/auth',require('./auth'));r.use('/users',require('./users'));r.use('/scans',require('./scans'));r.use('/analysis',require('./analysis'));
r.use('/threat-intelligence',require('./threatIntelligence'));r.use('/attachments',require('./attachments'));r.use('/reports',require('./reports'));
r.use('/admin',require('./admin'));r.use('/audit',require('./audit'));module.exports=r;
