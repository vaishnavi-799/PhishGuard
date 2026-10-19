const rl=require('express-rate-limit'),env=require('../config/env');
const handler=(req,res)=>res.status(429).json({success:false,error:{code:'RATE_LIMITED',message:'Too many requests, please try again later'}});
exports.globalLimiter=rl({windowMs:env.rateLimit.windowMs,limit:env.rateLimit.max,standardHeaders:'draft-7',legacyHeaders:false,handler});
exports.authLimiter=rl({windowMs:env.rateLimit.windowMs,limit:env.rateLimit.authMax,standardHeaders:'draft-7',legacyHeaders:false,handler});
// Login: only FAILED attempts count toward the limit
exports.loginLimiter=rl({windowMs:env.rateLimit.windowMs,limit:env.rateLimit.authMax,skipSuccessfulRequests:true,standardHeaders:'draft-7',legacyHeaders:false,handler});
exports.registerLimiter=rl({windowMs:3600000,limit:env.rateLimit.registerMax,standardHeaders:'draft-7',legacyHeaders:false,handler});
exports.scanLimiter=rl({windowMs:60000,limit:30,standardHeaders:'draft-7',legacyHeaders:false,handler});
