const svc=require('../services/authService'),Token=require('../models/token'),User=require('../models/user'),h=require('../utils/asyncHandler'),{ok}=require('../utils/response'),audit=require('../services/auditService');
exports.register=h(async(req,res)=>{const r=await svc.register(req.body);await audit.log({req,email:r.user.email,action:'REGISTER',detail:'Account created'});ok(res,r,201)});
exports.login=h(async(req,res)=>{try{const r=await svc.login(req.body);await audit.log({req,email:r.user.email,action:'LOGIN',detail:'Signed in with password'});ok(res,r)}
 catch(e){await audit.log({req,email:req.body.email,action:'LOGIN_FAILED',result:'Failure',detail:e.code||'error'});throw e}});
exports.me=h(async(req,res)=>{const{dbId,...user}=req.user;ok(res,{user})});
// Real logout: the token's jti is stored as revoked, so it stops working immediately on every device that holds it
exports.logout=h(async(req,res)=>{await Token.revoke({jti:req.token.jti,userId:req.user.dbId,exp:req.token.exp});await audit.log({req,user:req.user,action:'LOGOUT'});ok(res,{loggedOut:true})});
exports.logoutAll=h(async(req,res)=>{await User.revokeAllSessions(req.user.dbId);await audit.log({req,user:req.user,action:'LOGOUT_ALL',detail:'All sessions revoked'});ok(res,{loggedOut:true})});
