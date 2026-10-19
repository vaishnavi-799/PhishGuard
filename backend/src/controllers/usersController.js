const User=require('../models/user'),auth=require('../services/authService'),h=require('../utils/asyncHandler'),{ok}=require('../utils/response'),audit=require('../services/auditService');
exports.me=h(async(req,res)=>{const{dbId,...user}=req.user;ok(res,{user})});
exports.updateMe=h(async(req,res)=>{const u=await User.updateProfile(req.user.dbId,req.body);await audit.log({req,user:req.user,action:'USER_UPDATE',detail:'Updated profile'});ok(res,{user:User.toPublic(u)})});
exports.changePassword=h(async(req,res)=>{const session=await auth.changePassword(req.user.dbId,req.body);await audit.log({req,user:req.user,action:'PASSWORD_CHANGE',detail:'All other sessions signed out'});ok(res,session)}); // returns a fresh token; old tokens are now invalid
