const svc=require('../services/threatService'),h=require('../utils/asyncHandler'),{ok}=require('../utils/response'),audit=require('../services/auditService');
exports.overview=h(async(req,res)=>ok(res,await svc.overview()));
exports.lookup=h(async(req,res)=>ok(res,await svc.lookup(req.query.q)));
