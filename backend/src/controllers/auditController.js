const Audit=require('../models/audit'),h=require('../utils/asyncHandler'),{ok}=require('../utils/response'),audit=require('../services/auditService');
exports.list=h(async(req,res)=>ok(res,await Audit.list(req.query)));
