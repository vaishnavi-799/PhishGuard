const scans=require('../services/scanService'),analysis=require('../services/analysisService'),h=require('../utils/asyncHandler'),{ok}=require('../utils/response'),audit=require('../services/auditService');
exports.detail=h(async(req,res)=>ok(res,analysis.detail(await scans.getAccessible(req.user,req.params.id))));
exports.report=h(async(req,res)=>ok(res,await analysis.report(await scans.getAccessible(req.user,req.params.id))));
