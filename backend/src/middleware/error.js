const {ZodError}=require('zod'),ApiError=require('../utils/ApiError'),logger=require('../utils/logger'),env=require('../config/env');
exports.notFound=(req,res,next)=>next(new ApiError(404,`Route not found: ${req.method} ${req.originalUrl}`,'NOT_FOUND'));
exports.errorHandler=(err,req,res,next)=>{ // eslint-disable-line no-unused-vars
 let status=err.status||500,code=err.code||'INTERNAL_ERROR',message=err.message,details=err.details;
 if(err instanceof ZodError){status=400;code='VALIDATION_ERROR';message='Validation failed';details=err.issues.map(i=>({field:i.path.join('.'),message:i.message}))}
 else if(err.code==='23505'){status=409;code='CONFLICT';message='Resource already exists'}
 else if(err.name==='JsonWebTokenError'||err.name==='TokenExpiredError'){status=401;code='UNAUTHENTICATED';message=err.name==='TokenExpiredError'?'Session expired, please sign in again':'Invalid token'}
 else if(err.code==='LIMIT_FILE_SIZE'){status=413;code='FILE_TOO_LARGE';message=`File exceeds the ${env.maxUploadMb} MB limit`}
 else if(err.type==='entity.parse.failed'){status=400;code='BAD_JSON';message='Malformed JSON body'}
 if(status>=500){logger.error(err.message,{stack:err.stack,path:req.originalUrl});message=env.isProd?'Internal server error':message}
 if(status===403&&code==='FORBIDDEN'&&req.user)require('../services/auditService').log({req,user:req.user,action:'ACCESS_DENIED',result:'Blocked',detail:`${req.method} ${req.originalUrl.split('?')[0]}`}); // fire-and-forget
 res.status(status).json({success:false,error:{code,message,...(details?{details}:{})}})};
