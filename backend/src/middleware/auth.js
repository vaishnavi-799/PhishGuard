const jwt=require('../utils/jwt'),User=require('../models/user'),Token=require('../models/token'),ApiError=require('../utils/ApiError'),{authorize,adminOnly,requirePermission}=require('./authorize');
const BEARER=/^Bearer ([A-Za-z0-9._-]+)$/;
// Validates the JWT (signature, algorithm, issuer, audience, expiry), then re-checks the account in the database on every request:
// user exists, token not revoked, token_version unchanged (password change / logout-all), account not suspended.
const authenticate=async(req,res,next)=>{try{
 const m=BEARER.exec(req.headers.authorization||'');if(!m)throw new ApiError(401,'Authentication required','UNAUTHENTICATED');
 const p=jwt.verify(m[1]),id=Number(p.sub);if(!Number.isInteger(id))throw new ApiError(401,'Invalid token','UNAUTHENTICATED');
 const[u,revoked]=await Promise.all([User.findById(id),Token.isRevoked(p.jti)]);
 if(revoked||!u||u.token_version!==p.tv)throw new ApiError(401,'Session is no longer valid, please sign in again','UNAUTHENTICATED');
 if(u.status==='Suspended')throw new ApiError(403,'Account suspended','ACCOUNT_SUSPENDED');
 req.user={...User.toPublic(u),dbId:u.id};req.token={jti:p.jti,exp:p.exp};User.touch(u.id).catch(()=>{});next()}catch(e){next(e)}};
module.exports={authenticate,authorize,adminOnly,requirePermission};
