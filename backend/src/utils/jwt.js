const jwt=require('jsonwebtoken'),crypto=require('crypto'),env=require('../config/env');
const FIXED={issuer:'phishguard',audience:'phishguard-web'};
// The role is NOT put in the token: authorization always uses the role stored in the database.
exports.sign=u=>jwt.sign({tv:u.token_version},env.jwtSecret,{algorithm:'HS256',expiresIn:env.jwtExpiresIn,subject:String(u.id),jwtid:crypto.randomUUID(),...FIXED});
exports.verify=t=>jwt.verify(t,env.jwtSecret,{algorithms:['HS256'],...FIXED});
