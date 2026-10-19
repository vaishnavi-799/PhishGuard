const bcrypt=require('bcryptjs'),User=require('../models/user'),jwt=require('../utils/jwt'),ApiError=require('../utils/ApiError'),env=require('../config/env');
const MAX_ATTEMPTS=5,LOCK_MINUTES=15;
const DUMMY=bcrypt.hashSync('timing-safe-dummy',env.bcryptRounds); // equalises response time for unknown emails
const session=u=>({token:jwt.sign(u),user:User.toPublic(u)});
const hash=pw=>bcrypt.hash(pw,env.bcryptRounds);
// Public registration can only ever create a standard 'user'. Admins are created by seed/admin tooling.
exports.register=async({name,email,password})=>{if(await User.findByEmail(email))throw new ApiError(409,'An account with this email already exists','EMAIL_TAKEN');
 return session(await User.create({name,email,passwordHash:await hash(password)}))};
exports.login=async({email,password})=>{const u=await User.findByEmail(email);
 if(u&&u.locked_until&&new Date(u.locked_until)>new Date())throw new ApiError(429,`Too many failed attempts. Try again in ${Math.max(1,Math.ceil((new Date(u.locked_until)-Date.now())/60000))} minute(s).`,'ACCOUNT_LOCKED');
 const ok=await bcrypt.compare(password,u?u.password_hash:DUMMY);
 if(!u||!ok){if(u)await User.recordFailedLogin(u.id,MAX_ATTEMPTS,LOCK_MINUTES);throw new ApiError(401,'Invalid email or password','INVALID_CREDENTIALS')} // same message for unknown email / wrong password
 if(u.status==='Suspended')throw new ApiError(403,'Account suspended','ACCOUNT_SUSPENDED');
 await User.markLogin(u.id);return session(u)};
exports.changePassword=async(userId,{currentPassword,newPassword})=>{const u=await User.findById(userId);
 if(!(await bcrypt.compare(currentPassword,u.password_hash)))throw new ApiError(400,'Current password is incorrect','INVALID_CREDENTIALS');
 return session(await User.updatePassword(userId,await hash(newPassword)))};
