const db=require('../config/db'),bcrypt=require('bcryptjs'),crypto=require('crypto'),User=require('../models/user'),Scan=require('../models/scan'),Audit=require('../models/audit'),Threat=require('../models/threat'),scansSvc=require('./scanService'),
ApiError=require('../utils/ApiError'),env=require('../config/env'),{can}=require('../config/rbac'),{parse}=require('../utils/ids'),{toApiScan,fmt}=require('../utils/format');
const COLORS={'Credential Phishing':'#ef4444','Brand Impersonation':'#f97316','Malware Delivery':'#8b5cf6','Payment Fraud':'#f59e0b'};
exports.overview=async()=>{const t0=Date.now();const [u,sc,over,cats,dau,feeds,probs]=await Promise.all([db.query("select count(*) total,count(*) filter(where status='Active') active from users"),Scan.counts(null),scansSvc.overview({dbId:null},null),Scan.categories(),Audit.activeUsersByDay(),Threat.feeds(),Audit.recentProblems(4)]);
 const dbMs=Date.now()-t0,users=u.rows[0],degraded=feeds.some(f=>f.status!=='Operational');
 return{stats:{users:users.total,active:users.active,scans:sc.total,phishing:sc.phishing,critical:over.riskDist[4].value},volume7:over.activity7,volume30:over.activity30,
 threatDist:cats.map(c=>({name:c.name,value:c.value,color:COLORS[c.name]||'#0ea5e9'})),userActivity:dau.map(d=>({name:d.name,count:d.count})),riskDist:over.riskDist.map(r=>({name:r.name,count:r.value,color:r.color})),
 services:[{name:'API Gateway',status:'Operational',note:'Healthy'},{name:'ML Inference Service',status:'Operational',note:'Mock analysis mode'},{name:'PostgreSQL',status:'Operational',note:`${dbMs} ms`},{name:'Threat Feeds',status:degraded?'Degraded':'Operational',note:degraded?'A feed is degraded':'All feeds syncing'}],
 alerts:probs.map(p=>({time:fmt(p.created_at),title:p.action,detail:p.detail||`${p.result} from ${p.ip||'unknown IP'}`,tone:p.result==='Blocked'?'warning':'danger'}))}};
exports.users=()=>User.listAdmin();
exports.scans=async()=>(await Scan.listAll()).map(toApiScan);
const target=async(actor,pubId)=>{const id=parse('U',pubId),u=id&&await User.findById(id);if(!u)throw new ApiError(404,'User not found','NOT_FOUND');
 if(u.id===actor.dbId)throw new ApiError(400,'You cannot modify your own account here','SELF_ACTION');
 if(u.role==='super_admin'&&actor.role!=='super_admin')throw new ApiError(403,'Only a Super Admin can modify a Super Admin','FORBIDDEN');return u};
exports.updateUser=async(actor,pubId,patch)=>{const u=await target(actor,pubId);
 if(patch.role&&patch.role!==u.role&&!can(actor.role,'users:role'))throw new ApiError(403,'Only a Super Admin can change roles','FORBIDDEN');
 return User.toAdmin({...(await User.adminUpdate(u.id,patch)),scans:0})};
exports.deleteUser=async(actor,pubId)=>{const u=await target(actor,pubId);await User.remove(u.id);return u};
exports.inviteUser=async(actor,{email,role})=>{if(role!=='user'&&role!=='analyst'&&!can(actor.role,'users:role'))throw new ApiError(403,'Only a Super Admin can invite privileged roles','FORBIDDEN');
 if(await User.findByEmail(email))throw new ApiError(409,'A user with this email already exists','EMAIL_TAKEN');
 // Random unusable password: the invitee must use a password-reset/invite flow (email delivery not implemented yet).
 const u=await User.create({name:email.split('@')[0],email,passwordHash:await bcrypt.hash(crypto.randomBytes(24).toString('hex'),env.bcryptRounds),role,status:'Pending'});return User.toAdmin(u)};
exports.reviewScan=async(actor,pubId)=>{const id=parse('S',pubId);if(!id||!(await Scan.findSummary(id)))throw new ApiError(404,'Scan not found','NOT_FOUND');await Scan.setReviewed(id,actor.dbId)};
exports.deleteScan=async pubId=>{const id=parse('S',pubId);if(!id||!(await Scan.findSummary(id)))throw new ApiError(404,'Scan not found','NOT_FOUND');await Scan.remove(id)};
exports.threats=async()=>({entries:await Threat.list(),feeds:await Threat.feeds()});
