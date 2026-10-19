const Threat=require('../models/threat'),ApiError=require('../utils/ApiError'),{iocType}=require('../utils/ioc'),{parse}=require('../utils/ids');
const UNKNOWN='Unknown';
exports.overview=async()=>({
 // Only sources that are actually queried are advertised here. Feed rows currently
 // describe unconfigured integrations and must not look operational.
 providers:[{id:'internal-blocklist',name:'Internal blocklist',status:'Operational',updated:'Live',feed:'Admin-managed indicators'}],
 timeline:[]
});
exports.lookup=async q=>{
 const type=iocType(q);if(!type)throw new ApiError(400,'Enter a URL, domain, IPv4 address or MD5/SHA-1/SHA-256 hash','INVALID_INDICATOR');
 const query=String(q).trim(),hit=await Threat.findActive(query);
 const provider={name:'Internal blocklist',verdict:hit?'Malicious':UNKNOWN};
 return{query,type,reputation:hit?'Malicious':UNKNOWN,score:hit?100:null,malicious:hit?1:0,total:1,
  sources:hit?['Internal blocklist']:[],firstSeen:hit?(hit.created_at||hit.createdAt||null):null,lastSeen:hit?(hit.updated_at||hit.created_at||null):null,
  categories:hit?[hit.category]:[],providers:[provider],timeline:[],checkedAt:new Date().toISOString()};
};
exports.addIndicator=async(user,{indicator,category,severity})=>{const v=indicator.trim().toLowerCase(),type=iocType(v);if(!type)throw new ApiError(400,'Not a valid URL, domain, IP or hash','INVALID_INDICATOR');
 return Threat.add({indicator:v,type,category,severity,addedBy:user.dbId})};
exports.updateIndicator=async(pubId,patch)=>{const id=parse('T',pubId),r=id&&await Threat.update(id,patch);if(!r)throw new ApiError(404,'Indicator not found','NOT_FOUND');return r};
exports.removeIndicator=async pubId=>{const id=parse('T',pubId);if(!id||!(await Threat.remove(id)))throw new ApiError(404,'Indicator not found','NOT_FOUND')};
exports.updateFeed=async(id,patch)=>{const feeds=await Threat.feeds(),feed=feeds.find(x=>x.id===Number(id));if(!feed)throw new ApiError(404,'Feed not found','NOT_FOUND');if(patch.enabled)throw new ApiError(503,'This feed has no configured integration and cannot be enabled','SOURCE_UNAVAILABLE');return Threat.updateFeed(id,{enabled:false})};
exports.syncFeed=async id=>{const r=await Threat.feeds(),feed=r.find(x=>x.id===Number(id));if(!feed)throw new ApiError(404,'Feed not found','NOT_FOUND');throw new ApiError(503,'This feed has no configured integration and cannot be synchronized','SOURCE_UNAVAILABLE')};
