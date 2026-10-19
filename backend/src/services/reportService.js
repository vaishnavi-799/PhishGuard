const Report=require('../models/report'),scans=require('./scanService'),analysis=require('./analysisService'),ApiError=require('../utils/ApiError'),{parse}=require('../utils/ids');
exports.list=user=>Report.listByUser(user.dbId);
exports.create=async(user,scanId)=>{const row=await scans.getAccessible(user,scanId),data=await analysis.report(row),bytes=Buffer.byteLength(JSON.stringify(data));return Report.create({scanId:row.id,userId:user.dbId,format:'json',sizeKb:Math.max(1,Math.ceil(bytes/1024)),reportData:data})};
exports.get=async(user,pubId)=>{const id=parse('R',pubId),r=id&&await Report.findForUser(id,user.dbId);if(!r)throw new ApiError(404,'Report not found','NOT_FOUND');return r};
exports.download=async(user,pubId,format='json')=>{
 if(!['json','csv'].includes(format))throw new ApiError(400,'Report format must be json or csv','INVALID_FORMAT');
 const id=parse('R',pubId),record=id&&await Report.findForUser(id,user.dbId);if(!record)throw new ApiError(404,'Report not found','NOT_FOUND');
 let data=record.data;
 if(!data){const row=await scans.getAccessible(user,record.scanId);data=await analysis.report(row);await Report.updateData(id,user.dbId,data,Math.max(1,Math.ceil(Buffer.byteLength(JSON.stringify(data))/1024)))}
 if(format==='json')return{filename:`phishguard-${record.id}.json`,contentType:'application/json; charset=utf-8',body:JSON.stringify(data,null,2)};
 const rows=[];
 for(const section of ['scan','why','actions','url','domain','ssl','web','brand','intel','ml','shap']){
  const value=data[section];if(value==null)continue;
  if(Array.isArray(value))value.forEach((item,index)=>rows.push([section,index+1,JSON.stringify(item)]));
  else rows.push([section,'',JSON.stringify(value)]);
 }
 const csv=[['section','item','evidence'],...rows].map(row=>row.map(v=>`"${String(v??'').replace(/"/g,'""')}"`).join(',')).join('\r\n');
 return{filename:`phishguard-${record.id}.csv`,contentType:'text/csv; charset=utf-8',body:csv};
};
