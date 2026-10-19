const crypto=require('crypto'),{analyzeStatic,SUPPORTED_EXTENSIONS}=require('./fileHeuristics'),Attachment=require('../models/attachment'),ApiError=require('../utils/ApiError');
// Static analysis only: the buffer is hashed and inspected, never executed, and is not stored.
exports.analyze=async(user,file)=>{if(!file)throw new ApiError(400,'No file uploaded (field name: file)','NO_FILE');if(file.size===0)throw new ApiError(400,'File is empty','EMPTY_FILE');
 const name=String(file.originalname||'file').replace(/[\\/]/g,'_').slice(0,255),ext=(name.match(/\.([^\.\s]+)\s*$/)||[])[1]?.toLowerCase();
 if(!ext||!SUPPORTED_EXTENSIONS.has(ext))throw new ApiError(415,'Unsupported file type. Upload a supported document, image, archive, web file or static executable sample.','UNSUPPORTED_FILE_TYPE');
 const sha256=crypto.createHash('sha256').update(file.buffer).digest('hex');
 const result=analyzeStatic({name,size:file.size,type:file.mimetype==='application/octet-stream'?'':file.mimetype},sha256);
 await Attachment.insert({userId:user.dbId,filename:name,size:file.size,sha256,score:result.score,result});return result};
