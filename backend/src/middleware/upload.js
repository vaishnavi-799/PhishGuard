const multer=require('multer'),env=require('../config/env');
// Memory storage: files are analysed statically from the buffer and never written to disk or executed.
module.exports=multer({storage:multer.memoryStorage(),limits:{fileSize:env.maxUploadMb*1048576,files:1}});
