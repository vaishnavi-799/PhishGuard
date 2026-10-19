const {z}=require('./common'),{validateUrl}=require('../utils/validateUrl');
exports.create={body:z.object({url:z.string().max(2048).transform((v,ctx)=>{const r=validateUrl(v);if(!r.ok){ctx.addIssue({code:'custom',message:r.error});return z.NEVER}return r.normalized})})};
