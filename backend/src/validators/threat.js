const {z}=require('./common');
exports.lookup={query:z.object({q:z.string().trim().min(1).max(2048)})};
exports.add={body:z.object({indicator:z.string().trim().min(3).max(2048),category:z.string().trim().min(2).max(40),severity:z.enum(['High','Medium','Low'])})};
exports.update={body:z.object({status:z.enum(['Active','Pending','Disabled']).optional(),severity:z.enum(['High','Medium','Low']).optional()}).refine(o=>Object.keys(o).length>0,'Nothing to update')};
exports.feedUpdate={params:z.object({id:z.coerce.number().int().positive()}),body:z.object({enabled:z.boolean()})};
exports.feedParam={params:z.object({id:z.coerce.number().int().positive()})};
