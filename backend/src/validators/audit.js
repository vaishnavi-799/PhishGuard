const {z}=require('./common');
exports.list={query:z.object({limit:z.coerce.number().int().min(1).max(500).default(200),offset:z.coerce.number().int().min(0).default(0),action:z.string().max(40).optional(),result:z.enum(['Success','Failure','Blocked']).optional(),q:z.string().max(100).optional()})};
