const {z,pubId}=require('./common');
exports.create={body:z.object({scanId:pubId('S')})};
exports.download={params:z.object({id:pubId('R')}),query:z.object({format:z.enum(['json','csv']).default('json')})};
