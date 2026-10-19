const {z}=require('zod');
exports.z=z;
exports.pubId=p=>z.string().regex(new RegExp(`^${p}-\\d{1,9}$`),'Invalid id');
exports.idParam=p=>({params:z.object({id:exports.pubId(p)})});
exports.email=z.string().trim().toLowerCase().email().max(254);
exports.password=z.string().min(8,'Password must be at least 8 characters').regex(/[A-Za-z]/,'Password must contain a letter').regex(/\d/,'Password must contain a number').refine(v=>Buffer.byteLength(v,'utf8')<=72,'Password must be at most 72 bytes (bcrypt limit)'); // refine() last: it returns a type without .regex()
