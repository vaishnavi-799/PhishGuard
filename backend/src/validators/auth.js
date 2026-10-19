const {z,email,password}=require('./common');
exports.register={body:z.object({name:z.string().trim().min(2).max(80),email,password}).strict()};
exports.login={body:z.object({email,password:z.string().min(1).max(128)}).strict()};
