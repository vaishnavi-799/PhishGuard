const {z,password}=require('./common');
exports.updateMe={body:z.object({name:z.string().trim().min(2).max(80)})};
exports.changePassword={body:z.object({currentPassword:z.string().min(1).max(128),newPassword:password})};
