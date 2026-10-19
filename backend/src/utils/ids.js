// Public IDs match the frontend format (S-1042, U-1001, R-2005, L-5001, T-3)
const BASE={S:1000,U:1000,R:2000,L:5000,T:0};
exports.pub=(p,id)=>`${p}-${BASE[p]+Number(id)}`;
exports.parse=(p,s)=>{const m=new RegExp(`^${p}-(\\d+)$`).exec(String(s));const n=m?+m[1]-BASE[p]:0;return n>0?n:null};
