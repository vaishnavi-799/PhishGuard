// 'URL' | 'Domain' | 'IP' | 'Hash' | null
exports.iocType=q=>{
 if(!q||/\s/.test(q)||q.length>2048)return null;
 if(/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(q))return 'Hash';
 if(/^\d{1,3}(\.\d{1,3}){3}$/.test(q))return q.split('.').every(n=>+n<=255)?'IP':null;
 if(/^https?:\/\/[^/]+\.[a-z]{2,}/i.test(q)||/^([a-z0-9-]+\.)+[a-z]{2,}\/\S*$/i.test(q))return 'URL';
 if(/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(q))return 'Domain';
 return null};
