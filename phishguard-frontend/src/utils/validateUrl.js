// Returns {ok, error} or {ok:true, normalized}. Pure function: safe to reuse before any API call.
export function validateUrl(raw){
  const v=(raw||'').trim(), bad=error=>({ok:false,error});
  if(!v) return bad('Please enter a URL to scan.');
  if(v.length>2048) return bad('URL is too long (max 2048 characters).');
  if(/\s/.test(v)) return bad('URL must not contain spaces.');
  if(/^(javascript|data|file|ftp|mailto|vbscript|blob):/i.test(v)||/^[a-z][a-z0-9+.-]*:\/\//i.test(v)&&!/^https?:\/\//i.test(v)) return bad('Only http:// and https:// URLs are supported.');
  let u; try{u=new URL(/^https?:\/\//i.test(v)?v:'https://'+v)}catch{return bad('This is not a valid URL. Example: https://example.com/login')}
  const h=u.hostname;
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(h)){
    const n=h.split('.').map(Number);
    if(n.some(x=>x>255)) return bad('Invalid IP address.');
    if(n[0]===10||n[0]===127||n[0]===0||(n[0]===192&&n[1]===168)||(n[0]===172&&n[1]>=16&&n[1]<=31)) return bad('Private or local addresses cannot be scanned.');
  } else if(!/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/i.test(h)) return bad('Enter a valid domain name, e.g. example.com');
  return {ok:true,normalized:u.toString()};
}
