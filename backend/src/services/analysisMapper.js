// Maps the analysis engine's normalized JSON (schema 1.0) onto the normalized database tables. Pure, no I/O.
const cut=(s,n)=>s==null?null:String(s).slice(0,n);
const clamp=(n,lo,hi)=>Math.max(lo,Math.min(hi,n));
const pct=x=>x==null||Number.isNaN(+x)?0:+clamp(+x*100,0,100).toFixed(2);
const iso=s=>{if(!s)return null;const d=new Date(s);return Number.isNaN(d.getTime())?null:d};
const bool=v=>v==null?null:!!v;
const num=(v,d=0)=>Number.isFinite(+v)&&v!==null?+v:d;
const PRED={phishing:'Phishing',legitimate:'Legitimate'};

function mapScanResult(r){
 const ml=r.ml,risk=r.risk;
 if(ml&&ml.probability!=null){
  const[algo,...rest]=String(ml.model_version||'ml-unknown').split('-');
  return{prediction:PRED[ml.prediction]||(ml.probability>=0.5?'Phishing':'Legitimate'),probability:pct(ml.probability),confidence:pct(ml.confidence),model_name:cut(algo||'ml',40),model_version:cut(rest.join('-')||'unknown',20),
   top_features:JSON.stringify((ml.top_features||[]).slice(0,8).map(t=>({f:t.label||t.feature,val:t.value==null?'n/a':String(t.value),v:+num(t.contribution).toFixed(3)})))};
 }
 // No ML model available: the risk engine's own heuristic result is stored, and labelled as such (model_name = 'heuristic-risk')
 const s=risk.score;
 return{prediction:s>=50?'Phishing':'Legitimate',probability:clamp(s,0,100),confidence:clamp(Math.round(Math.abs(s-50)*2),0,100),model_name:'heuristic-risk',model_version:cut('engine-'+(r.engine_version||'1'),20),
  top_features:JSON.stringify((risk.factors||[]).slice(0,8).map(f=>({f:cut(f.id.replace(/_/g,' '),60),val:f.group,v:+(f.points/10).toFixed(2)})))};
}
function mapUrl(r){
 const u=r.url_analysis||{},enc=u.url_encoding||{},hex=u.hex_encoding||{},web=r.website_analysis||{};
 return{url_length:Math.max(1,num(u.length,(r.url&&r.url.input||'x').length)),subdomain_count:num(u.subdomain_count),special_char_count:num(u.special_char_count),is_ip_based:!!u.is_ip_host,
  has_encoding:num(enc.encoded_char_count)>0||num(hex.hex_sequences)>0||!!hex.hex_ip_host,uses_shortener:!!u.is_shortener,suspicious_keywords:(u.suspicious_keywords||[]).map(String).slice(0,20),
  redirect_count:Math.max(0,num((web.redirects||{}).count))};
}
function mapDomain(r){
 const d=r.domain_analysis||{},dns=d.dns,reg=d.registration||{},rep=(r.reputation||{}).rating;
 return{domain:cut((r.url||{}).registered_domain||(r.url||{}).host,255),domain_age_days:Number.isInteger(reg.age_days)&&reg.age_days>=0?reg.age_days:null,registrar:cut(reg.registrar,80),
  dns_resolves:dns?bool(dns.resolves):null,nameservers:((dns&&dns.nameservers)||reg.nameservers||[]).slice(0,10).map(String),reputation:['Good','Neutral','Poor','Unknown'].includes(rep)?rep:'Unknown',
  whois_privacy:!!reg.privacy_redacted,registered_at:iso(reg.registered_at)};
}
function mapTls(r){
 const t=r.tls_analysis||{},https=t.https!=null?!!t.https:((r.url||{}).scheme==='https');
 const issuer=t.issuer&&(t.issuer.organization||t.issuer.common_name);
 let issued=iso(t.issued_at),expires=iso(t.expires_at);if(issued&&expires&&expires<=issued)issued=expires=null; // never violate the DB check
 return{https_enabled:https,certificate_valid:bool(t.certificate_valid),issuer:cut(issuer,120),issued_at:issued,expires_at:expires,hostname_match:bool(t.hostname_match),tls_version:cut(t.tls_version,10),weak_cipher:!!t.weak_cipher};
}
function mapWebsite(r){
 const w=r.website_analysis||{},forms=w.forms||{},ext=(forms.items||[]).find(f=>f.external);
 return{has_login_form:!!forms.login_form,has_password_field:num(w.password_fields)>0,external_form_action:ext?cut(ext.action_host||'external',255):null,iframe_count:num((w.iframes||{}).count),hidden_element_count:num((w.hidden_elements||{}).total),
  has_suspicious_scripts:!!(w.scripts||{}).is_suspicious,has_auto_download:!!w.is_download,redirect_count:Math.max(0,num((w.redirects||{}).count))};
}
function mapBrands(r){
 const seen=new Set(),out=[];
 for(const t of ((r.brand_impersonation||{}).targets||[]).slice(0,3)){
  if(seen.has(t.brand)||!t.metrics)continue;seen.add(t.brand);
  out.push({brand:cut(t.brand,60),similarity:pct(t.metrics.similarity),levenshtein:pct(t.metrics.levenshtein_similarity),jaro_winkler:pct(t.metrics.jaro_winkler),ngram:pct(t.metrics.ngram_similarity)});
 }
 return out;
}
function mapThreats(r){
 const seen=new Set(),out=[];
 for(const p of r.threat_intelligence||[]){
  if(!p.provider||seen.has(p.provider))continue;seen.add(p.provider);
  out.push({provider:cut(p.provider,60),reputation:['Malicious','Suspicious','Clean','Unknown'].includes(p.reputation)?p.reputation:'Unknown',is_known_malicious:!!p.is_known_malicious,threat_category:cut(p.threat_category,40),detail:cut(p.detail,80)});
 }
 return out;
}
function toDbAnalysis(r){
 const risk=r.risk;
 return{
  host:cut((r.url||{}).host,255),
  scan_result:mapScanResult(r),url_indicators:mapUrl(r),domain_indicators:mapDomain(r),tls_analysis:mapTls(r),website_analysis:mapWebsite(r),
  brand_matches:mapBrands(r),threat_results:mapThreats(r),
  risk:{score:clamp(Math.round(risk.score),0,100),category:cut(risk.category||'Unknown',40),summary:cut(risk.summary,500),indicators:JSON.stringify((risk.indicators||[]).slice(0,10).map(i=>({icon:cut(i.icon,16),text:cut(i.text,200),detail:cut(i.detail,200),sev:['High','Medium','Low'].includes(i.sev)?i.sev:'Low'})))},
  recommendations:(r.recommendations||[]).slice(0,10).map((x,i)=>({icon:cut(x.icon,16),title:cut(x.title,120),description:String(x.description||''),priority:['High','Medium','Low'].includes(x.priority)?x.priority:'Medium',sort_order:i}))};
}
module.exports={toDbAnalysis};
