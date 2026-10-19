// HTTP client for the Python analysis service (POST /analyze). No dependency on app config: everything is injected.
class AnalysisError extends Error{constructor(code,message,{retryable=false,status}={}){super(message);this.code=code;this.retryable=retryable;this.status=status}}
const SAFE_MESSAGES={INVALID_URL:'The URL was rejected by the analysis service',BUSY:'The analysis service is busy, please try again',UNAVAILABLE:'The analysis service is unavailable',TIMEOUT:'The analysis timed out',UPSTREAM:'The analysis service returned an error',BAD_RESPONSE:'The analysis service returned an unexpected response',UNAUTHORIZED:'The analysis service rejected our credentials'};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function validateReport(r){
 if(!r||typeof r!=='object'||r.schema_version!=='1.0')return 'unsupported schema_version';
 if(!r.risk||!Number.isInteger(r.risk.score)||r.risk.score<0||r.risk.score>100)return 'risk.score invalid';
 for(const k of ['url','modules','url_analysis','domain_analysis','tls_analysis','website_analysis','brand_impersonation','threat_intelligence','recommendations'])if(r[k]==null)return `missing ${k}`;
 return null}
function createAnalysisClient({baseUrl,apiKey='',timeoutMs=45000,retries=1,retryDelayMs=500,fetchImpl=globalThis.fetch}){
 if(!baseUrl)throw new Error('baseUrl is required');
 async function call(path,{method='GET',body}={}){
  const ctl=new AbortController(),timer=setTimeout(()=>ctl.abort(),timeoutMs);
  try{
   const res=await fetchImpl(baseUrl+path,{method,signal:ctl.signal,headers:{'Content-Type':'application/json',Accept:'application/json',...(apiKey?{'X-API-Key':apiKey}:{})},body:body?JSON.stringify(body):undefined});
   if(res.status===422||res.status===400)throw new AnalysisError('INVALID_URL',SAFE_MESSAGES.INVALID_URL,{status:res.status});
   if(res.status===401||res.status===403)throw new AnalysisError('UNAUTHORIZED',SAFE_MESSAGES.UNAUTHORIZED,{status:res.status});
   if(res.status===429||res.status===503)throw new AnalysisError('BUSY',SAFE_MESSAGES.BUSY,{retryable:true,status:res.status});
   if(!res.ok)throw new AnalysisError('UPSTREAM',SAFE_MESSAGES.UPSTREAM,{status:res.status});
   try{return await res.json()}catch{throw new AnalysisError('BAD_RESPONSE',SAFE_MESSAGES.BAD_RESPONSE)}
  }catch(e){
   if(e instanceof AnalysisError)throw e;
   if(e&&e.name==='AbortError')throw new AnalysisError('TIMEOUT',SAFE_MESSAGES.TIMEOUT,{retryable:false});
   throw new AnalysisError('UNAVAILABLE',SAFE_MESSAGES.UNAVAILABLE,{retryable:true}); // connection refused, DNS failure, reset...
  }finally{clearTimeout(timer)}}
 async function withRetry(fn){let last;for(let i=0;i<=retries;i++){try{return await fn()}catch(e){last=e;if(!(e instanceof AnalysisError)||!e.retryable||i===retries)throw e;await sleep(retryDelayMs*(i+1))}}throw last}
 return{
  analyze:(url,{inspectWebsite=true,includeMl=true}={})=>withRetry(async()=>{const r=await call('/analyze',{method:'POST',body:{url,inspect_website:inspectWebsite,include_ml:includeMl}});const bad=validateReport(r);if(bad)throw new AnalysisError('BAD_RESPONSE',SAFE_MESSAGES.BAD_RESPONSE);return r}),
  health:()=>call('/health')};
}
module.exports={createAnalysisClient,AnalysisError,validateReport,SAFE_MESSAGES};
