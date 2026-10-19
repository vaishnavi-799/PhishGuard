import {api,USE_MOCK} from './client.js';
import {scans} from '../data/mock.js';
/*
 * Scan API contract (what the backend must provide later):
 *   POST /scans              {url}  -> {scanId}
 *   GET  /scans/:id/status          -> {status:'running'|'completed'|'failed', stageIndex, progress(0-100), error?}
 *   POST /scans/:id/cancel          -> 204
 * Results are then loaded on /results/:id via svc.scan(id).
 * To go live: set USE_MOCK=false. No UI code changes are needed.
 */
export const SCAN_STAGES=['Initializing scan','Analyzing URL','Checking domain','Analyzing website','Checking SSL/TLS','Checking threat intelligence','Running ML model','Calculating risk','Generating report'];
const DUR=[500,700,800,900,800,900,1000,700,600], TOTAL=DUR.reduce((a,b)=>a+b,0);
const jobs=new Map(), wait=ms=>new Promise(r=>setTimeout(r,ms));
const URLS=scans.filter(s=>s.type==='URL');const pick=url=>URLS[[...url].reduce((a,c)=>a+c.charCodeAt(0),0)%URLS.length].id; // varied mock results per URL
export async function submitScan(url){
  if(!USE_MOCK){const{data}=await api.post('/scans',{url});return data}
  await wait(300);const scanId=pick(url);jobs.set(scanId,{start:Date.now()});return{scanId};
}
export async function getScanStatus(scanId){
  if(!USE_MOCK){const{data}=await api.get(`/scans/${scanId}/status`);return data}
  const j=jobs.get(scanId);if(!j) return{status:'failed',stageIndex:0,progress:0,error:'Scan session expired. Please try again.'};
  const el=Date.now()-j.start;let acc=0,idx=DUR.length;
  for(let i=0;i<DUR.length;i++){acc+=DUR[i];if(el<acc){idx=i;break}}
  const done=idx>=DUR.length;
  return{status:done?'completed':'running',stageIndex:done?DUR.length-1:idx,progress:done?100:Math.min(99,Math.round(el/TOTAL*100))};
}
export async function cancelScan(scanId){if(!USE_MOCK){await api.post(`/scans/${scanId}/cancel`);return}jobs.delete(scanId)}
