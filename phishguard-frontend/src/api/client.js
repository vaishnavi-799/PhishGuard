import axios from 'axios';
import * as m from '../data/mock.js';
export const USE_MOCK=import.meta.env.VITE_USE_MOCK==='true';
export const api=axios.create({baseURL:import.meta.env.VITE_API_URL||'/api',timeout:20000});
api.interceptors.request.use(c=>{const t=localStorage.getItem('token');if(t)c.headers.Authorization=`Bearer ${t}`;return c});
// Backend envelope {success,data} is unwrapped here, so callers receive the payload directly.
api.interceptors.response.use(r=>{if(r.data&&r.data.success===true&&'data' in r.data)r.data=r.data.data;return r},err=>{
  const r=err.response;const e=r?.data?.error;err.message=e?.details?.[0]?.message||e?.message||(r?null:'Cannot reach the server. Is the backend running?')||err.message;
  if(r?.status===401&&!/\/auth\/(login|register)/.test(err.config?.url||'')){sessionStorage.setItem('auth_notice',r.data?.error?.message||'Please sign in again.');localStorage.removeItem('token');localStorage.removeItem('pg_user');if(location.pathname!=='/login')location.assign('/login')}
  return Promise.reject(err)});
const get=(u,params)=>api.get(u,{params}).then(r=>r.data),post=(u,b)=>api.post(u,b).then(r=>r.data),patch=(u,b)=>api.patch(u,b).then(r=>r.data),del=u=>api.delete(u).then(r=>r.data);
const now=()=>new Date().toISOString().slice(0,16).replace('T',' ');
// ---------- Real backend ----------
const realSvc={
 overview:()=>get('/scans/overview'),scans:()=>get('/scans'),scan:id=>get(`/analysis/${id}`),scanReport:id=>get(`/analysis/${id}/report`),deleteScan:id=>del(`/scans/${id}`),
 intelOverview:()=>get('/threat-intelligence/overview'),lookup:q=>get('/threat-intelligence/lookup',{q}),
 reports:()=>get('/reports'),createReport:scanId=>post('/reports',{scanId}),downloadReport:(id,format='json')=>api.get(`/reports/${id}/download`,{params:{format},responseType:'blob'}),
 adminOverview:()=>get('/admin/overview'),adminUsers:()=>get('/admin/users'),adminScans:()=>get('/admin/scans'),adminLogs:()=>get('/audit',{limit:500}),adminThreats:()=>get('/admin/threats'),
 adminUpdateUser:(id,b)=>patch(`/admin/users/${id}`,b),adminDeleteUser:id=>del(`/admin/users/${id}`),adminInviteUser:b=>post('/admin/users',b),
 adminReviewScan:id=>patch(`/admin/scans/${id}/review`),adminDeleteScan:id=>del(`/admin/scans/${id}`),
 adminAddIndicator:b=>post('/admin/threats',b),adminUpdateIndicator:(id,b)=>patch(`/admin/threats/${id}`,b),adminDeleteIndicator:id=>del(`/admin/threats/${id}`),adminUpdateFeed:(id,b)=>patch(`/admin/threat-feeds/${id}`,b),adminSyncFeed:id=>post(`/admin/threat-feeds/${id}/sync`,{})};
// ---------- Built-in mock (VITE_USE_MOCK=true) ----------
const mock=(d,ms=600)=>new Promise(r=>setTimeout(()=>r(structuredClone(d)),ms)),ok=()=>mock({ok:true},300);
const mockSvc={
 overview:()=>mock({...m.overview,scans:m.scans.slice(0,8),indicators:m.threats.slice(0,5)}),scans:()=>mock(m.scans),
 scan:id=>mock({...(m.scans.find(s=>s.id===id)||m.scans[0]),indicators:m.indicators}),
 scanReport:id=>{const s=m.scans.find(x=>x.id===id);return s?mock(m.reportFor(s),800):Promise.reject(new Error(`Scan ${id} was not found.`))},deleteScan:ok,
 intelOverview:()=>mock({providers:m.providers,timeline:m.globalTimeline},500),lookup:(q,t)=>mock(m.lookupFor(q,t),1400),
 reports:()=>mock(m.reportList),
 createReport:id=>{const s=m.scans.find(x=>x.id===id)||m.scans[0];return mock({id:`R-${3000+Math.floor(Math.random()*999)}`,scanId:s.id,target:s.target,score:s.score,prediction:s.prediction,generated:now(),size:'148 KB'},900)},
 adminOverview:()=>mock(m.adminOverview,600),adminUsers:()=>mock(m.adminUsers),adminScans:()=>mock(m.scans),adminLogs:()=>mock(m.auditLogs),adminThreats:()=>mock({entries:m.adminThreats,feeds:m.providers}),
 adminUpdateUser:ok,adminDeleteUser:ok,adminReviewScan:ok,adminDeleteScan:ok,adminUpdateIndicator:ok,adminDeleteIndicator:ok,
 adminInviteUser:({email,role})=>mock({id:`U-${1100+Math.floor(Math.random()*900)}`,name:email.split('@')[0],email:email.toLowerCase(),role,status:'Pending',scans:0,created:now().slice(0,10),lastActive:'—'},400),
 adminAddIndicator:b=>mock({id:`T-${Date.now()}`,indicator:b.indicator,type:b.type,category:b.category,severity:b.severity,source:'Manual',status:'Active',added:now().slice(0,10)},300)};
export const svc=USE_MOCK?mockSvc:realSvc;
