import {useState,useEffect} from 'react';
import {useNavigate,useSearchParams} from 'react-router-dom';
import {Card,Btn,Alert,Progress,PageHeader} from '../components/ui.jsx';
import {validateUrl} from '../utils/validateUrl.js';
import {submitScan,getScanStatus,cancelScan,SCAN_STAGES} from '../api/scanService.js';
// [icon, name, description, stage index at which the layer runs]
const LAYERS=[['🔗','URL Security','Structure, length, entropy, encoding and suspicious keywords.',1],['🌍','Domain Intelligence','Domain age, WHOIS data, registrar and DNS records.',2],['🌐','Website Security','Redirect chains, login forms, scripts and hidden iframes.',3],['🔒','SSL/TLS','Certificate issuer, validity window and configuration.',4],['📡','Threat Intelligence','Blocklists and live phishing feeds.',5],['🏷','Brand Impersonation','Look-alike domains and brand mimicry.',5],['🤖','Machine Learning','XGBoost phishing probability with confidence.',6],['⚖️','Risk Assessment','Weighted 0–100 score with explanations.',7]];
const EXAMPLES=['https://secure-paypa1-login.com/verify','https://github.com/login','http://dhl-track-parcel.info/in'];
const Spin=()=><span className="spinner-border spinner-border-sm text-primary"/>;
export default function Scanner(){
const nav=useNavigate();const[sp]=useSearchParams();
const[url,setUrl]=useState(sp.get('url')||'');const[err,setErr]=useState('');const[apiErr,setApiErr]=useState('');
const[jobId,setJobId]=useState(null);const[scanning,setScanning]=useState(false);const[st,setSt]=useState({stageIndex:0,progress:0,status:'running'});
useEffect(()=>{if(!jobId)return;let stop=false;
const fail=m=>{clearInterval(t);setScanning(false);setJobId(null);setApiErr(m)};
const t=setInterval(async()=>{try{const s=await getScanStatus(jobId);if(stop)return;setSt(s);
if(s.status==='completed'){clearInterval(t);setTimeout(()=>nav(`/results/${jobId}`),600)}else if(s.status==='failed')fail(s.error||'Scan failed.')}catch(e){fail(e.message||'Network error.')}},500);
return()=>{stop=true;clearInterval(t)}},[jobId]);
const submit=async e=>{e.preventDefault();setApiErr('');const v=validateUrl(url);if(!v.ok)return setErr(v.error);setErr('');setScanning(true);setSt({stageIndex:0,progress:0,status:'running'});
try{const{scanId}=await submitScan(v.normalized);setJobId(scanId)}catch(x){setScanning(false);setApiErr(x.message||'Could not start the scan.')}};
const cancel=async()=>{await cancelScan(jobId);setJobId(null);setScanning(false)};
const clear=()=>{setUrl('');setErr('');setApiErr('')};
const done=i=>st.status==='completed'||i<st.stageIndex;
return(<><PageHeader title="Phishing URL Scanner" sub="Analyze a URL using machine learning, cybersecurity indicators and threat intelligence."/>
<div className="row g-3 mb-4"><div className="col-lg-8"><Card>
<form onSubmit={submit} noValidate><label htmlFor="url" className="form-label fw-semibold">URL to analyze</label>
<input id="url" autoFocus className={`form-control form-control-lg ${err?'is-invalid':''}`} placeholder="https://example.com/login" value={url} disabled={scanning} autoComplete="off" spellCheck="false" aria-describedby="urlHelp" onChange={e=>{setUrl(e.target.value);setErr('')}}/>
{err?<div className="text-danger small mt-2" role="alert">{err}</div>:<div id="urlHelp" className="form-text">http(s) links only. We never visit or store sensitive form data.</div>}
<div className="d-flex flex-wrap gap-2 mt-3"><Btn loading={scanning} size="lg">{scanning?'Scanning…':'Scan URL'}</Btn><Btn type="button" variant="outline-secondary" size="lg" disabled={scanning||!url} onClick={clear}>Clear</Btn></div></form>
{!scanning&&<div className="mt-3 small text-muted">Try an example: {EXAMPLES.map(x=><button key={x} type="button" className="btn btn-sm btn-light border me-1 mb-1" onClick={()=>{setUrl(x);setErr('')}}>{x.replace(/^https?:\/\//,'').slice(0,30)}</button>)}</div>}
{apiErr&&<div className="mt-3"><Alert type="danger" title="Scan failed." onClose={()=>setApiErr('')}>{apiErr}</Alert></div>}</Card></div>
<div className="col-lg-4"><Card title="Safe scanning tips"><ul className="small text-muted ps-3 mb-0"><li className="mb-1">Copy links instead of clicking them.</li><li className="mb-1">Watch for swapped characters (paypa1).</li><li className="mb-1">A padlock icon does not prove a site is safe.</li><li>Report confirmed phishing to your IT team.</li></ul></Card></div></div>
{scanning&&<div className="mb-4"><Card title="Scan in progress" action={<Btn size="sm" variant="outline-danger" disabled={!jobId||st.status==='completed'} onClick={cancel}>Cancel</Btn>}>
<div className="small text-muted text-break mb-2">{url}</div>
<div className="d-flex justify-content-between small mb-1"><span className="fw-semibold">{st.status==='completed'?'Scan complete — opening results…':SCAN_STAGES[st.stageIndex]+'…'}</span><span>{st.progress}%</span></div><Progress value={st.progress} type="primary"/>
<div className="row g-1 mt-3">{SCAN_STAGES.map((s,i)=>(<div key={s} className={`col-sm-6 col-lg-4 small ${done(i)?'text-success':i===st.stageIndex?'text-primary fw-semibold':'text-muted'}`}><span className="d-inline-block text-center" style={{width:22}}>{done(i)?'✔':i===st.stageIndex?<Spin/>:'○'}</span>{s}</div>))}</div></Card></div>}
<h5 className="fw-bold mb-3">Analysis Layers</h5>
<div className="row g-3">{LAYERS.map(([ic,n,d,stage],k)=>{const state=!scanning?'idle':done(stage)||st.stageIndex>stage?'done':st.stageIndex===stage?'active':'wait';
return(<div key={n} className="col-sm-6 col-xl-3"><div className={`card sp-card h-100 ${state==='active'?'border-primary':state==='done'?'border-success':''}`} style={{opacity:state==='wait'?.55:1,transition:'.2s'}}><div className="card-body"><div className="d-flex justify-content-between align-items-start"><div className="sp-stat-ico bg-primary-subtle">{ic}</div><span className="small">{state==='done'?<span className="text-success">✔ Done</span>:state==='active'?<Spin/>:<span className="text-muted">{k+1}</span>}</span></div><h6 className="mt-3 mb-1">{n}</h6><small className="text-muted">{d}</small></div></div></div>)})}</div></>)}
