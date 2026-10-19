import {useState} from 'react';
import {Link,useNavigate} from 'react-router-dom';
import {Card,Btn,Badge,PageHeader,Async,useAsync,DataTable,LevelBadge,riskLevel,Progress,useToast,Empty} from '../components/ui.jsx';
import {svc} from '../api/client.js';
import {scanPdf} from '../utils/mockPdf.js';
const init={q:'',cat:'All',pred:'All',status:'All',from:'',to:'',min:'',max:''};
const Sel=({label,v,on,opts})=>(<div className="col-6 col-lg-3"><label className="form-label small text-muted mb-1">{label}</label><select className="form-select form-select-sm" value={v} onChange={on}>{opts.map(o=><option key={o}>{o}</option>)}</select></div>);
const In=({label,cls='col-6 col-lg-3',...p})=>(<div className={cls}><label className="form-label small text-muted mb-1">{label}</label><input className="form-control form-control-sm" {...p}/></div>);
export default function History(){const st=useAsync(svc.scans);const nav=useNavigate();const toast=useToast();const[f,setF]=useState(init);const set=k=>e=>setF({...f,[k]:e.target.value});
const q=f.q.toLowerCase(),badRange=f.min!==''&&f.max!==''&&+f.min>+f.max;
const match=r=>{const d=r.date.slice(0,10);return(!q||r.target.toLowerCase().includes(q)||r.id.toLowerCase().includes(q))&&(f.cat==='All'||riskLevel(r.score)[1]===f.cat)&&(f.pred==='All'||r.prediction===f.pred)&&(f.status==='All'||r.status===f.status)&&(!f.from||d>=f.from)&&(!f.to||d<=f.to)&&(f.min===''||r.score>=+f.min)&&(f.max===''||r.score<=+f.max)};
const cols=[{h:'Scan ID',r:r=><b>{r.id}</b>},{h:'URL',r:r=><div className="text-truncate" style={{maxWidth:240}} title={r.target}><code className="small">{r.target}</code></div>},
{h:'Risk Score',r:r=><div className="d-flex align-items-center gap-2" style={{minWidth:110}}><b style={{width:24}}>{r.score}</b><div className="flex-grow-1"><Progress value={r.score}/></div></div>},
{h:'Category',r:r=><LevelBadge score={r.score}/>},{h:'Prediction',r:r=><Badge type={r.prediction==='Phishing'?'danger':'success'}>{r.prediction}</Badge>},
{h:'Confidence',r:r=>`${r.confidence}%`},{h:'Date',r:r=><span className="text-nowrap">{r.date}</span>},
{h:'Actions',r:r=><div className="d-flex gap-1"><Link to={`/history/${r.id}`} className="btn btn-sm btn-outline-primary" onClick={e=>e.stopPropagation()}>View</Link><Btn size="sm" variant="outline-secondary" title="Download PDF" aria-label="Download PDF" onClick={e=>{e.stopPropagation();scanPdf(r);toast(`Downloaded ${r.id}.pdf`)}}>⬇</Btn></div>}];
return(<><PageHeader title="Scan History" sub="Review, filter and revisit every scan."><Link to="/scanner" className="btn btn-primary">+ New scan</Link></PageHeader>
<Async state={st}>{d=>{const n=d.filter(match).length;return(<>
<div className="mb-3"><Card><div className="row g-2">
<In label="Search URL or ID" cls="col-12 col-lg-4" type="search" placeholder="e.g. paypal, S-1040" value={f.q} onChange={set('q')}/>
<Sel label="Risk category" v={f.cat} on={set('cat')} opts={['All','Very Low','Low','Medium','High','Critical']}/>
<Sel label="Prediction" v={f.pred} on={set('pred')} opts={['All','Phishing','Legitimate']}/>
<Sel label="Status" v={f.status} on={set('status')} opts={['All','Completed','Reviewed','Failed']}/>
<In label="From date" type="date" value={f.from} max={f.to||undefined} onChange={set('from')}/><In label="To date" type="date" value={f.to} min={f.from||undefined} onChange={set('to')}/>
<In label="Min score" type="number" min="0" max="100" placeholder="0" value={f.min} onChange={set('min')}/><In label="Max score" type="number" min="0" max="100" placeholder="100" value={f.max} onChange={set('max')}/></div>
<div className="d-flex justify-content-between align-items-center mt-3"><small className={badRange?'text-danger':'text-muted'}>{badRange?'Min score must not exceed max score.':`${n} of ${d.length} scans match`}</small><Btn size="sm" variant="outline-secondary" disabled={JSON.stringify(f)===JSON.stringify(init)} onClick={()=>setF(init)}>Reset filters</Btn></div></Card></div>
<Card>{n===0?<Empty icon="🔎" title="No scans match your filters" message="Try widening the date range or clearing filters." action={<Btn variant="outline-primary" size="sm" onClick={()=>setF(init)}>Reset filters</Btn>}/>:<DataTable search={false} pageSize={10} cols={cols} rows={d} filter={match} onRow={r=>nav(`/history/${r.id}`)}/>}</Card></>)}}</Async></>)}
