import {useState} from 'react';
import {Link,useNavigate} from 'react-router-dom';
import {Card,Btn,Badge,Stat,PageHeader,Async,useAsync,DataTable,LineTrend,DonutChart,BarsChart,Empty,useToast,LevelBadge,Progress} from '../components/ui.jsx';
import {svc} from '../api/client.js';
const cols=[
{h:'URL',r:r=><div className="text-truncate" style={{maxWidth:230}} title={r.target}><code className="small">{r.target}</code></div>},
{h:'Risk Score',r:r=><div className="d-flex align-items-center gap-2" style={{minWidth:120}}><b>{r.score}</b><LevelBadge score={r.score}/></div>},
{h:'Category',k:'category'},
{h:'ML Prediction',r:r=><Badge type={r.prediction==='Phishing'?'danger':'success'}>{r.prediction}</Badge>},
{h:'Confidence',r:r=><div style={{minWidth:90}}><Progress value={r.confidence} type="primary" label={`${r.confidence}%`}/></div>},
{h:'Date',r:r=><span className="text-nowrap">{r.date}</span>},
{h:'Status',r:r=><Badge>{r.status}</Badge>},
{h:'Action',r:r=><Link className="btn btn-sm btn-outline-primary" to={`/history/${r.id}`}>View</Link>}];
function QuickScan(){const nav=useNavigate();const[u,setU]=useState('');const[e,setE]=useState('');
const go=ev=>{ev.preventDefault();if(!u.trim())return setE('Enter a URL to scan.');nav(`/scanner?url=${encodeURIComponent(u.trim())}`)};
return(<Card><div className="row align-items-center g-3"><div className="col-lg-4"><h6 className="mb-1">⚡ Quick Scan</h6><small className="text-muted">Check any link for phishing risk in under 2 seconds.</small></div>
<div className="col-lg-8"><form onSubmit={go}><div className="input-group input-group-lg"><input className={`form-control ${e?'is-invalid':''}`} aria-label="URL to scan" placeholder="https://example.com/login" value={u} onChange={x=>{setU(x.target.value);setE('')}}/><Btn>Scan</Btn>{e&&<div className="invalid-feedback">{e}</div>}</div></form></div></div></Card>)}
function Recs({items}){const[list,setL]=useState(items);const toast=useToast();
return(<Card title="Security Recommendations" action={<small className="text-muted">{list.length} open</small>}>{!list.length?<Empty icon="✅" title="All caught up" message="You have no open recommendations."/>:list.map(r=>(<div key={r.id} className="d-flex gap-3 py-2 border-bottom align-items-start"><div className="fs-5">{r.icon}</div><div className="flex-grow-1"><div className="d-flex gap-2 align-items-center flex-wrap"><strong className="small">{r.title}</strong><Badge>{r.priority}</Badge></div><small className="text-muted">{r.text}</small></div><Btn size="sm" variant="outline-secondary" onClick={()=>{setL(list.filter(x=>x.id!==r.id));toast('Marked as done')}}>Done</Btn></div>))}</Card>)}
export default function Dashboard(){const st=useAsync(svc.overview);const[range,setRange]=useState(7);
return(<><PageHeader title="Security Overview" sub="Monitor phishing threats and analyze suspicious URLs."><Link to="/reports" className="btn btn-outline-primary">Export</Link><Link to="/scanner" className="btn btn-primary">+ New scan</Link></PageHeader>
<Async state={st}>{d=>(<><div className="mb-3"><QuickScan/></div>
<div className="row g-3 mb-3"><div className="col-sm-6 col-xl-3"><Stat icon="🔍" label="Total Scans" value={d.stats.total.toLocaleString()} delta="▲ 12% vs last week"/></div>
<div className="col-sm-6 col-xl-3"><Stat icon="🎣" label="Phishing Detected" value={d.stats.phishing} color="danger" delta={<span className="text-danger">▲ 8% vs last week</span>}/></div>
<div className="col-sm-6 col-xl-3"><Stat icon="⚠️" label="High / Critical Risks" value={d.stats.highCritical} color="warning" delta={<span className="text-success">▼ 3% vs last week</span>}/></div>
<div className="col-sm-6 col-xl-3"><Stat icon="✅" label="Safe URLs" value={d.stats.safe} color="success" delta="▲ 14% vs last week"/></div></div>
<div className="row g-3 mb-3"><div className="col-xl-6"><Card title="Scan Activity" action={<div className="btn-group btn-group-sm">{[7,30].map(n=><button key={n} className={`btn btn-${range===n?'primary':'outline-secondary'}`} onClick={()=>setRange(n)}>{n}d</button>)}</div>}><LineTrend data={range===7?d.activity7:d.activity30}/></Card></div>
<div className="col-md-6 col-xl-3"><Card title="Risk Distribution"><DonutChart data={d.riskDist}/></Card></div>
<div className="col-md-6 col-xl-3"><Card title="Detection Results"><BarsChart data={d.detection}/></Card></div></div>
<div className="mb-3"><Card title="Recent Scans" action={<Link to="/history" className="small">View all</Link>}><DataTable search={false} pageSize={6} cols={cols} rows={d.scans}/></Card></div>
<div className="row g-3"><div className="col-lg-6"><Card title="Recent Threat Indicators" action={<Link to="/threats" className="small">Threat intel</Link>}>{d.indicators.map(t=>(<div key={t.id} className="d-flex justify-content-between align-items-center gap-2 py-2 border-bottom"><div className="text-truncate"><code>{t.domain}</code><div className="small text-muted">{t.category} · {t.source} · {t.seen}</div></div><Badge>{t.severity}</Badge></div>))}</Card></div>
<div className="col-lg-6"><Recs items={d.recs}/></div></div></>)}</Async></>)}
