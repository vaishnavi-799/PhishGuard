import {useState} from 'react';
import {Link} from 'react-router-dom';
import {Card,Badge,Stat,PageHeader,Async,useAsync,LineTrend,DonutChart,BarsChart} from '../../components/ui.jsx';
import {svc} from '../../api/client.js';
export default function AdminDashboard(){const st=useAsync(svc.adminOverview);const[range,setRange]=useState(30);
return(<><PageHeader title="Admin Dashboard" sub="Platform-wide usage, threats and system health."><Link to="/admin/logs" className="btn btn-outline-primary">Audit logs</Link></PageHeader>
<Async state={st}>{d=>{const bad=d.services.some(s=>s.status!=='Operational'),s=d.stats;return(<>
<div className="row g-3 mb-3">
<div className="col-sm-6 col-xl-4"><Stat icon="👥" label="Total users" value={s.users.toLocaleString()} delta="▲ 5.2% this month"/></div>
<div className="col-sm-6 col-xl-4"><Stat icon="🟢" label="Active users (30d)" value={s.active.toLocaleString()} color="success" delta={`${Math.round(s.active/s.users*100)}% of all users`}/></div>
<div className="col-sm-6 col-xl-4"><Stat icon="🔍" label="Total scans" value={s.scans.toLocaleString()} color="info" delta="▲ 12% this month"/></div>
<div className="col-sm-6 col-xl-4"><Stat icon="🎣" label="Phishing detections" value={s.phishing.toLocaleString()} color="danger" delta={<span className="text-muted">{(s.phishing/s.scans*100).toFixed(1)}% of scans</span>}/></div>
<div className="col-sm-6 col-xl-4"><Stat icon="🚨" label="Critical threats" value={s.critical.toLocaleString()} color="danger" delta={<span className="text-danger">▲ 8% this week</span>}/></div>
<div className="col-sm-6 col-xl-4"><Stat icon={bad?'🟠':'✅'} label="System status" value={<span className={bad?'text-warning':'text-success'}>{bad?'Degraded':'Operational'}</span>} color={bad?'warning':'success'} delta={<span className="text-muted">{d.services.filter(x=>x.status==='Operational').length}/{d.services.length} services healthy</span>}/></div></div>
<div className="row g-3 mb-3"><div className="col-xl-8"><Card title="Scan volume" action={<div className="btn-group btn-group-sm">{[7,30].map(n=><button key={n} className={`btn btn-${range===n?'primary':'outline-secondary'}`} onClick={()=>setRange(n)}>{n}d</button>)}</div>}><LineTrend data={range===7?d.volume7:d.volume30}/></Card></div>
<div className="col-xl-4"><Card title="Threat distribution"><DonutChart data={d.threatDist}/></Card></div></div>
<div className="row g-3 mb-3"><div className="col-lg-6"><Card title="User activity (daily active users)"><BarsChart data={d.userActivity} color="#2563eb"/></Card></div><div className="col-lg-6"><Card title="Risk distribution"><BarsChart data={d.riskDist}/></Card></div></div>
<div className="row g-3"><div className="col-lg-5"><Card title="System health">{d.services.map(x=><div key={x.name} className="d-flex justify-content-between align-items-center py-2 border-bottom"><div><div className="small fw-semibold">{x.name}</div><small className="text-muted">{x.note}</small></div><Badge>{x.status}</Badge></div>)}</Card></div>
<div className="col-lg-7"><Card title="Recent alerts">{d.alerts.map((a,i)=><div key={i} className="d-flex gap-3 py-2 border-bottom"><span className={`rounded-circle bg-${a.tone} flex-shrink-0 mt-1`} style={{width:10,height:10}}/><div><div className="small fw-semibold">{a.title}</div><small className="text-muted">{a.detail} · {a.time}</small></div></div>)}</Card></div></div></>)}}</Async></>)}
