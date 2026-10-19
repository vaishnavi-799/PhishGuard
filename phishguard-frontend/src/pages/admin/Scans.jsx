import {useState} from 'react';
import {Link} from 'react-router-dom';
import {Card,Btn,Badge,PageHeader,Async,useAsync,DataTable,Modal,useToast,Sel,FInput,Empty,LevelBadge,riskLevel,Progress} from '../../components/ui.jsx';
import {Can} from '../../auth/AuthContext.jsx';
import {svc} from '../../api/client.js';
const init={q:'',cat:'All',pred:'All',status:'All'};
function ScanTable({initial}){const toast=useToast();const[list,setList]=useState(initial);const[f,setF]=useState(init);const[del,setDel]=useState(null);const set=k=>e=>setF({...f,[k]:e.target.value}),q=f.q.toLowerCase();
const match=s=>(!q||s.target.toLowerCase().includes(q)||s.id.toLowerCase().includes(q)||s.user.includes(q))&&(f.cat==='All'||riskLevel(s.score)[1]===f.cat)&&(f.pred==='All'||s.prediction===f.pred)&&(f.status==='All'||s.status===f.status);
const n=list.filter(match).length;
const cols=[{h:'Scan ID',r:s=><b>{s.id}</b>},{h:'User',k:'user'},{h:'URL',r:s=><div className="text-truncate" style={{maxWidth:220}} title={s.target}><code className="small">{s.target}</code></div>},
{h:'Risk',r:s=><div className="d-flex align-items-center gap-2" style={{minWidth:130}}><b style={{width:24}}>{s.score}</b><LevelBadge score={s.score}/></div>},{h:'Prediction',r:s=><Badge type={s.prediction==='Phishing'?'danger':'success'}>{s.prediction}</Badge>},
{h:'Date',r:s=><span className="text-nowrap">{s.date}</span>},{h:'Status',r:s=><Badge>{s.status}</Badge>},
{h:'Actions',r:s=><div className="d-flex gap-1"><Link to={`/history/${s.id}`} className="btn btn-sm btn-outline-primary">View</Link><Can perm="scans:manage"><Btn size="sm" variant="outline-secondary" disabled={s.status==='Reviewed'} onClick={()=>svc.adminReviewScan(s.id).then(()=>{setList(l=>l.map(x=>x.id===s.id?{...x,status:'Reviewed'}:x));toast(`${s.id} marked as reviewed`)}).catch(e=>toast(e.message,'danger'))}>Review</Btn></Can><Can perm="scans:delete"><Btn size="sm" variant="outline-danger" onClick={()=>setDel(s)}>Delete</Btn></Can></div>}];
return(<><PageHeader title="Scan Management" sub="Monitor and review scans across all users."/>
<div className="mb-3"><Card><div className="row g-2"><FInput label="Search ID, user or URL" cls="col-12 col-lg-4" type="search" value={f.q} onChange={set('q')}/><Sel label="Risk" v={f.cat} on={set('cat')} opts={['All','Very Low','Low','Medium','High','Critical']}/><Sel label="Prediction" v={f.pred} on={set('pred')} opts={['All','Phishing','Legitimate']}/><Sel label="Status" v={f.status} on={set('status')} opts={['All','Completed','Reviewed','Failed']} cls="col-6 col-lg-2"/></div>
<div className="d-flex justify-content-between align-items-center mt-3"><small className="text-muted">{n} of {list.length} scans</small><Btn size="sm" variant="outline-secondary" disabled={JSON.stringify(f)===JSON.stringify(init)} onClick={()=>setF(init)}>Reset filters</Btn></div></Card></div>
<Card>{n===0?<Empty icon="🔎" title="No scans match" message="Adjust or reset the filters."/>:<DataTable search={false} pageSize={10} cols={cols} rows={list} filter={match}/>}</Card>
<Modal show={!!del} title="Delete scan?" onClose={()=>setDel(null)} footer={<><Btn variant="light" onClick={()=>setDel(null)}>Cancel</Btn><Btn variant="danger" onClick={()=>svc.adminDeleteScan(del.id).then(()=>{setList(l=>l.filter(x=>x.id!==del.id));toast('Scan deleted','danger');setDel(null)}).catch(e=>{toast(e.message,'danger');setDel(null)})}>Delete</Btn></>}>Remove scan <b>{del?.id}</b> and its report for {del?.user}?</Modal></>)}
export default function Scans(){const st=useAsync(svc.adminScans);return<Async state={st}>{d=><ScanTable initial={d}/>}</Async>}
