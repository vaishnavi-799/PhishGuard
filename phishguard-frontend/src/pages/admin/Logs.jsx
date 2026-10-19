import {useState} from 'react';
import {Card,Btn,Badge,PageHeader,Async,useAsync,DataTable,Modal,Sel,FInput,Empty} from '../../components/ui.jsx';
import {Can} from '../../auth/AuthContext.jsx';
import {svc} from '../../api/client.js';
import {downloadCsv} from '../../utils/csv.js';
const init={q:'',action:'All',result:'All',from:'',to:''};
function LogTable({initial}){const[f,setF]=useState(init);const[sel,setSel]=useState(null);const set=k=>e=>setF({...f,[k]:e.target.value}),q=f.q.toLowerCase();
const match=l=>{const d=l.timestamp.slice(0,10);return(!q||l.user.includes(q)||l.ip.includes(q)||l.action.toLowerCase().includes(q))&&(f.action==='All'||l.action===f.action)&&(f.result==='All'||l.result===f.result)&&(!f.from||d>=f.from)&&(!f.to||d<=f.to)};
const rows=initial.filter(match),actions=['All',...new Set(initial.map(l=>l.action))];
const cols=[{h:'User',r:l=><span className={l.user==='unknown'?'text-muted fst-italic':''}>{l.user}</span>},{h:'Action',r:l=><code>{l.action}</code>},{h:'IP',k:'ip'},{h:'Timestamp',r:l=><span className="text-nowrap">{l.timestamp}</span>},{h:'Result',r:l=><Badge>{l.result}</Badge>}];
return(<><PageHeader title="Audit Logs" sub="Immutable record of security-relevant activity."><Can perm="logs:export"><Btn variant="outline-primary" disabled={!rows.length} onClick={()=>downloadCsv('audit-logs.csv',['id','user','action','ip','timestamp','result','detail'],rows.map(l=>[l.id,l.user,l.action,l.ip,l.timestamp,l.result,l.detail]))}>⬇ Export CSV</Btn></Can></PageHeader>
<div className="mb-3"><Card><div className="row g-2"><FInput label="Search user, IP or action" cls="col-12 col-lg-3" type="search" value={f.q} onChange={set('q')}/><Sel label="Action" v={f.action} on={set('action')} opts={actions} cls="col-6 col-lg-2"/><Sel label="Result" v={f.result} on={set('result')} opts={['All','Success','Failure','Blocked']} cls="col-6 col-lg-2"/><FInput label="From" type="date" cls="col-6 col-lg-2" value={f.from} onChange={set('from')}/><FInput label="To" type="date" cls="col-6 col-lg-2" value={f.to} onChange={set('to')}/></div>
<div className="d-flex justify-content-between align-items-center mt-3"><small className="text-muted">{rows.length} of {initial.length} events · click a row for details</small><Btn size="sm" variant="outline-secondary" disabled={JSON.stringify(f)===JSON.stringify(init)} onClick={()=>setF(init)}>Reset filters</Btn></div></Card></div>
<Card>{!rows.length?<Empty icon="📜" title="No events found" message="Try a different filter or date range."/>:<DataTable search={false} pageSize={12} cols={cols} rows={initial} filter={match} onRow={setSel}/>}</Card>
<Modal show={!!sel} title="Audit event" onClose={()=>setSel(null)} footer={<Btn variant="light" onClick={()=>setSel(null)}>Close</Btn>}>{sel&&<dl className="row small mb-0">{[['Event ID',sel.id],['User',sel.user],['Action',sel.action],['IP address',sel.ip],['Timestamp',sel.timestamp],['Result',<Badge>{sel.result}</Badge>],['Details',sel.detail]].map(([k,v])=><><dt className="col-4">{k}</dt><dd className="col-8">{v}</dd></>)}</dl>}</Modal></>)}
export default function Logs(){const st=useAsync(svc.adminLogs);return<Async state={st}>{d=><LogTable initial={d}/>}</Async>}
