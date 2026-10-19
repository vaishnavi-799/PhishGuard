import {useParams} from 'react-router-dom';
import {Async,useAsync} from '../components/ui.jsx';
import {svc} from '../api/client.js';
import {Report} from './Results.jsx';
export default function ScanDetails(){const{id}=useParams();const st=useAsync(()=>svc.scanReport(id),[id]);return<Async state={st}>{r=><Report r={r} details/>}</Async>}
