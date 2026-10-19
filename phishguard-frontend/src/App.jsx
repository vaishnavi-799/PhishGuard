import {Routes,Route} from 'react-router-dom';
import {PublicLayout,AppLayout} from './components/layout.jsx';
import {Login,Register} from './pages/public.jsx';
import Landing from './pages/Landing.jsx';import Dashboard from './pages/Dashboard.jsx';import Scanner from './pages/Scanner.jsx';import Results from './pages/Results.jsx';
import History from './pages/History.jsx';import ScanDetails from './pages/ScanDetails.jsx';import Reports from './pages/Reports.jsx';import ThreatIntel from './pages/ThreatIntel.jsx';import Attachments from './pages/Attachments.jsx';
import * as U from './pages/user.jsx';
import {Guard,RequireAuth} from './auth/AuthContext.jsx';
import AdminDashboard from './pages/admin/AdminDashboard.jsx';import Users from './pages/admin/Users.jsx';import Scans from './pages/admin/Scans.jsx';import Logs from './pages/admin/Logs.jsx';import ThreatMgmt from './pages/admin/ThreatMgmt.jsx';
import {ErrorState} from './components/ui.jsx';
export default function App(){return(<Routes>
<Route element={<PublicLayout/>}><Route path="/" element={<Landing/>}/><Route path="/login" element={<Login/>}/><Route path="/register" element={<Register/>}/></Route>
<Route element={<RequireAuth/>}>
<Route element={<AppLayout/>}>
<Route path="/dashboard" element={<Dashboard/>}/><Route path="/scanner" element={<Scanner/>}/>
<Route path="/results/:id" element={<Results/>}/><Route path="/analysis/:id" element={<U.Analysis/>}/>
<Route path="/history" element={<History/>}/><Route path="/history/:id" element={<ScanDetails/>}/>
<Route path="/threats" element={<ThreatIntel/>}/><Route path="/attachments" element={<Attachments/>}/>
<Route path="/reports" element={<Reports/>}/><Route path="/profile" element={<U.Profile/>}/><Route path="/settings" element={<U.Settings/>}/>
</Route>
<Route element={<AppLayout admin/>}><Route element={<Guard perm="admin:access"/>}>
<Route path="/admin" element={<AdminDashboard/>}/>
<Route element={<Guard perm="users:read"/>}><Route path="/admin/users" element={<Users/>}/></Route>
<Route element={<Guard perm="scans:read"/>}><Route path="/admin/scans" element={<Scans/>}/></Route>
<Route element={<Guard perm="logs:read"/>}><Route path="/admin/logs" element={<Logs/>}/></Route>
<Route element={<Guard perm="threats:read"/>}><Route path="/admin/threats" element={<ThreatMgmt/>}/></Route>
</Route></Route>
</Route>
<Route path="*" element={<div className="p-5"><ErrorState title="404 – Page not found" message="This page doesn't exist."/></div>}/>
</Routes>)}
