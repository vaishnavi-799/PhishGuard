import {createContext,useContext,useState} from 'react';
import {Outlet,Navigate,useLocation} from 'react-router-dom';
import {can as check,ROLES} from './rbac.js';
import {ErrorState,Badge} from '../components/ui.jsx';
import {api,USE_MOCK} from '../api/client.js';
const Ctx=createContext(null),DEFAULT={name:'Amy Collins',email:'amy@corp.io',role:'admin'};
const load=()=>{try{return JSON.parse(localStorage.getItem('pg_user'))}catch{return null}};
const initial=()=>USE_MOCK?(load()||DEFAULT):(localStorage.getItem('token')?load():null);
export const useAuth=()=>useContext(Ctx);
export function AuthProvider({children}){const[u,setU]=useState(initial);
const save=(x,token)=>{setU(x);try{if(x)localStorage.setItem('pg_user',JSON.stringify(x));else localStorage.removeItem('pg_user');if(token)localStorage.setItem('token',token);if(!x)localStorage.removeItem('token')}catch{}};
const mockUser=email=>({email,role:email.startsWith('admin')?'admin':'user',name:email.split('@')[0].replace(/^./,c=>c.toUpperCase())});
const value={user:u&&{...u,initials:u.name.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase()},can:p=>!!u&&check(u.role,p),setRole:role=>save({...u,role}),
 login:async(email,password)=>{if(USE_MOCK){const x=mockUser(email);save(x);return x}const{data}=await api.post('/auth/login',{email,password});save(data.user,data.token);return data.user},
 register:async(name,email,password)=>{if(USE_MOCK){const x={...mockUser(email),name};save(x);return x}const{data}=await api.post('/auth/register',{name,email,password});save(data.user,data.token);return data.user},
 logout:async()=>{if(!USE_MOCK){try{await api.post('/auth/logout')}catch{}}save(USE_MOCK?DEFAULT:null)}};
return<Ctx.Provider value={value}>{children}</Ctx.Provider>}
export const Can=({perm,children,fallback=null})=>useAuth().can(perm)?children:fallback;
export function RequireAuth(){const{user}=useAuth(),loc=useLocation();return user?<Outlet/>:<Navigate to="/login" replace state={{from:loc}}/>}
export function Guard({perm}){const{can}=useAuth();return can(perm)?<Outlet/>:<ErrorState title="403 – Access denied" message="Your role does not have permission to view this page."/>}
export const RoleBadge=({role})=><Badge type={{super_admin:'danger',admin:'primary',analyst:'info',user:'secondary'}[role]}>{ROLES[role]}</Badge>;
