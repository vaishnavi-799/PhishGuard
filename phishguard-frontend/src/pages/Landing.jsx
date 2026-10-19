import {useState} from 'react';
import {Link,useNavigate} from 'react-router-dom';
import {RiskScore,Progress} from '../components/ui.jsx';
const Sec=({id,tag,title,sub,children,alt})=>(<section id={id} className={`lp-sec ${alt?'lp-alt':''}`}><div className="container"><div className="text-center mx-auto mb-5" style={{maxWidth:680}}><span className="lp-tag">{tag}</span><h2 className="fw-bold mt-2">{title}</h2><p className="text-muted">{sub}</p></div>{children}</div></section>);
const CAP=['Machine Learning','URL analysis','Domain intelligence','Website security','Threat intelligence','Brand impersonation','Explainable risk'];
const PROB=[['📋','Blacklist limits','Static lists lag behind attackers; most phishing sites are reported only after victims are hit.'],['⚡','Fresh URLs','Thousands of new phishing domains appear daily and many live under 24 hours.'],['🎭','URL obfuscation','Encoded characters, long subdomains and redirect chains hide the real destination.'],['🏷','Brand impersonation','Pixel-perfect clones of banks, mail and payment pages fool even trained users.'],['🔤','Look-alike domains','Swaps like paypa1.com or rn → m defeat quick visual checks.']];
const LAYERS=[['URL & lexical','Length, entropy, keywords, encoding, special characters'],['Domain intelligence','Domain age, WHOIS, registrar, DNS and hosting reputation'],['Website security','TLS/SSL, redirects, forms, hidden iframes, scripts'],['ML prediction','XGBoost ensemble trained on labelled phishing data'],['Threat & brand intel','Live feeds plus look-alike and logo/brand matching']];
const FEAT=[['🤖','AI Phishing Detection','Gradient-boosted models classify URLs in under two seconds.'],['🔗','URL Security Analysis','Parses structure, redirects and obfuscation tricks.'],['🌍','Domain Intelligence','Age, registrar, WHOIS privacy, DNS and hosting signals.'],['🔒','SSL/TLS Analysis','Certificate issuer, validity window and misconfigurations.'],['📡','Threat Intelligence','Correlates with PhishTank, OpenPhish and your own history.'],['🏷','Brand Impersonation','Detects look-alike domains of top targeted brands.'],['🎯','Risk Scoring','One transparent 0–100 score with a clear severity level.'],['📄','Explainable Reports','SHAP-powered reasons you can export and share.']];
const FLOW=[['🔗','URL / Input','Paste a link or upload a file'],['🛡','Security Analysis','URL, domain and TLS checks'],['🤖','ML Prediction','Phishing probability'],['📡','Threat Intel','Feed and brand lookups'],['⚖️','Risk Engine','Weighted 0–100 score'],['📄','Explainable Report','Reasons and actions']];
const RISK=[['0–19','Very Low','#22c55e','Safe to proceed. No indicators found.'],['20–39','Low','#84cc16','Minor anomalies. Normal caution.'],['40–59','Medium','#f59e0b','Suspicious signals. Verify the sender.'],['60–79','High','#f97316','Likely phishing. Avoid and report.'],['80–100','Critical','#ef4444','Confirmed threat patterns. Block now.']];
const TECH=[['⚛️','React','Responsive analyst dashboard'],['🟩','Node.js','REST API and auth layer'],['🐍','Python','Feature extraction and ML service'],['🚀','XGBoost','High-accuracy classifier'],['🔍','SHAP','Per-prediction explanations'],['🐘','PostgreSQL','Scans, users and audit data']];
function Mock(){return(<div className="position-relative"><div className="lp-mock"><div className="lp-bar"><i/><i/><i/><span>phishguard.ai/scan/S-1042</span></div><div className="p-3 p-md-4">
<div className="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3"><code className="small text-break">secure-paypa1-login.com/verify</code><span className="badge text-bg-danger">Critical</span></div>
<div className="row g-3 align-items-center"><div className="col-5"><RiskScore score={94} size={132}/></div><div className="col-7">{[['Brand impersonation',96],['Domain age',92],['Credential form',90],['Blocklists',84]].map(([n,v])=><div key={n} className="mb-2"><div className="d-flex justify-content-between small"><span>{n}</span><b>{v}</b></div><Progress value={v}/></div>)}</div></div>
<div className="row g-2 mt-2 text-center">{[['Domain age','3 days'],['TLS','DV · 2d'],['Feeds','4 / 9']].map(([k,v])=><div key={k} className="col-4"><div className="lp-chip"><small className="text-muted d-block">{k}</small><b>{v}</b></div></div>)}</div></div></div>
<div className="lp-float d-none d-md-block"><small className="text-muted">Impersonating</small><div className="fw-bold">PayPal · 97%</div></div></div>)}
export default function Landing(){const nav=useNavigate();const[u,setU]=useState('');
return(<>
<section className="lp-hero"><div className="container"><div className="row align-items-center g-5"><div className="col-lg-6">
<span className="lp-tag">🛡 AI-powered cyber defence</span>
<h1 className="display-4 fw-bold mt-3 lp-h1">Detect Phishing. <span className="text-primary">Assess Risk.</span> Respond Faster.</h1>
<p className="lead text-muted mt-3">One platform combining machine learning, URL and domain analysis, website security checks, live threat intelligence and brand impersonation detection — with every risk score explained.</p>
<div className="d-flex flex-wrap gap-1 mb-4">{CAP.map(c=><span key={c} className="lp-pill">✓ {c}</span>)}</div>
<div className="d-flex gap-2 flex-wrap"><Link to="/scanner" className="btn btn-primary btn-lg px-4">Start Scanning</Link><Link to="/dashboard" className="btn btn-outline-primary btn-lg px-4">View Dashboard</Link></div>
<div className="d-flex gap-4 mt-4 text-muted small"><span><b className="text-dark">98.4%</b> accuracy</span><span><b className="text-dark">&lt;2s</b> per scan</span><span><b className="text-dark">40+</b> features</span></div></div>
<div className="col-lg-6"><Mock/></div></div></div></section>

<Sec id="problem" tag="The problem" title="Phishing evolves faster than blacklists" sub="Attackers automate, disguise and rotate. Reactive defences can't keep up.">
<div className="row g-3 justify-content-center">{PROB.map(([i,t,d])=><div key={t} className="col-md-6 col-lg-4"><div className="lp-card h-100"><div className="lp-ico bg-danger-subtle">{i}</div><h6 className="mt-3">{t}</h6><p className="small text-muted mb-0">{d}</p></div></div>)}</div></Sec>

<Sec id="solution" alt tag="The solution" title="Multi-layer detection, one clear verdict" sub="Five independent analysis layers feed a single risk engine, so evasion in one layer is caught by another.">
<div className="row g-3">{LAYERS.map(([t,d],i)=><div key={t} className="col-md-6 col-lg"><div className="lp-card h-100 text-center"><div className="lp-num">{i+1}</div><h6 className="mt-3">{t}</h6><p className="small text-muted mb-0">{d}</p></div></div>)}</div>
<div className="lp-merge mt-4"><span>↓ Risk Engine fuses all layers into a 0–100 score with SHAP explanations ↓</span></div></Sec>

<Sec id="features" tag="Features" title="Everything you need to assess phishing risk" sub="Built for analysts, students and security teams.">
<div className="row g-3">{FEAT.map(([i,t,d])=><div key={t} className="col-sm-6 col-lg-3"><div className="lp-card lp-hover h-100"><div className="lp-ico bg-primary-subtle">{i}</div><h6 className="mt-3">{t}</h6><p className="small text-muted mb-0">{d}</p></div></div>)}</div></Sec>

<Sec id="how" alt tag="How it works" title="From URL to explainable report in seconds" sub="A transparent pipeline you can audit end to end.">
<div className="row g-3 lp-flow">{FLOW.map(([i,t,d],k)=><div key={t} className="col-6 col-lg-2 position-relative"><div className="lp-card h-100 text-center"><div className="lp-ico bg-primary text-white mx-auto">{i}</div><small className="text-primary fw-bold d-block mt-2">STEP {k+1}</small><h6 className="mb-1">{t}</h6><small className="text-muted">{d}</small></div>{k<5&&<span className="lp-arrow d-none d-lg-block">→</span>}</div>)}</div></Sec>

<Sec id="risk" tag="Risk scoring" title="A risk score that tells you what to do" sub="Every scan maps to one of five severity levels with a recommended action.">
<div className="lp-scale mb-4">{RISK.map(([r,l,c])=><div key={l} style={{background:c}}><b>{l}</b><small>{r}</small></div>)}</div>
<div className="row g-3">{RISK.map(([r,l,c,d])=><div key={l} className="col-sm-6 col-lg"><div className="lp-card h-100" style={{borderTop:`4px solid ${c}`}}><div className="fw-bold" style={{color:c}}>{l}</div><div className="small text-muted mb-2">Score {r}</div><p className="small mb-0">{d}</p></div></div>)}</div></Sec>

<Sec id="technology" alt tag="Technology" title="Built on a modern, proven stack" sub="Open, auditable components from interface to model.">
<div className="row g-3">{TECH.map(([i,t,d])=><div key={t} className="col-6 col-md-4 col-lg-2"><div className="lp-card lp-hover h-100 text-center"><div className="fs-2">{i}</div><h6 className="mt-2 mb-1">{t}</h6><small className="text-muted">{d}</small></div></div>)}</div></Sec>

<section className="lp-cta"><div className="container text-center"><h2 className="fw-bold text-white">Check a URL for phishing risk</h2><p className="text-white-50">Paste any link and get an explainable risk score in seconds.</p>
<form className="mx-auto" style={{maxWidth:620}} onSubmit={e=>{e.preventDefault();nav(`/scanner?url=${encodeURIComponent(u)}`)}}><div className="input-group input-group-lg"><input className="form-control" aria-label="URL" placeholder="https://example.com/login" value={u} onChange={e=>setU(e.target.value)}/><button className="btn btn-light fw-semibold">Scan now</button></div></form>
<small className="text-white-50 d-block mt-3">Free to try · No installation required</small></div></section></>)}
