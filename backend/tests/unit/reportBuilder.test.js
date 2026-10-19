const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),path=require('path');
const {toDbAnalysis}=require('../../src/services/analysisMapper'),builder=require('../../src/services/reportBuilder');
const load=n=>JSON.parse(fs.readFileSync(path.join(__dirname,'..','fixtures',`report.${n}.json`),'utf8'));
// Rebuilds the rows a database would return for a stored analysis, then renders the frontend report.
function fromDb(name){
 const raw=load(name),a=toDbAnalysis(raw),fx=o=>({...o});
 const parts={url:fx(a.url_indicators),domain:fx(a.domain_indicators),tls:fx(a.tls_analysis),web:fx(a.website_analysis),result:{...a.scan_result,top_features:JSON.parse(a.scan_result.top_features)},
  risk:{...a.risk,indicators:JSON.parse(a.risk.indicators)},brands:a.brand_matches.map(b=>({...b,similarity:b.similarity})),intel:a.threat_results.map((t,i)=>({id:i,...t})),recs:a.recommendations.map(r=>({...r})),engine:raw};
 const summary={id:7,user_id:1,email:'a@b.c',target:raw.url.input,type:'URL',score:a.risk.score,prediction:a.scan_result.prediction,confidence:a.scan_result.confidence,category:a.risk.category,status:'Completed',created_at:new Date()};
 return{raw,report:builder.build(summary,parts)};
}
const KEYS=['scan','why','actions','url','domain','ssl','web','brand','intel','ml','shap','engine'];
for(const n of ['phishing_with_ml','phishing_heuristic','legit','offline','ip_host'])test(`builds a complete report for '${n}'`,()=>{
 const{report:r}=fromDb(n);for(const k of KEYS)assert.ok(k in r,k);
 for(const sec of ['url','domain','ssl','web'])assert.ok(r[sec].length>0&&r[sec].every(x=>x.label&&x.value!=null&&['ok','warn','bad','info'].includes(x.status)),sec);
 assert.ok(r.actions.length>0);assert.ok(r.shap.length>0);assert.equal(JSON.stringify(r).includes('undefined'),false);
});
test('unknown DNS is shown as Unknown, not as "Not resolving"',()=>{
 const dns=fromDb('offline').report.domain.find(x=>x.label==='DNS status');assert.deepEqual([dns.value,dns.status],['Unknown','info']);
});
test('modules that did not run are reported honestly instead of as clean results',()=>{
 const off=fromDb('offline').report;assert.deepEqual(off.web.map(x=>x.label),['Website inspection']);assert.equal(off.web[0].status,'warn');assert.match(off.web[0].value,/disabled/i);
 const ip=fromDb('ip_host').report;assert.deepEqual(ip.web.map(x=>x.label),['Website inspection']);assert.match(ip.web[0].value,/private/i);
});
test('engine summary is attached for the UI',()=>{
 const r=fromDb('phishing_with_ml').report;assert.equal(r.engine.risk_method,'blended');assert.ok(r.engine.risk_factors.length>0);assert.equal(r.engine.modules.website.status,'ok');assert.ok(r.engine.typosquatting.length>0);
 assert.equal(r.brand.name,'PayPal');assert.ok(r.brand.jw>80);assert.equal(r.ml.model,'xgboost 20260101T000000Z');
 assert.ok(r.web.find(x=>x.label==='External form action').value.includes('collector.evil.ru'));
});
test('mock-analyzer data (no engine report) still renders',()=>{
 const raw=load('legit'),a=toDbAnalysis(raw);
 const r=builder.build({id:1,user_id:1,email:'x@y.z',target:'t.example',type:'URL',score:5,prediction:'Legitimate',confidence:90,category:'Legitimate',status:'Completed',created_at:new Date()},{url:a.url_indicators,domain:a.domain_indicators,tls:a.tls_analysis,web:a.website_analysis,result:{...a.scan_result,top_features:JSON.parse(a.scan_result.top_features)},risk:{...a.risk,indicators:JSON.parse(a.risk.indicators)},brands:[],intel:[],recs:[]});
 assert.equal(r.engine,null);assert.ok(r.web.length>1);
});
