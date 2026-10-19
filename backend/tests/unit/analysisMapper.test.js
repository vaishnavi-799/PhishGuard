// Runs without a database or any npm packages:  node --test tests/unit
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),path=require('path');
const {toDbAnalysis}=require('../../src/services/analysisMapper');
const load=n=>JSON.parse(fs.readFileSync(path.join(__dirname,'..','fixtures',`report.${n}.json`),'utf8'));
const FIX=['phishing_with_ml','phishing_heuristic','legit','offline','ip_host'];
const inList=(v,l)=>l.includes(v);
const between=(v,a,b)=>typeof v==='number'&&v>=a&&v<=b;

// Mirrors the CHECK / NOT NULL constraints in the SQL migrations, so mapping bugs are caught without a database.
function assertMatchesSchema(a){
 const sr=a.scan_result;
 assert.ok(inList(sr.prediction,['Phishing','Legitimate']));assert.ok(between(sr.probability,0,100));assert.ok(between(sr.confidence,0,100));
 assert.ok(sr.model_name.length>0&&sr.model_name.length<=40&&sr.model_version.length<=20);assert.ok(Array.isArray(JSON.parse(sr.top_features)));
 const u=a.url_indicators;assert.ok(u.url_length>0&&u.subdomain_count>=0&&u.special_char_count>=0&&u.redirect_count>=0);assert.ok(Array.isArray(u.suspicious_keywords));
 const d=a.domain_indicators;assert.ok(d.domain&&d.domain.length<=255);assert.ok(d.domain_age_days===null||d.domain_age_days>=0);assert.ok(inList(d.reputation,['Good','Neutral','Poor','Unknown']));assert.ok(Array.isArray(d.nameservers));assert.ok(d.registered_at===null||d.registered_at instanceof Date);
 const t=a.tls_analysis;assert.equal(typeof t.https_enabled,'boolean');assert.equal(typeof t.weak_cipher,'boolean');if(t.issued_at&&t.expires_at)assert.ok(t.expires_at>t.issued_at);assert.ok(!t.tls_version||t.tls_version.length<=10);
 const w=a.website_analysis;for(const k of ['has_login_form','has_password_field','has_suspicious_scripts','has_auto_download'])assert.equal(typeof w[k],'boolean',k);for(const k of ['iframe_count','hidden_element_count','redirect_count'])assert.ok(Number.isInteger(w[k])&&w[k]>=0,k);
 const seenB=new Set();for(const b of a.brand_matches){assert.ok(!seenB.has(b.brand));seenB.add(b.brand);for(const k of ['similarity','levenshtein','jaro_winkler','ngram'])assert.ok(between(b[k],0,100),k)}
 const seenP=new Set();for(const t of a.threat_results){assert.ok(!seenP.has(t.provider));seenP.add(t.provider);assert.ok(inList(t.reputation,['Malicious','Suspicious','Clean','Unknown']));assert.ok(!t.threat_category||t.threat_category.length<=40);assert.ok(!t.detail||t.detail.length<=80)}
 const r=a.risk;assert.ok(Number.isInteger(r.score)&&between(r.score,0,100));assert.ok(r.category.length<=40);assert.ok(Array.isArray(JSON.parse(r.indicators)));
 for(const x of a.recommendations){assert.ok(inList(x.priority,['High','Medium','Low']));assert.ok(x.title&&x.title.length<=120);assert.ok(Number.isInteger(x.sort_order))}
 assert.ok(a.host&&a.host.length<=255);
}

for(const name of FIX)test(`maps '${name}' to rows that satisfy every DB constraint`,()=>assertMatchesSchema(toDbAnalysis(load(name))));

test('phishing report with ML: values flow through',()=>{
 const r=load('phishing_with_ml'),a=toDbAnalysis(r);
 assert.equal(a.risk.score,r.risk.score);assert.equal(a.risk.category,'Brand Impersonation');
 assert.deepEqual([a.scan_result.prediction,a.scan_result.probability,a.scan_result.confidence,a.scan_result.model_name,a.scan_result.model_version],['Phishing',95,90,'xgboost','20260101T000000Z']);
 assert.deepEqual(JSON.parse(a.scan_result.top_features)[0],{f:'Look-alike of a known brand domain',val:'1',v:2.31});
 assert.equal(a.brand_matches[0].brand,'PayPal');assert.ok(a.brand_matches[0].jaro_winkler>80);
 assert.equal(a.domain_indicators.domain_age_days,3);assert.equal(a.domain_indicators.dns_resolves,true);assert.equal(a.domain_indicators.reputation,'Poor');
 assert.deepEqual([a.website_analysis.has_password_field,a.website_analysis.has_suspicious_scripts,a.website_analysis.external_form_action,a.website_analysis.iframe_count],[true,true,'collector.evil.ru',1]);
 assert.equal(a.tls_analysis.https_enabled,true);assert.equal(a.tls_analysis.certificate_valid,true);assert.equal(a.tls_analysis.issuer,'Test CA');
 assert.equal(a.url_indicators.uses_shortener,false);assert.ok(a.url_indicators.suspicious_keywords.includes('login'));
 assert.ok(a.threat_results.some(t=>t.provider==='LocalHeuristics'));assert.ok(a.recommendations.some(x=>x.title==='Do not enter credentials'));
 assert.equal(a.host,'paypa1-secure-login.xyz');
});
test('without an ML model the heuristic result is stored and clearly labelled',()=>{
 const r=load('phishing_heuristic'),a=toDbAnalysis(r),s=a.scan_result;
 assert.equal(r.ml,null);assert.equal(s.model_name,'heuristic-risk');assert.match(s.model_version,/^engine-/);
 assert.equal(s.prediction,r.risk.score>=50?'Phishing':'Legitimate');assert.equal(s.probability,r.risk.score);
 const f=JSON.parse(s.top_features);assert.ok(f.length>0&&f.every(x=>typeof x.v==='number'));
});
test('legitimate brand domain maps to a low-risk, non-phishing result',()=>{
 const a=toDbAnalysis(load('legit'));assert.equal(a.scan_result.prediction,'Legitimate');assert.ok(a.risk.score<=10);assert.deepEqual(a.brand_matches,[]);
});
test('offline analysis stores unknowns as NULL, not as fake facts',()=>{
 const a=toDbAnalysis(load('offline'));
 assert.equal(a.domain_indicators.dns_resolves,null);assert.equal(a.domain_indicators.domain_age_days,null);assert.equal(a.tls_analysis.certificate_valid,null);assert.equal(a.tls_analysis.https_enabled,false);
 assert.equal(a.url_indicators.has_encoding,true);assert.deepEqual(a.website_analysis,{has_login_form:false,has_password_field:false,external_form_action:null,iframe_count:0,hidden_element_count:0,has_suspicious_scripts:false,has_auto_download:false,redirect_count:0});
});
test('IP host with a blocked website fetch still maps cleanly',()=>{
 const r=load('ip_host'),a=toDbAnalysis(r);assert.equal(a.url_indicators.is_ip_based,true);assert.equal(a.host,'203.0.113.5');assert.equal(r.modules.website.status,'failed');
});
test('hostile or malformed engine output cannot violate constraints',()=>{
 const r=load('phishing_with_ml');
 r.risk.score=250.7;r.risk.category='x'.repeat(200);r.tls_analysis.issued_at='2030-01-01T00:00:00Z';r.tls_analysis.expires_at='2020-01-01T00:00:00Z';
 r.threat_intelligence=[{provider:'P',reputation:'Weird',is_known_malicious:1,detail:'d'.repeat(500)},{provider:'P',reputation:'Clean'}];
 r.brand_impersonation.targets=[{brand:'B',metrics:{similarity:9,levenshtein_similarity:-3,jaro_winkler:'x',ngram_similarity:null}},{brand:'B',metrics:{similarity:1}}];
 r.recommendations=[{title:'t',description:null,priority:'Urgent'}];r.ml.probability=7;r.ml.confidence=-1;
 const a=toDbAnalysis(r);assertMatchesSchema(a);
 assert.equal(a.risk.score,100);assert.equal(a.tls_analysis.issued_at,null);assert.equal(a.threat_results.length,1);assert.equal(a.threat_results[0].reputation,'Unknown');assert.equal(a.brand_matches.length,1);assert.equal(a.recommendations[0].priority,'Medium');
});
