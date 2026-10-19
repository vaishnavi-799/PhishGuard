const {test,before,after}=require('node:test'),assert=require('node:assert/strict'),http=require('http'),fs=require('fs'),path=require('path');
const {createAnalysisClient,AnalysisError}=require('../../src/services/analysisClient');
const REPORT=JSON.parse(fs.readFileSync(path.join(__dirname,'..','fixtures','report.legit.json'),'utf8'));
let server,base,handler,seen;
before(async()=>{server=http.createServer((req,res)=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>{seen.push({method:req.method,url:req.url,key:req.headers['x-api-key'],body:b?JSON.parse(b):null});handler(req,res)})});await new Promise(r=>server.listen(0,'127.0.0.1',r));base=`http://127.0.0.1:${server.address().port}`});
after(()=>server.close());
const reply=(status,body)=>(req,res)=>{res.writeHead(status,{'Content-Type':'application/json'});res.end(typeof body==='string'?body:JSON.stringify(body))};
const client=o=>createAnalysisClient({baseUrl:base,apiKey:'k3y',timeoutMs:500,retries:1,retryDelayMs:5,...o});
const codeOf=p=>p.then(()=>null,e=>e instanceof AnalysisError?e.code:`NOT_ANALYSIS_ERROR:${e&&e.message}`);

test('sends the URL and options with the API key and returns a validated report',async()=>{
 seen=[];handler=reply(200,REPORT);
 const r=await client().analyze('https://www.example.com/x',{inspectWebsite:false,includeMl:false});
 assert.equal(r.risk.score,REPORT.risk.score);
 assert.deepEqual(seen[0],{method:'POST',url:'/analyze',key:'k3y',body:{url:'https://www.example.com/x',inspect_website:false,include_ml:false}});
});
test('defaults: website inspection and ML enabled',async()=>{seen=[];handler=reply(200,REPORT);await client().analyze('https://a.example');assert.deepEqual(seen[0].body,{url:'https://a.example',inspect_website:true,include_ml:true})});
test('maps HTTP errors to safe, typed errors',async()=>{
 for(const [status,code] of [[422,'INVALID_URL'],[400,'INVALID_URL'],[401,'UNAUTHORIZED'],[403,'UNAUTHORIZED'],[500,'UPSTREAM'],[502,'UPSTREAM']]){
  handler=reply(status,{detail:'secret internal stack trace'});seen=[];
  const e=await client({retries:0}).analyze('https://a.example').catch(x=>x);
  assert.equal(e.code,code,String(status));assert.ok(!/secret|stack/.test(e.message),'internal details must not leak');
 }
});
test('retries once on 429/503 then succeeds; gives up after the retry budget',async()=>{
 let n=0;handler=(req,res)=>{n++;n===1?reply(429,{})(req,res):reply(200,REPORT)(req,res)};seen=[];
 assert.equal((await client().analyze('https://a.example')).schema_version,'1.0');assert.equal(seen.length,2);
 handler=reply(503,{});seen=[];assert.equal(await codeOf(client().analyze('https://a.example')),'BUSY');assert.equal(seen.length,2);
 seen=[];assert.equal(await codeOf(client({retries:0}).analyze('https://a.example')),'BUSY');assert.equal(seen.length,1);
});
test('does not retry non-retryable failures',async()=>{handler=reply(422,{});seen=[];await codeOf(client().analyze('https://a.example'));assert.equal(seen.length,1)});
test('times out on a hanging service',async()=>{handler=()=>{};const t=Date.now();assert.equal(await codeOf(client({timeoutMs:150}).analyze('https://a.example')),'TIMEOUT');assert.ok(Date.now()-t<1000)});
test('reports an unreachable service as UNAVAILABLE',async()=>{assert.equal(await codeOf(createAnalysisClient({baseUrl:'http://127.0.0.1:1',timeoutMs:500,retries:0}).analyze('https://a.example')),'UNAVAILABLE')});
test('rejects malformed or unsupported responses',async()=>{
 for(const body of ['not json',JSON.stringify({}),JSON.stringify({...REPORT,schema_version:'2.0'}),JSON.stringify({...REPORT,risk:{...REPORT.risk,score:'high'}}),JSON.stringify({...REPORT,modules:undefined})]){
  handler=reply(200,body);assert.equal(await codeOf(client({retries:0}).analyze('https://a.example')),'BAD_RESPONSE',String(body).slice(0,30));
 }
});
test('requires a base URL; health() calls /health',async()=>{
 assert.throws(()=>createAnalysisClient({}));handler=reply(200,{status:'ok'});seen=[];assert.deepEqual(await client().health(),{status:'ok'});assert.equal(seen[0].url,'/health');
});
