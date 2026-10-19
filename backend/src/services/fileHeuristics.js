// Static (never executed) file heuristics. Mock reputation; replace with real hash-reputation lookups later.
const K={pdf:['PDF document',['pdf'],12],doc:['Word document (legacy)',['msword'],15],docx:['Word document',['wordprocessingml'],10],docm:['Word document with macros',['macroenabled','ms-word'],45],xls:['Excel workbook (legacy)',['ms-excel'],15],xlsx:['Excel workbook',['spreadsheetml'],10],xlsm:['Excel workbook with macros',['macroenabled','ms-excel'],45],ppt:['PowerPoint (legacy)',['powerpoint'],12],pptx:['PowerPoint presentation',['presentationml'],10],zip:['ZIP archive',['zip'],25],rar:['RAR archive',['rar'],25],'7z':['7-Zip archive',['7z'],25],txt:['Plain text',['text/plain'],3],csv:['CSV data',['csv','excel','text'],4],png:['PNG image',['png'],3],jpg:['JPEG image',['jpeg'],3],jpeg:['JPEG image',['jpeg'],3],gif:['GIF image',['gif'],3],html:['HTML document',['html'],25],
exe:['Windows executable',['msdownload','portable-executable','dosexec','octet-stream'],60],dll:['Dynamic-link library',[],55],msi:['Windows installer',[],55],scr:['Screensaver executable',[],60],bat:['Batch script',[],55],ps1:['PowerShell script',[],55],js:['JavaScript file',['javascript'],55],vbs:['VBScript file',[],60],jar:['Java archive',['java'],50],hta:['HTML application',[],60],lnk:['Windows shortcut',[],50],iso:['Disk image',[],40]};
const SUPPORTED_EXTENSIONS=new Set(Object.keys(K));
const analyzeStatic=(f,hash)=>{
  const name=f.name,m=name.match(/\.([^.\s]+)\s*$/),ext=m?m[1].toLowerCase():'',k=K[ext],reported=(f.type||'').toLowerCase();
  const mismatch=!!(k&&k[1].length&&reported&&!k[1].some(x=>reported.includes(x)));
  const an=[];let score=k?k[2]:20;
  if(/\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(exe|scr|js|vbs|bat|cmd|ps1|jar|hta|lnk|msi)\s*$/i.test(name)){an.push({text:'Double extension: looks like a document but is executable',sev:'bad'});score+=20}
  if(/\u202e/.test(name)){an.push({text:'Right-to-left override character hides the real extension',sev:'bad'});score+=25}
  if(/\s{3,}|\s+\.[a-z0-9]+$/i.test(name)){an.push({text:'Excessive whitespace before the extension',sev:'warn'});score+=8}
  if(name.length>100){an.push({text:'Unusually long file name',sev:'warn'});score+=5}
  if(!ext){an.push({text:'File has no extension',sev:'warn'});score+=5}
  if(/[^\x00-\x7F]/.test(name.replace(/\u202e/g,''))){an.push({text:'Non-ASCII characters in file name',sev:'warn'});score+=5}
  const lure=name.match(/invoice|urgent|payment|salary|password|statement|refund/i);if(lure){an.push({text:`Social-engineering keyword in name: "${lure[0].toLowerCase()}"`,sev:'warn'});score+=5}
  if(mismatch)score+=15;score=Math.min(99,score);
  const rep=score>=60?{label:'High static heuristic risk',status:'bad'}:score>=30?{label:'Review static indicators',status:'warn'}:{label:'No concerning static indicators found',status:'ok'};
  return{name,size:f.size,sha256:hash,fileType:k?k[0]:'Unknown file type',extension:ext?'.'+ext:'(none)',risky:!!k&&k[2]>=40,mime:reported||'Not reported by browser',mismatch,mismatchDetail:mismatch?`Content type "${reported}" does not match .${ext}`:'Extension and MIME type are consistent',anomalies:an,reputation:rep,scanEngine:{name:'External malware scanner',configured:false,status:'unavailable',detail:'No external malware-scanning engine is configured; this result uses static heuristics only.'},score};
};
module.exports={analyzeStatic,SUPPORTED_EXTENSIONS};
