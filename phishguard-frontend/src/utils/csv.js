export function downloadCsv(name,header,rows){const q=v=>`"${String(v??'').replace(/"/g,'""')}"`;
const url=URL.createObjectURL(new Blob([[header,...rows].map(r=>r.map(q).join(',')).join('\n')],{type:'text/csv'})),a=document.createElement('a');
a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)}
