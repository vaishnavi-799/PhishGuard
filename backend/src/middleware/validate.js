// validate({body,query,params}) with zod schemas; parsed values replace the raw ones
module.exports=schemas=>(req,res,next)=>{try{for(const k of ['params','query','body'])if(schemas[k]){const r=schemas[k].parse(req[k]);if(k==='query')Object.defineProperty(req,'query',{value:r,writable:true});else req[k]=r}next()}catch(e){next(e)}};
