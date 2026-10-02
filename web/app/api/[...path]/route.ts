import {NextRequest} from 'next/server';
async function proxy(request:NextRequest, context:{params:Promise<{path:string[]}>}) {
 const path=(await context.params).path.join('/');
 if(!/^(targets|scans|scans\/[0-9a-f-]{36})$/.test(path)) return new Response('Not found',{status:404});
 if(request.method==='POST' && (request.headers.get('origin')!==`http://${request.headers.get('host')}` || request.headers.get('content-type')!=='application/json')) return new Response('Invalid origin or content type',{status:403});
 const body=request.method==='POST'?await request.text():undefined;
 if(body && body.length>2048) return new Response('Too large',{status:413});
 try {
 const response=await fetch(`${process.env.API_URL}/${path}`,{method:request.method,headers:{Authorization:`Bearer ${process.env.API_TOKEN}`,'Content-Type':'application/json','Idempotency-Key':request.headers.get('idempotency-key')??''},body,cache:'no-store',signal:AbortSignal.timeout(10000)});
 return new Response(await response.text(),{status:response.status,headers:{'Content-Type':'application/json'}});
 } catch {return Response.json({detail:'Backend unavailable'},{status:503});}
}
export {proxy as GET,proxy as POST};
