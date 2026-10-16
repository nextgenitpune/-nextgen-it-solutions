const json=(v,status=200)=>new Response(JSON.stringify(v),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
const hash=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))).map(x=>x.toString(16).padStart(2,'0')).join('');
const cookie=(r)=>Object.fromEntries((r.headers.get('cookie')||'').split(';').map(s=>s.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2));
const authenticated=async(r,e)=>{const t=cookie(r).ng_session;if(!t)return false;const row=await e.DB.prepare('SELECT expires_at FROM sessions WHERE token_hash=?').bind(await hash(t)).first();return !!row&&row.expires_at>Date.now()};
export async function onRequest({request,env,params}){
 try{
  if(!env.DB)return json({error:'D1 binding DB missing'},503);
  const p='/'+(Array.isArray(params.path)?params.path.join('/'):params.path||'');const method=request.method;
  if(p==='/products'&&method==='GET'){const rows=await env.DB.prepare('SELECT id,name,category,description,price,image_url,warranty,created_at FROM products WHERE active=1 ORDER BY created_at DESC').all();return json({products:rows.results})}
  if(p==='/auth/status'&&method==='GET')return json({authenticated:await authenticated(request,env)});
  if(p==='/auth/request'&&method==='POST'){
   const body=await request.json();const email=String(body.email||'').trim().toLowerCase();if(!(env.ADMIN_EMAIL||env.OWNER_EMAIL)||email!==(String(env.ADMIN_EMAIL||env.OWNER_EMAIL||'').trim().toLowerCase()))return json({message:'If authorized, a code will be sent.'});
  if (!env.RESEND_API_KEY || !env.OTP_FROM_EMAIL || !env.SESSION_SECRET) {
  return json({
    error: 'Email configuration incomplete',
    missing: [
      !env.RESEND_API_KEY && 'RESEND_API_KEY',
      !env.OTP_FROM_EMAIL && 'OTP_FROM_EMAIL',
      !env.SESSION_SECRET && 'SESSION_SECRET'
    ].filter(Boolean)
  }, 503);
  }
   const recent=await env.DB.prepare('SELECT created_at FROM otp_codes WHERE email=? ORDER BY created_at DESC LIMIT 1').bind(email).first();if(recent&&Date.now()-recent.created_at<60000)return json({error:'Wait 60 seconds before requesting another code'},429);
   const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,'0');const digest=await hash(code+':'+env.SESSION_SECRET);await env.DB.prepare('INSERT INTO otp_codes(email,code_hash,expires_at,created_at,attempts) VALUES(?,?,?,?,0)').bind(email,digest,Date.now()+600000,Date.now()).run();
   const sent=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+env.RESEND_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({from:env.OTP_FROM_EMAIL,to:[email],subject:'NEXTGEN Admin login code',text:'Your login code: '+code+' (valid 10 minutes). Do not share it.'})});if(!sent.ok)return json({error:'Email could not be sent; check Resend domain verification'},502);return json({message:'Code sent'});
  }
  if(p==='/auth/verify'&&method==='POST'){
   const b=await request.json();const email=String(b.email||'').trim().toLowerCase(),code=String(b.code||'');if(email!==String((env.ADMIN_EMAIL||env.OWNER_EMAIL)||'').toLowerCase()||!/^[0-9]{6}$/.test(code))return json({error:'Invalid code'},401);
   const row=await env.DB.prepare('SELECT * FROM otp_codes WHERE email=? ORDER BY created_at DESC LIMIT 1').bind(email).first();if(!row||row.expires_at<Date.now()||row.attempts>=5)return json({error:'Code expired or too many attempts'},401);
   await env.DB.prepare('UPDATE otp_codes SET attempts=attempts+1 WHERE id=?').bind(row.id).run();if(await hash(code+':'+env.SESSION_SECRET)!==row.code_hash)return json({error:'Invalid code'},401);
   await env.DB.prepare('DELETE FROM otp_codes WHERE email=?').bind(email).run();const token=Array.from(crypto.getRandomValues(new Uint8Array(32))).map(v=>v.toString(16).padStart(2,'0')).join('');await env.DB.prepare('INSERT INTO sessions(token_hash,expires_at) VALUES(?,?)').bind(await hash(token),Date.now()+86400000).run();return new Response(JSON.stringify({authenticated:true}),{headers:{'content-type':'application/json','set-cookie':'ng_session='+token+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400'}});
  }
  if(p==='/auth/logout'&&method==='POST'){const t=cookie(request).ng_session;if(t)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await hash(t)).run();return new Response('{}',{headers:{'content-type':'application/json','set-cookie':'ng_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'}})}
  if(p.startsWith('/admin/')||p==='/admin/products'){
   if(!await authenticated(request,env))return json({error:'Unauthorized'},401);
   if(p==='/admin/products'&&method==='GET'){const r=await env.DB.prepare('SELECT * FROM products ORDER BY created_at DESC').all();return json({products:r.results})}
   if(p==='/admin/products'&&method==='POST'){
    const b=await request.json();if(!String(b.name||'').trim()||!['laptop','desktop','printer','cctv','accessories'].includes(b.category))return json({error:'Name and valid category required'},400);
    const price=b.price===''||b.price==null?null:Number(b.price);if(price!==null&&(!Number.isFinite(price)||price<0))return json({error:'Invalid price'},400);
    await env.DB.prepare('INSERT INTO products(name,category,description,price,image_url,warranty,active,created_at) VALUES(?,?,?,?,?,?,1,?)').bind(String(b.name).slice(0,150),b.category,String(b.description||'').slice(0,3000),price,String(b.image_url||'').slice(0,1000),String(b.warranty||'').slice(0,200),Date.now()).run();return json({ok:true},201);
   }
   const m=p.match(/^\/admin\/products\/(\d+)$/);if(m&&method==='DELETE'){await env.DB.prepare('DELETE FROM products WHERE id=?').bind(Number(m[1])).run();return json({ok:true})}
   if(m&&method==='PUT'){const b=await request.json();if(!String(b.name||'').trim()||!['laptop','desktop','printer','cctv','accessories'].includes(b.category))return json({error:'Invalid product'},400);const price=b.price===''||b.price==null?null:Number(b.price);if(price!==null&&(!Number.isFinite(price)||price<0))return json({error:'Invalid price'},400);await env.DB.prepare('UPDATE products SET name=?,category=?,description=?,price=?,image_url=?,warranty=?,active=? WHERE id=?').bind(String(b.name).slice(0,150),b.category,String(b.description||'').slice(0,3000),price,String(b.image_url||'').slice(0,1000),String(b.warranty||'').slice(0,200),b.active===0?0:1,Number(m[1])).run();return json({ok:true})}
  }
  return json({error:'Not found'},404);
 }catch(e){return json({error:'Server error; check database migration and environment settings'},500)}
}
