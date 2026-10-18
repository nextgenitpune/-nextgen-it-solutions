
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers }
});
const hash = async (value) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))).map(x => x.toString(16).padStart(2, '0')).join('');
const getCookie = (request, name) => {
  const item = (request.headers.get('cookie') || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  if (!item) return null;
  try { return decodeURIComponent(item.slice(name.length + 1)); } catch { return null; }
};
const ownerEmail = env => String(env.ADMIN_EMAIL || env.OWNER_EMAIL || '').trim().toLowerCase();
const isAuthenticated = async (request, env) => {
  const token = getCookie(request, 'ng_session');
  if (!token) return false;
  const row = await env.DB.prepare('SELECT expires_at FROM sessions WHERE token_hash = ?').bind(await hash(token)).first();
  return Boolean(row && Number(row.expires_at) > Date.now());
};
const allowedCategories = ['laptop', 'desktop', 'printer', 'cctv', 'accessories'];
const productInput = b => {
  const name = String(b.name || '').trim();
  const category = String(b.category || '');
  const brand = String(b.brand || '').trim().slice(0,80);
  const model = String(b.model || b.name || '').trim().slice(0,150);
  const condition = ['new','refurbished'].includes(b.condition) ? b.condition : 'new';
  const price = b.price === '' || b.price == null ? null : Number(b.price);
  if (!name || !allowedCategories.includes(category) || (price !== null && (!Number.isFinite(price) || price < 0))) return null;
  return { name: name.slice(0, 150), category, brand, model, condition, description: String(b.description || '').slice(0, 3000), price, image_url: String(b.image_url || '').slice(0, 1000), warranty: String(b.warranty || '').slice(0, 200) };
};

export async function onRequest({ request, env, params }) {
  try {
    if (!env.DB) return json({ error: 'D1 binding DB missing' }, 503);
    const path = '/' + (Array.isArray(params.path) ? params.path.join('/') : (params.path || ''));
    const method = request.method;

     // Public images are served through this API; R2 bucket itself stays private.
     if (path.startsWith('/images/') && method === 'GET') {
       if (!env.PHOTOS) return json({ error: 'R2 PHOTOS binding missing' }, 503);
       const key = path.slice('/images/'.length);
       if (!/^products\/[a-f0-9-]{36}\.(jpg|png|webp|gif)$/.test(key)) return json({ error: 'Invalid image' }, 400);
       const object = await env.PHOTOS.get(key);
       if (!object) return json({ error: 'Image not found' }, 404);
       return new Response(object.body, { headers: { 'content-type': object.httpMetadata?.contentType || 'application/octet-stream', 'cache-control': 'public, max-age=3600', 'x-content-type-options': 'nosniff' } });
     }

    if (path === '/products' && method === 'GET') {
      const result = await env.DB.prepare('SELECT id,name,category,brand,model,condition,description,price,image_url,warranty,created_at FROM products WHERE active=1 ORDER BY created_at DESC').all();
      return json({ products: result.results || [] });
    }
    if (path === '/auth/status' && method === 'GET') return json({ authenticated: await isAuthenticated(request, env) });

    if (path === '/auth/request' && method === 'POST') {
      const body = await request.json();
      const email = String(body.email || '').trim().toLowerCase();
      if (!email || email !== ownerEmail(env)) return json({ message: 'If authorized, a code will be sent.' });
      const missing = ['RESEND_API_KEY', 'OTP_FROM_EMAIL', 'SESSION_SECRET'].filter(key => !env[key]);
      if (missing.length) return json({ error: 'Email configuration incomplete', missing }, 503);

      // Matches existing D1 schema: email, code_hash, expires_at, sent_at, attempts.
      const now = Date.now();
      const previous = await env.DB.prepare('SELECT sent_at FROM otp_codes WHERE email = ?').bind(email).first();
      if (previous && now - Number(previous.sent_at) < 60000) return json({ error: 'Wait 60 seconds before requesting another code' }, 429);

      const random = crypto.getRandomValues(new Uint32Array(1))[0];
      const code = String(random % 1000000).padStart(6, '0');
      const codeHash = await hash(code + ':' + env.SESSION_SECRET);

      const sent = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: env.OTP_FROM_EMAIL, to: [email], subject: 'NEXTGEN Admin login code', text: 'Your login code: ' + code + ' (valid 10 minutes). Do not share it.' })
      });
      if (!sent.ok) {
        console.error('Resend rejected OTP request', sent.status, (await sent.text()).slice(0, 500));
        return json({ error: 'OTP email sending failed. Check Resend settings.' }, 502);
      }

      await env.DB.prepare(`INSERT INTO otp_codes(email,code_hash,expires_at,sent_at,attempts)
        VALUES(?,?,?,?,0)
        ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash, expires_at=excluded.expires_at, sent_at=excluded.sent_at, attempts=0`)
        .bind(email, codeHash, now + 600000, now).run();
      return json({ message: 'Code sent' });
    }

    if (path === '/auth/verify' && method === 'POST') {
      const body = await request.json();
      const email = String(body.email || '').trim().toLowerCase();
      const code = String(body.code || '').trim();
      if (!email || email !== ownerEmail(env) || !/^[0-9]{6}$/.test(code)) return json({ error: 'Invalid code' }, 401);
      if (!env.SESSION_SECRET) return json({ error: 'Session configuration incomplete' }, 503);

      const row = await env.DB.prepare('SELECT code_hash,expires_at,attempts FROM otp_codes WHERE email=?').bind(email).first();
      if (!row || Number(row.expires_at) < Date.now() || Number(row.attempts) >= 5) return json({ error: 'Code expired or too many attempts' }, 401);

      await env.DB.prepare('UPDATE otp_codes SET attempts=attempts+1 WHERE email=?').bind(email).run();
      if (await hash(code + ':' + env.SESSION_SECRET) !== row.code_hash) return json({ error: 'Invalid code' }, 401);

      await env.DB.prepare('DELETE FROM otp_codes WHERE email=?').bind(email).run();
      const token = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(x => x.toString(16).padStart(2, '0')).join('');
      await env.DB.prepare('INSERT INTO sessions(token_hash,expires_at) VALUES(?,?)').bind(await hash(token), Date.now() + 86400000).run();

      return json({ authenticated: true }, 200, { 'set-cookie': 'ng_session=' + token + '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400' });
    }

    if (path === '/auth/logout' && method === 'POST') {
      const token = getCookie(request, 'ng_session');
      if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await hash(token)).run();
      return json({}, 200, { 'set-cookie': 'ng_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0' });
    }

    if (path.startsWith('/admin/')) {
      if (!await isAuthenticated(request, env)) return json({ error: 'Unauthorized' }, 401);

       if (path === '/admin/upload-photo' && method === 'POST') {
         if (!env.PHOTOS) return json({ error: 'R2 PHOTOS binding missing. Configure the bucket in Cloudflare Pages.' }, 503);
         const size = Number(request.headers.get('content-length') || 0);
         if (size > 6 * 1024 * 1024) return json({ error: 'Photo too large (max 5 MB)' }, 413);
         const form = await request.formData();
         const photo = form.get('photo');
         if (!photo || typeof photo.arrayBuffer !== 'function') return json({ error: 'Select a photo' }, 400);
         const formats = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif' };
         const ext = formats[photo.type];
         if (!ext) return json({ error: 'Only JPG, PNG, WebP and GIF photos are allowed' }, 400);
         if (photo.size === 0 || photo.size > 5 * 1024 * 1024) return json({ error: 'Photo must be between 1 byte and 5 MB' }, 413);
         const bytes = new Uint8Array(await photo.arrayBuffer());
         const matches = ext === 'jpg' ? bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff
           : ext === 'png' ? bytes.length >= 8 && [137,80,78,71,13,10,26,10].every((n,i)=>bytes[i]===n)
           : ext === 'gif' ? bytes.length >= 6 && String.fromCharCode(...bytes.slice(0,6)).startsWith('GIF8')
           : ext === 'webp' ? bytes.length >= 12 && String.fromCharCode(...bytes.slice(0,4)) === 'RIFF' && String.fromCharCode(...bytes.slice(8,12)) === 'WEBP' : false;
         if (!matches) return json({ error: 'Invalid image file' }, 400);
         const key = 'products/' + crypto.randomUUID() + '.' + ext;
         await env.PHOTOS.put(key, bytes, { httpMetadata: { contentType: photo.type } });
         return json({ url: '/api/images/' + key }, 201);
       }

      if (path === '/admin/products' && method === 'GET') {
        const result = await env.DB.prepare('SELECT * FROM products ORDER BY created_at DESC').all();
        return json({ products: result.results || [] });
      }

      if (path === '/admin/products' && method === 'POST') {
        const b = productInput(await request.json());
        if (!b) return json({ error: 'Name, category or price invalid' }, 400);
        await env.DB.prepare('INSERT INTO products(name,category,brand,model,condition,description,price,image_url,warranty,active,created_at) VALUES(?,?,?,?,?,?,?,?,?, ?,?)')
          .bind(b.name,b.category,b.brand,b.model,b.condition,b.description,b.price,b.image_url,b.warranty,1,Date.now()).run();
        return json({ ok: true }, 201);
      }

      const match = path.match(/^\/admin\/products\/(\d+)$/);
      if (match && method === 'DELETE') {
        await env.DB.prepare('DELETE FROM products WHERE id=?').bind(Number(match[1])).run();
        return json({ ok: true });
      }
      if (match && method === 'PUT') {
        const raw = await request.json();
        const b = productInput(raw);
        if (!b) return json({ error: 'Invalid product' }, 400);
        await env.DB.prepare('UPDATE products SET name=?,category=?,brand=?,model=?,condition=?,description=?,price=?,image_url=?,warranty=?,active=? WHERE id=?')
          .bind(b.name,b.category,b.brand,b.model,b.condition,b.description,b.price,b.image_url,b.warranty,raw.active === 0 ? 0 : 1,Number(match[1])).run();
        return json({ ok: true });
      }
    }

    return json({ error: 'Not found' }, 404);
  } catch (error) {
    console.error('NEXTGEN API error', error && error.stack ? error.stack : String(error));
    return json({ error: 'Server error; check Cloudflare Function logs' }, 500);
  }
}
