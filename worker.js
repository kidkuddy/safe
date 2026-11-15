// Serves the private R2 bucket behind a password. Bucket binding: B. Secret: PASSWORD.
const enc = new TextEncoder();
const sha = async (s) => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const hex = (u) => [...u].map((b) => b.toString(16).padStart(2, '0')).join('');
const html = { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' };
const LOGIN = `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>safe</title>
<body style="background:#111;color:#ddd;font:16px system-ui;display:grid;place-items:center;height:100vh;margin:0">
<form method=post action=/login><label>Password <input type=password name=p autofocus required></label> <button>Enter</button></form>`;

export default {
  async fetch(req, env) {
    if (!env.PASSWORD) return new Response('PASSWORD secret not set', { status: 500 });
    const url = new URL(req.url);
    // ponytail: session cookie is a fixed hash of the password, so changing the password is the only logout.
    // Switch to signed, expiring tokens if more than one person ever uses this.
    const token = hex(await sha('safe-session:' + env.PASSWORD));

    if (url.pathname === '/login' && req.method === 'POST') {
      const p = String((await req.formData()).get('p') || '');
      if (!crypto.subtle.timingSafeEqual(await sha(p), await sha(env.PASSWORD)))
        return new Response(LOGIN, { status: 401, headers: html });
      return new Response(null, {
        status: 303,
        headers: { location: '/', 'set-cookie': `s=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000` },
      });
    }

    const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)s=([0-9a-f]{64})(?:;|$)/);
    if (!m || !crypto.subtle.timingSafeEqual(enc.encode(m[1]), enc.encode(token)))
      return new Response(LOGIN, { status: 401, headers: html });
    if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('method not allowed', { status: 405 });

    let key;
    try {
      key = decodeURIComponent(url.pathname.slice(1)) || 'index.html';
    } catch {
      return new Response('bad path', { status: 400 });
    }
    let obj;
    try {
      obj = await env.B.get(key, { range: req.headers });
    } catch {
      return new Response('range not satisfiable', { status: 416 });
    }
    if (!obj) return new Response('not found', { status: 404 });

    const h = new Headers();
    obj.writeHttpMetadata(h);
    h.set('etag', obj.httpEtag);
    h.set('accept-ranges', 'bytes');
    h.set('cache-control', key === 'index.html' || key === 'manifest.json' ? 'no-cache' : 'private, max-age=86400');
    if (url.searchParams.has('dl')) h.set('content-disposition', 'attachment');
    let status = 200;
    if (req.headers.has('range') && obj.range) {
      const { offset = 0, length = obj.size - offset } = obj.range;
      h.set('content-range', `bytes ${offset}-${offset + length - 1}/${obj.size}`);
      h.set('content-length', String(length));
      status = 206;
    }
    return new Response(req.method === 'HEAD' ? null : obj.body, { status, headers: h });
  },
};
