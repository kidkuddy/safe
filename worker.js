// Serves the private R2 bucket behind a password.
// Bindings: B (R2 bucket), LOGIN (rate limiter). Secrets: PASSWORD, SESSION_KEY (any long random string).
const enc = new TextEncoder();
const sha = async (s) => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const hex = (u) => [...new Uint8Array(u)].map((b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (s) => new Uint8Array(s.match(/../g).map((b) => parseInt(b, 16)));
const html = { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' };
const LOGIN = `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>safe</title>
<body style="background:#121212;color:#ededed;font:16px system-ui;display:grid;place-items:center;height:100vh;margin:0">
<form method=post action=/login><label>Password <input type=password name=p autofocus required></label> <button>Enter</button></form>`;
const SESSION_DAYS = 30;
// Types a browser only displays or plays (PDFs open in the browser's sandboxed viewer). Anything else from the bucket (html, svg, pdf, unknown) is sent as a
// download, so a file inside an uploaded folder can never run as a page on this origin.
const PASSIVE = /^(video|audio)\/|^image\/(png|jpeg|gif|webp)$|^text\/vtt$|^application\/(json|pdf)$/;

const hmacKey = (env) => crypto.subtle.importKey('raw', enc.encode(env.SESSION_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);

// Session cookie: "<expiry ms>.<HMAC>", signed with SESSION_KEY. The signed text also covers a hash of the
// current password, so changing PASSWORD (or SESSION_KEY) invalidates every existing session.
const signed = async (env, exp) => enc.encode(exp + '.' + hex(await sha(env.PASSWORD)));
async function newSession(env) {
  const exp = String(Date.now() + SESSION_DAYS * 864e5);
  return exp + '.' + hex(await crypto.subtle.sign('HMAC', await hmacKey(env), await signed(env, exp)));
}
async function validSession(req, env) {
  const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)s=(\d{13})\.([0-9a-f]{64})(?:;|$)/);
  if (!m || Number(m[1]) < Date.now()) return false;
  return crypto.subtle.verify('HMAC', await hmacKey(env), unhex(m[2]), await signed(env, m[1]));
}

export default {
  async fetch(req, env) {
    if (!env.PASSWORD || !env.SESSION_KEY) return new Response('PASSWORD and SESSION_KEY secrets must be set', { status: 500 });
    const url = new URL(req.url);

    if (url.pathname === '/login' && req.method === 'POST') {
      // 5 attempts per minute per client address
      const { success } = await env.LOGIN.limit({ key: req.headers.get('cf-connecting-ip') || 'unknown' });
      if (!success) return new Response('Too many attempts. Wait a minute.', { status: 429, headers: { 'retry-after': '60' } });
      const p = String((await req.formData()).get('p') || '');
      if (!crypto.subtle.timingSafeEqual(await sha(p), await sha(env.PASSWORD)))
        return new Response(LOGIN, { status: 401, headers: html });
      return new Response(null, {
        status: 303,
        headers: { location: '/', 'set-cookie': `s=${await newSession(env)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}` },
      });
    }

    if (!(await validSession(req, env))) return new Response(LOGIN, { status: 401, headers: html });
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
    h.set('x-content-type-options', 'nosniff');
    h.set('cache-control', key === 'index.html' || key === 'manifest.json' ? 'no-cache' : 'private, max-age=86400');
    if (key !== 'index.html') {
      const passive = PASSIVE.test(h.get('content-type') || '');
      if (!passive || url.searchParams.has('dl')) h.set('content-disposition', 'attachment');
      if (!passive) h.set('content-security-policy', "sandbox; default-src 'none'");
    }
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
