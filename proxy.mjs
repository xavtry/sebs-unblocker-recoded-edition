// proxy.mjs
import express from 'express';
import rateLimit from 'express-rate-limit';
import fetch from 'node-fetch';
import basicAuth from 'basic-auth';
import { URL } from 'url';
import fs from 'fs';
import path from 'path';

const app = express();
const PORT = process.env.PROXY_PORT ? Number(process.env.PROXY_PORT) : 8002;

// --- Simple config ---
const ALLOWED_HOSTS = [ // restrict destinations you allow the proxy to fetch
  'example.com',
  'www.example.com',
  'api.github.com'
  // add domains you trust/need for dev
];

const ENABLE_AUTH = false;            // set true to require basic auth
const AUTH_USER = process.env.PROXY_USER || 'user';
const AUTH_PASS = process.env.PROXY_PASS || 'pass';

// Rate limiter: limit incoming requests to protect the proxy
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,             // max 30 requests per IP per window
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// optional simple request logging
app.use((req, res, next) => {
  console.log(`[PROXY] ${req.ip} ${req.method} ${req.originalUrl}`);
  next();
});

// Basic auth middleware (if enabled)
function requireAuth(req, res, next) {
  if (!ENABLE_AUTH) return next();
  const creds = basicAuth(req);
  if (!creds || creds.name !== AUTH_USER || creds.pass !== AUTH_PASS) {
    res.set('WWW-Authenticate', 'Basic realm="Proxy"');
    return res.status(401).send('Authentication required');
  }
  next();
}

// Helper: remove hop-by-hop headers
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailers', 'transfer-encoding', 'upgrade'
]);

function filterHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (HOP_BY_HOP.has(k.toLowerCase())) continue;
    // don't forward host header from client blindly
    if (k.toLowerCase() === 'host') continue;
    out[k] = v;
  }
  return out;
}

// Main proxy endpoint
// Usage: /proxy?url=<encoded target url>
app.all('/proxy', requireAuth, express.raw({ type: '*/*', limit: '5mb' }), async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send('Missing url query parameter');

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (e) {
    return res.status(400).send('Invalid URL');
  }

  // security: only allow http(s)
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).send('Only http/https protocols are allowed');
  }

  // security: enforce host whitelist
  const hostname = parsed.hostname;
  if (!ALLOWED_HOSTS.includes(hostname)) {
    return res.status(403).send('Host not allowed by proxy policy');
  }

  // Build fetch options
  const upstreamHeaders = filterHeaders(req.headers);
  // set an identifiable user-agent so target servers see origin
  upstreamHeaders['user-agent'] = upstreamHeaders['user-agent'] || 'DevProxy/1.0 (+https://example.local)';

  const fetchOptions = {
    method: req.method,
    headers: upstreamHeaders,
    redirect: 'manual'
  };

  // attach body for methods that might include one
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    // express.raw has put body into req.body Buffer
    // if no raw parser used, req.body may be empty; express.raw ensures it exists
    fetchOptions.body = req.body && req.body.length ? req.body : null;
  }

  try {
    const upstream = await fetch(targetUrl, fetchOptions);

    // copy status
    res.status(upstream.status);

    // copy selected headers
    upstream.headers.forEach((value, name) => {
      if (HOP_BY_HOP.has(name.toLowerCase())) return;
      // don't send back compression if client doesn't accept it (optional)
      res.setHeader(name, value);
    });

    // stream upstream body to client
    const body = upstream.body;
    if (!body) {
      return res.end();
    }
    body.pipe(res);
    body.on('error', (err) => {
      console.error('[PROXY] upstream stream error', err);
      try { res.end(); } catch (e) {}
    });
  } catch (err) {
    console.error('[PROXY] fetch error', err);
    res.status(502).send('Bad Gateway: error fetching target');
  }
});

// Small HTML page to test (optional)
app.get('/', (req, res) => {
  res.type('html').send(`
    <html>
      <head><meta charset="utf-8"><title>Dev Proxy</title></head>
      <body style="font-family:system-ui,Segoe UI,Roboto">
        <h2>Dev Proxy</h2>
        <p>Use the <code>/proxy?url=</code> endpoint to fetch allowed hosts.</p>
        <p>Allowed hosts: <pre>${ALLOWED_HOSTS.join(', ')}</pre></p>
        <form id="f">
          <input id="u" placeholder="https://example.com" style="width:60%">
          <button>Go</button>
        </form>
        <iframe id="out" style="width:100%;height:60vh;border:1px solid #ddd"></iframe>
        <script>
          document.getElementById('f').addEventListener('submit', e => {
            e.preventDefault();
            const u = document.getElementById('u').value;
            const iframe = document.getElementById('out');
            iframe.src = '/proxy?url=' + encodeURIComponent(u);
          });
        </script>
      </body>
    </html>
  `);
});

app.listen(PORT, () => console.log(`Dev proxy listening on http://localhost:${PORT}`));
