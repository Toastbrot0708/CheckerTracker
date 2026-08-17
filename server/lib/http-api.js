/* ============================================================================
   The API the browser talks to.

   The authorization gate lives here as well as in the wizard. A UI can be
   bypassed by anything that can reach the port, so the check that actually
   matters is this one.
   ========================================================================= */
'use strict';

const { parseScope } = require('./scope');
const systemInfo = require('./system-info');
const tlsProbe = require('./tls-probe');
const httpProbe = require('./http-probe');
const probe = require('./probe');
const { Assessment } = require('./assessment');

const VERSION = '1.0.0';
const runs = new Map();

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store'
  });
  res.end(payload);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > (limit || 64 * 1024)) { reject(new Error('Request body too large.')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!chunks.length) { resolve({}); return; }
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(new Error('Request body is not valid JSON.')); }
    });
    req.on('error', reject);
  });
}

/**
 * Route one /api request.
 * @param {object} opts { allowPublic, auditLog }
 */
async function handle(req, res, url, opts) {
  const path = url.pathname.replace(/^\/api/, '') || '/';
  const method = req.method.toUpperCase();

  if (method === 'GET' && path === '/health') {
    return json(res, 200, {
      ok: true,
      service: 'checkertracker',
      version: VERSION,
      platform: process.platform,
      allowPublic: !!opts.allowPublic,
      secureContext: !!opts.tls,
      capabilities: {
        hostDiscovery: 'real', portScan: 'real', interfaceInfo: 'real',
        tlsHandshake: 'real', httpFetch: 'real', macAddress: 'real',
        hostnameResolution: 'real'
      }
    });
  }

  if (method === 'GET' && path === '/interfaces') {
    return json(res, 200, await systemInfo.environment());
  }

  if (method === 'POST' && path === '/tls') {
    const body = await readBody(req);
    if (!body.host) return json(res, 400, { error: 'host is required' });
    const result = await tlsProbe.inspect(String(body.host), Number(body.port) || 443, {
      servername: body.servername || body.host,
      enumerate: body.enumerate !== false,
      timeoutMs: 8000
    });
    opts.auditLog('tls.inspect', body.host + ':' + (body.port || 443));
    return json(res, 200, result);
  }

  if (method === 'POST' && path === '/http') {
    const body = await readBody(req);
    if (!body.url) return json(res, 400, { error: 'url is required' });
    const result = await httpProbe.fetchHead(String(body.url), { timeoutMs: 10000 });
    opts.auditLog('http.fetch', String(body.url));
    return json(res, 200, result);
  }

  if (method === 'POST' && path === '/port') {
    const body = await readBody(req);
    if (!body.host || !body.port) return json(res, 400, { error: 'host and port are required' });
    const result = await probe.probePort(String(body.host), Number(body.port), 3000);
    const banner = result.state === 'open'
      ? await probe.grabBanner(String(body.host), Number(body.port), 1500) : null;
    return json(res, 200, Object.assign({}, result, { banner, identity: probe.identifyBanner(banner) }));
  }

  if (method === 'POST' && path === '/scan') {
    return startScan(req, res, opts);
  }

  const runMatch = path.match(/^\/scan\/([\w-]+)\/(events|control)$/);
  if (runMatch) {
    const run = runs.get(runMatch[1]);
    if (!run) return json(res, 404, { error: 'No such run.' });
    if (runMatch[2] === 'events') return streamEvents(req, res, run);
    const body = await readBody(req);
    if (body.action === 'pause') run.pause();
    else if (body.action === 'resume') run.resume();
    else if (body.action === 'cancel') run.cancel();
    else return json(res, 400, { error: 'Unknown action.' });
    return json(res, 200, { state: run.state });
  }

  return json(res, 404, { error: 'Unknown endpoint.' });
}

async function startScan(req, res, opts) {
  const body = await readBody(req);

  // The gate. Not advisory, and not delegated to the UI.
  if (body.authorized !== true) {
    return json(res, 403, {
      error: 'unauthorized',
      message: 'An assessment cannot start until the operator confirms authorization for the systems in scope.'
    });
  }

  let scope;
  try {
    scope = parseScope(String(body.scope || ''), { allowPublic: opts.allowPublic });
  } catch (err) {
    return json(res, 400, { error: 'scope', message: err.message });
  }

  const env = await systemInfo.environment();
  const run = new Assessment({
    id: 'run-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 1e6).toString(36),
    scope,
    depth: ['passive', 'hosts', 'services'].indexOf(body.depth) === -1 ? 'services' : body.depth,
    stages: Array.isArray(body.stages) ? body.stages : ['discover', 'identify', 'metadata', 'tls', 'headers'],
    gateway: env.gateway,
    ports: body.fullPorts ? probe.TOP_PORTS : probe.TOP_PORTS,
    concurrency: Math.min(256, Math.max(8, Number(body.concurrency) || 96))
  });

  runs.set(run.id, run);
  opts.auditLog('scan.start', scope.label + ' (' + scope.total + ' addresses, depth ' + run.depth + ')');

  // Drop finished runs after a grace period so a reconnecting client can
  // still collect the result.
  run.on('done', () => setTimeout(() => runs.delete(run.id), 10 * 60 * 1000));
  run.on('error', () => setTimeout(() => runs.delete(run.id), 60 * 1000));

  run.run();

  return json(res, 202, {
    runId: run.id,
    scope: { label: scope.label, total: scope.total },
    network: env,
    events: '/api/scan/' + run.id + '/events'
  });
}

/** Server-Sent Events: no extra protocol, and it survives a phone sleeping. */
function streamEvents(req, res, run) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });

  const send = (type, payload) => {
    if (res.writableEnded) return;
    res.write('event: ' + type + '\n');
    res.write('data: ' + JSON.stringify(payload) + '\n\n');
  };

  send('hello', { runId: run.id, state: run.state, progress: run.progress });
  run.log.forEach((entry) => send('log', entry));

  ['progress', 'stage', 'log', 'state', 'host'].forEach((type) => run.on(type, (p) => send(type, p)));
  run.on('done', (result) => { send('done', result); res.end(); });
  run.on('error', (err) => { send('failed', err); res.end(); });

  const keepAlive = setInterval(() => { if (!res.writableEnded) res.write(': ping\n\n'); }, 15000);
  req.on('close', () => clearInterval(keepAlive));
}

module.exports = { handle, json, VERSION, runs };
