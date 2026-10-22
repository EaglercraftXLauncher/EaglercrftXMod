import { analyze } from './analyzer.js';
import { ApiError, fetchSource } from './fetcher.js';

const SCHEMA_VERSION = 1;
const REPORT_FIELDS = ['versions', 'dependencies', 'assets', 'warnings', 'metadata', 'findings'];

function corsHeaders(env) {
  return {
    'access-control-allow-origin': env.ALLOWED_ORIGIN || '*',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type, authorization, x-api-key',
    'access-control-max-age': '86400',
    vary: 'Origin',
  };
}

function respond(body, status, env, extra = {}, pretty = false) {
  return new Response(JSON.stringify(body, null, pretty ? 2 : 0), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff', ...corsHeaders(env), ...extra },
  });
}

function fail(err, env, pretty) {
  if (err instanceof ApiError) {
    return respond({ ok: false, schemaVersion: SCHEMA_VERSION, error: { code: err.code, message: err.message, ...err.extra } }, err.status, env, { 'cache-control': 'no-store' }, pretty);
  }
  return respond({ ok: false, schemaVersion: SCHEMA_VERSION, error: { code: 'internal_error', message: 'The scanner failed on this input.' } }, 500, env, { 'cache-control': 'no-store' }, pretty);
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function authorize(request, env) {
  if (!env.API_KEY) return;
  const h = request.headers.get('authorization') || '';
  const given = request.headers.get('x-api-key') || (h.toLowerCase().startsWith('bearer ') ? h.slice(7) : '');
  if (!given || !safeEqual(given, String(env.API_KEY))) throw new ApiError('unauthorized', 'Missing or invalid API key.', 401);
}

async function sha256Hex(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function nameFromUrl(u) {
  try {
    const last = decodeURIComponent(new URL(u).pathname.split('/').filter(Boolean).pop() || '');
    return last || 'mod.js';
  } catch { return 'mod.js'; }
}

function summarize(report) {
  const sev = { high: 0, medium: 0, low: 0 };
  for (const w of report.warnings) sev[w.severity] = (sev[w.severity] || 0) + 1;
  const assets = { total: report.assets.length, embedded: 0, remote: 0, relative: 0, runtime: 0 };
  for (const a of report.assets) {
    if (a.cls === 'inline') assets.embedded++;
    else if (a.cls === 'external') assets.remote++;
    else if (a.cls === 'relative') assets.relative++;
    else assets.runtime++;
  }
  const v = report.versions;
  return {
    versions: { declared: v.filter((x) => x.level === 'declared').length, inferred: v.filter((x) => x.level === 'inferred').length, known: v.some((x) => x.level !== 'unknown') },
    dependencies: { total: report.dependencies.length },
    likelyRequired: report.dependencies.filter((d) => d.status === 'Likely required').map((d) => d.name),
    remoteHosts: report.dependencies.filter((d) => d.type === 'Remote resource').map((d) => d.name),
    assets,
    warnings: { total: report.warnings.length, ...sev },
  };
}

async function readInput(request, url, maxBytes) {
  if (request.method === 'GET') {
    const modUrl = url.searchParams.get('url');
    if (!modUrl) throw new ApiError('missing_url', 'Provide the mod location as ?url=<https://...>.', 400);
    return { modUrl, name: url.searchParams.get('name') };
  }
  const len = Number(request.headers.get('content-length'));
  if (len && len > maxBytes + 4096) throw new ApiError('too_large', `The request body is larger than the ${maxBytes} byte limit.`, 413);
  const ct = (request.headers.get('content-type') || '').toLowerCase();
  const buf = new Uint8Array(await request.arrayBuffer());
  if (buf.byteLength > maxBytes + 4096) throw new ApiError('too_large', `The request body is larger than the ${maxBytes} byte limit.`, 413);
  const text = new TextDecoder().decode(buf);
  if (ct.includes('json')) {
    let body;
    try { body = JSON.parse(text); } catch { throw new ApiError('invalid_json', 'The request body is not valid JSON.', 400); }
    if (body && typeof body.url === 'string') return { modUrl: body.url, name: body.name || null };
    if (body && typeof body.source === 'string') return { source: body.source, name: body.name || 'mod.js' };
    throw new ApiError('missing_input', 'Send {"url": "..."} or {"source": "...", "name": "mod.js"}.', 400);
  }
  if (!text.trim()) throw new ApiError('missing_input', 'Empty request body.', 400);
  return { source: text, name: url.searchParams.get('name') || 'mod.js' };
}

export async function handleScan(request, env = {}, ctx = {}) {
  const url = new URL(request.url);
  const pretty = url.searchParams.has('pretty');
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(env) });
  if (request.method !== 'GET' && request.method !== 'POST') {
    return respond({ ok: false, schemaVersion: SCHEMA_VERSION, error: { code: 'method_not_allowed', message: 'Use GET ?url= or POST.' } }, 405, env, { allow: 'GET, POST, OPTIONS' }, pretty);
  }
  try {
    authorize(request, env);
    const maxBytes = Number(env.MAX_BYTES) || 2 * 1024 * 1024;
    const ttl = Number(env.CACHE_TTL ?? 300);
    const cache = request.method === 'GET' && ttl > 0 && typeof caches !== 'undefined' ? caches.default : null;
    if (cache) {
      const hit = await cache.match(request);
      if (hit) { const r = new Response(hit.body, hit); r.headers.set('x-eaglerscan-cache', 'HIT'); return r; }
    }

    const input = await readInput(request, url, maxBytes);
    let text, bytes, bytesRaw, finalUrl = null, contentType = null;
    if (input.source !== undefined) {
      bytesRaw = new TextEncoder().encode(input.source);
      text = input.source; bytes = bytesRaw.byteLength;
      if (bytes > maxBytes) throw new ApiError('too_large', `The source is larger than the ${maxBytes} byte limit.`, 413);
    } else {
      ({ text, bytes, bytesRaw, finalUrl, contentType } = await fetchSource(input.modUrl, env));
    }
    const name = input.name || (finalUrl ? nameFromUrl(finalUrl) : 'mod.js');

    const raw = analyze(name, text, { bytes });
    const report = { versions: raw.versions, dependencies: raw.deps, assets: raw.assets, warnings: raw.warnings, metadata: raw.metadata, findings: raw.findings };
    const summary = summarize(report);

    const wanted = (url.searchParams.get('fields') || '').split(',').map((s) => s.trim()).filter((f) => REPORT_FIELDS.includes(f));
    const out = {
      ok: true,
      schemaVersion: SCHEMA_VERSION,
      scanner: { name: 'EaglerScan', mode: 'static', note: 'Static analysis only; nothing in the mod is executed.' },
      generatedAt: new Date().toISOString(),
      input: { url: input.modUrl || null, resolvedUrl: finalUrl, name, bytes, lines: raw.lines, sha256: await sha256Hex(bytesRaw), contentType },
      summary,
      report: wanted.length ? Object.fromEntries(wanted.map((f) => [f, report[f]])) : report,
    };
    const res = respond(out, 200, env, { 'cache-control': cache ? `public, max-age=${ttl}` : 'no-store', 'x-eaglerscan-cache': 'MISS' }, pretty);
    if (cache && ctx.waitUntil) ctx.waitUntil(cache.put(request, res.clone()));
    return res;
  } catch (err) {
    return fail(err, env, pretty);
  }
}
