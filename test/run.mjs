// Offline tests: the handler is exercised with a mocked global fetch (no network needed).
import assert from 'node:assert/strict';
import { handleScan } from '../src/handler.js';

const MOD = `ModAPI.meta.title("guns");
ModAPI.meta.description("Requires AsyncSink.");
const player = require("player");
AsyncSink.setFile("resourcepacks/AsyncSinkLib/assets/minecraft/textures/items/pistol.png", await (await fetch("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==")).arrayBuffer());
`;
const calls = [];
const files = {
  'https://example.com/guns.js': () => new Response(MOD, { headers: { 'content-type': 'text/javascript' } }),
  'https://raw.githubusercontent.com/ck/repo/main/guns.js': () => new Response(MOD, { headers: { 'content-type': 'text/plain' } }),
  'https://example.com/page': () => new Response('<!DOCTYPE html><html></html>', { headers: { 'content-type': 'text/html' } }),
  'https://example.com/big.js': () => new Response('a'.repeat(3000), { headers: { 'content-type': 'text/javascript' } }),
  'https://example.com/redir': () => new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/secret' } }),
  'https://example.com/redir-ok': () => new Response(null, { status: 301, headers: { location: '/guns.js' } }),
  'https://example.com/missing.js': () => new Response('nope', { status: 404 }),
  'https://example.com/bin.js': () => new Response(new Uint8Array([1, 2, 0, 3]), { headers: { 'content-type': 'application/octet-stream' } }),
};
globalThis.fetch = async (u) => { calls.push(String(u)); const f = files[String(u)]; if (!f) throw new Error('no network in tests: ' + u); return f(); };

const env = { MAX_BYTES: '2048', CACHE_TTL: '0' };
const req = (path, init) => new Request('https://api.test' + path, init);
const call = async (path, init, e = env) => { const r = await handleScan(req(path, init), e, {}); return { r, j: await r.json() }; };
let n = 0;
const t = async (name, fn) => { await fn(); n++; console.log('ok -', name); };

await t('GET ?url= returns a full JSON report', async () => {
  const { r, j } = await call('/api/scan?url=' + encodeURIComponent('https://example.com/guns.js'), undefined, { ...env, MAX_BYTES: '200000' });
  assert.equal(r.status, 200); assert.equal(j.ok, true); assert.equal(j.schemaVersion, 1);
  assert.equal(j.input.name, 'guns.js'); assert.match(j.input.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(j.summary.likelyRequired, ['AsyncSink']);
  assert.equal(j.summary.assets.embedded, 1); assert.equal(j.summary.assets.remote, 0);
  assert.ok(!j.report.warnings.some((w) => /data: URL/.test(w.title)), 'embedded data URL must not warn');
  assert.ok(j.report.dependencies.find((d) => d.name === 'player' && d.status === 'Unverified'));
  assert.ok(j.report.assets[0].path.endsWith('pistol.png'));
  assert.equal(r.headers.get('access-control-allow-origin'), '*');
});
await t('GitHub blob URLs are rewritten to raw', async () => {
  calls.length = 0;
  const { j } = await call('/api/scan?url=' + encodeURIComponent('https://github.com/ck/repo/blob/main/guns.js'), undefined, { ...env, MAX_BYTES: '200000' });
  assert.equal(j.ok, true); assert.equal(calls[0], 'https://raw.githubusercontent.com/ck/repo/main/guns.js');
});
await t('POST {url} and POST {source} and raw body', async () => {
  const big = { ...env, MAX_BYTES: '200000' };
  let x = await call('/api/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'https://example.com/guns.js' }) }, big);
  assert.equal(x.j.ok, true);
  x = await call('/api/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ source: MOD, name: 'inline.js' }) }, big);
  assert.equal(x.j.ok, true); assert.equal(x.j.input.name, 'inline.js'); assert.equal(x.j.input.url, null);
  x = await call('/api/scan?name=raw.js', { method: 'POST', headers: { 'content-type': 'text/javascript' }, body: MOD }, big);
  assert.equal(x.j.input.name, 'raw.js');
});
await t('?fields= trims the report', async () => {
  const { j } = await call('/api/scan?fields=dependencies,assets&url=' + encodeURIComponent('https://example.com/guns.js'), undefined, { ...env, MAX_BYTES: '200000' });
  assert.deepEqual(Object.keys(j.report), ['dependencies', 'assets']);
});
await t('redirects are followed and re-validated', async () => {
  let x = await call('/api/scan?url=' + encodeURIComponent('https://example.com/redir-ok'), undefined, { ...env, MAX_BYTES: '200000' });
  assert.equal(x.j.ok, true);
  x = await call('/api/scan?url=' + encodeURIComponent('https://example.com/redir'));
  assert.equal(x.r.status, 403); assert.equal(x.j.error.code, 'blocked_host');
});
await t('SSRF guard blocks local/private/odd targets', async () => {
  for (const u of ['http://localhost/a.js', 'http://127.0.0.1/a.js', 'http://169.254.169.254/latest/meta-data', 'http://10.0.0.5/a.js', 'http://[::1]/a.js', 'http://2130706433/a.js', 'https://intranet/a.js', 'https://example.com:8443/a.js', 'ftp://example.com/a.js', 'https://user:pw@example.com/a.js']) {
    const { r, j } = await call('/api/scan?url=' + encodeURIComponent(u));
    assert.ok([400, 403].includes(r.status), u + ' -> ' + r.status); assert.equal(j.ok, false);
  }
});
await t('size limit, html pages, binary, 404', async () => {
  assert.equal((await call('/api/scan?url=' + encodeURIComponent('https://example.com/big.js'))).r.status, 413);
  const h = await call('/api/scan?url=' + encodeURIComponent('https://example.com/page'));
  assert.equal(h.r.status, 415); assert.equal(h.j.error.code, 'not_javascript');
  assert.equal((await call('/api/scan?url=' + encodeURIComponent('https://example.com/bin.js'))).r.status, 415);
  assert.equal((await call('/api/scan?url=' + encodeURIComponent('https://example.com/missing.js'))).r.status, 404);
});
await t('input validation and methods', async () => {
  assert.equal((await call('/api/scan')).j.error.code, 'missing_url');
  assert.equal((await call('/api/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' })).j.error.code, 'invalid_json');
  assert.equal((await call('/api/scan', { method: 'DELETE' })).r.status, 405);
  const o = await handleScan(req('/api/scan', { method: 'OPTIONS' }), env, {});
  assert.equal(o.status, 204); assert.match(o.headers.get('access-control-allow-methods'), /POST/);
});
await t('API key and host allow-list', async () => {
  const keyed = { ...env, MAX_BYTES: '200000', API_KEY: 's3cret' };
  const path = '/api/scan?url=' + encodeURIComponent('https://example.com/guns.js');
  assert.equal((await call(path, undefined, keyed)).r.status, 401);
  assert.equal((await call(path, { headers: { 'x-api-key': 's3cret' } }, keyed)).r.status, 200);
  assert.equal((await call(path, { headers: { authorization: 'Bearer s3cret' } }, keyed)).r.status, 200);
  const listed = { ...env, ALLOWED_HOSTS: 'raw.githubusercontent.com,*.github.io' };
  assert.equal((await call(path, undefined, listed)).j.error.code, 'host_not_allowed');
});
console.log(`\n${n} test groups passed`);
