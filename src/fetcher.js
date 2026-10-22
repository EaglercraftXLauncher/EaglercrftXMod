// Safe remote source fetching for the scan API: URL validation (SSRF guard), manual redirects,
// timeout, streaming size cap and "is this actually JavaScript?" checks.

export class ApiError extends Error {
  constructor(code, message, status = 400, extra = {}) {
    super(message);
    this.code = code;
    this.status = status;
    this.extra = extra;
  }
}

const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.lan', '.home', '.corp', '.intranet'];

function isPrivateIPv4(h) {
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

/** Throws ApiError if the URL must not be fetched. Returns the parsed URL. */
export function assertFetchable(input, env = {}) {
  let u;
  try { u = new URL(input); } catch { throw new ApiError('invalid_url', 'The url parameter is not a valid absolute URL.', 400); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new ApiError('invalid_url', 'Only http(s) URLs are supported.', 400);
  if (u.username || u.password) throw new ApiError('invalid_url', 'URLs with embedded credentials are not allowed.', 400);
  if (u.port && u.port !== '80' && u.port !== '443') throw new ApiError('blocked_host', 'Only the default http/https ports are allowed.', 403);
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  const ipv6 = host.startsWith('[') || host.includes(':');
  const single = !host.includes('.');
  if (ipv6 || single || host === 'localhost' || BLOCKED_SUFFIXES.some((s) => host.endsWith(s)) || isPrivateIPv4(host)) {
    throw new ApiError('blocked_host', 'That host is not allowed (local, private or IPv6-literal addresses are blocked).', 403);
  }
  const allow = String(env.ALLOWED_HOSTS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (allow.length && !allow.some((p) => (p.startsWith('*.') ? host === p.slice(2) || host.endsWith(p.slice(1)) : host === p))) {
    throw new ApiError('host_not_allowed', 'This API instance only scans mods from approved hosts.', 403);
  }
  return u;
}

/** github.com/<u>/<r>/blob/<ref>/<path> -> raw.githubusercontent.com/<u>/<r>/<ref>/<path> */
export function normalizeModUrl(u) {
  if (u.hostname === 'github.com' || u.hostname === 'www.github.com') {
    const m = u.pathname.match(/^\/([^/]+)\/([^/]+)\/(?:blob|raw)\/(.+)$/);
    if (m) return new URL(`https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}${u.search}`);
  }
  if (u.hostname === 'gist.github.com') {
    const m = u.pathname.match(/^\/([^/]+)\/([0-9a-f]+)\/?$/i);
    if (m) throw new ApiError('use_raw_url', 'Gist page URLs are not supported; use the "Raw" link of the file.', 400);
  }
  return u;
}

function concat(chunks, total) {
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.byteLength; }
  return out;
}

export async function fetchSource(rawUrl, env = {}, fetchImpl = fetch) {
  const maxBytes = Number(env.MAX_BYTES) || 2 * 1024 * 1024;
  const timeoutMs = Number(env.FETCH_TIMEOUT_MS) || 10000;
  let url = normalizeModUrl(assertFetchable(rawUrl, env));
  assertFetchable(url.toString(), env);

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    let res;
    for (let hop = 0; ; hop++) {
      try {
        res = await fetchImpl(url.toString(), {
          redirect: 'manual',
          signal: ac.signal,
          headers: { 'user-agent': 'EaglerScan/1 (+static mod analyzer)', accept: 'text/javascript, application/javascript, text/plain, */*;q=0.5' },
        });
      } catch (e) {
        if (ac.signal.aborted) throw new ApiError('timeout', `Fetching the mod took longer than ${timeoutMs} ms.`, 504);
        throw new ApiError('fetch_failed', 'Could not reach the mod URL.', 502);
      }
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const loc = res.headers.get('location');
        if (!loc) throw new ApiError('fetch_failed', 'Redirect without a Location header.', 502);
        if (hop >= 3) throw new ApiError('too_many_redirects', 'The mod URL redirected too many times.', 502);
        url = normalizeModUrl(assertFetchable(new URL(loc, url).toString(), env)); // re-validate every hop
        continue;
      }
      break;
    }
    if (!res.ok) throw new ApiError('upstream_error', `The mod host answered HTTP ${res.status}.`, res.status === 404 ? 404 : 502, { upstreamStatus: res.status });

    const ct = (res.headers.get('content-type') || '').toLowerCase();
    if (/^(image|video|audio)\//.test(ct) || /(zip|java-archive|octet-stream)/.test(ct) && /\.(zip|jar|class)(\?|$)/i.test(url.pathname)) {
      throw new ApiError('unsupported_type', 'Only JavaScript source files can be scanned (got ' + ct.split(';')[0] + ').', 415);
    }
    const declared = Number(res.headers.get('content-length'));
    if (declared && declared > maxBytes) throw new ApiError('too_large', `The file is larger than the ${maxBytes} byte limit.`, 413);

    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      let r;
      try { r = await reader.read(); } catch { throw new ApiError(ac.signal.aborted ? 'timeout' : 'fetch_failed', ac.signal.aborted ? `Fetching the mod took longer than ${timeoutMs} ms.` : 'The connection to the mod host failed.', ac.signal.aborted ? 504 : 502); }
      if (r.done) break;
      total += r.value.byteLength;
      if (total > maxBytes) { try { await reader.cancel(); } catch {} throw new ApiError('too_large', `The file is larger than the ${maxBytes} byte limit.`, 413); }
      chunks.push(r.value);
    }
    const bytes = concat(chunks, total);
    if (bytes.subarray(0, 2048).includes(0)) throw new ApiError('unsupported_type', 'The file looks binary, not JavaScript source.', 415);
    let text = new TextDecoder('utf-8').decode(bytes);
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    if (ct.includes('text/html') || /^\s*<(?:!doctype\s+html|html[\s>])/i.test(text)) {
      throw new ApiError('not_javascript', 'The URL returned an HTML page, not a script. Use the raw file URL (for GitHub: the "Raw" button).', 415);
    }
    return { text, bytes: total, bytesRaw: bytes, finalUrl: url.toString(), contentType: ct.split(';')[0] || null };
  } finally {
    clearTimeout(timer);
  }
}
