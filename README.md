# EaglerScan API

Static mod analysis as a REST API on **Cloudflare Pages Functions**. Give it a mod URL, get the full scan as JSON:
versions, dependencies (including `Requires X` from descriptions), bundled assets (AsyncSink etc.), remote hosts,
compatibility warnings, metadata and evidence. Nothing in the mod is ever executed.

```
public/index.html      the EaglerScan web UI (local-only scanning, same engine)
functions/api/scan.js  route  ->  /api/scan
src/analyzer.js        the analysis engine (pure ES module, no DOM)
src/fetcher.js         safe remote fetch (SSRF guard, redirects, size/time limits)
src/handler.js         request handling, JSON shape, caching, auth
test/run.mjs           offline tests (npm test)
```
## Use

```bash
# scan a mod by URL
curl "https://https://eaglercraftxmod.pages.dev/api/scanurl=https://raw.githubusercontent.com/user/repo/main/mod.js"

# GitHub "blob" page URLs are rewritten to raw automatically
curl "https://eaglercraftxmod.pages.dev/api/scan?url=https://github.com/user/repo/blob/main/mod.js&pretty"

# POST a URL, raw source, or JSON source
curl -X POST .../api/scan -H 'content-type: application/json' -d '{"url":"https://example.com/mod.js"}'
curl -X POST ".../api/scan?name=mod.js" -H 'content-type: text/javascript' --data-binary @mod.js
curl -X POST .../api/scan -H 'content-type: application/json' -d '{"source":"...","name":"mod.js"}'
```

| Parameter | Meaning |
|---|---|
| `url` | Mod location (http/https). GET query or POST JSON. |
| `name` | Display name override. |
| `fields` | Comma list to trim `report`: `versions,dependencies,assets,warnings,metadata,findings`. |
| `pretty` | Pretty-print the JSON. |

### Response (`schemaVersion: 1`)

See `examples/sample-response.json` for a real one.

```
{
  ok, schemaVersion, scanner, generatedAt,
  input:   { url, resolvedUrl, name, bytes, lines, sha256, contentType },
  summary: { versions, dependencies, likelyRequired[], remoteHosts[], assets{total,embedded,remote,relative,runtime}, warnings{total,high,medium,low} },
  report:  { versions[], dependencies[], assets[], warnings[], metadata[], findings[] }
}
```

Errors are `{ "ok": false, "error": { "code", "message" } }` with matching HTTP status:
`invalid_url` 400, `missing_url` 400, `invalid_json` 400, `unauthorized` 401, `blocked_host` / `host_not_allowed` 403,
`upstream_error` 404/502, `too_large` 413, `not_javascript` / `unsupported_type` 415, `fetch_failed` / `too_many_redirects` 502, `timeout` 504.

## Configuration (`wrangler.jsonc` vars, or the Pages dashboard)

| Variable | Default | Purpose |
|---|---|---|
| `MAX_BYTES` | 2097152 | Max mod size (fetched or posted). |
| `FETCH_TIMEOUT_MS` | 10000 | Timeout for fetching the mod. |
| `CACHE_TTL` | 300 | Seconds to cache GET results (0 disables). |
| `ALLOWED_HOSTS` | (any public host) | e.g. `raw.githubusercontent.com,*.github.io` to lock the API down. |
| `API_KEY` | (none) | If set, require `x-api-key` or `Authorization: Bearer`. Set it as a **secret**, not in the file. |
| `ALLOWED_ORIGIN` | `*` | CORS origin. |

## Security notes

- The fetcher only allows http(s) on ports 80/443, rejects credentials in URLs, localhost/private/link-local/IPv6-literal hosts,
  re-validates every redirect (max 3), and streams with a hard size cap.
- A public endpoint can be abused. Add a Cloudflare **rate limiting rule** for `/api/*` and consider `API_KEY` or `ALLOWED_HOSTS`.
- Scanning is static: results are heuristics, not proof of compatibility.

## CPU limits

Workers **Free** allows 10 ms CPU per request; **Paid** allows 30 s by default (up to 5 min). Typical mods (tens of KB)
take a few ms warm, but the first request in a fresh isolate and files with large embedded assets cost more
(a 1.5 MB file with an embedded texture took ~50 ms locally). If you see "Exceeded CPU Time Limits", use the Paid plan
or lower `MAX_BYTES`.

## Extending

Recognize another asset-registering library by adding an entry to `ASSET_SINKS` in `src/analyzer.js`
(call-name regex + owner). Its calls then appear under `assets` instead of as network warnings.
