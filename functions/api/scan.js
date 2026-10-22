// Cloudflare Pages Function -> served at /api/scan (GET ?url=..., POST {url} | {source}).
import { handleScan } from '../../src/handler.js';

export async function onRequest(context) {
  return handleScan(context.request, context.env, { waitUntil: context.waitUntil.bind(context) });
}
