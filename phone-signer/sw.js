/**
 * CapAuth Bunker phone-signer — service worker (SPIKE).
 *
 * Minimal app-shell cache so the PWA is installable + works offline for the
 * key-management UI. The WebSocket relay obviously needs the network. We do NOT
 * cache OpenPGP.js from the CDN here (sovereignty follow-up: vendor it locally
 * and add it to the precache list).
 */
const CACHE = "capauth-bunker-v2";
const SHELL = [
  "./",
  "./index.html",
  "./app.js",
  "./manifest.webmanifest",
  "./lib/keyvault.js",
  "./lib/canonical.js",
  "./lib/bunker-signer.js",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  // Never intercept the relay WebSocket or cross-origin CDN requests.
  if (url.origin !== location.origin) return;
  // NETWORK-FIRST: always prefer the freshest code when online, fall back to the
  // cached shell only when offline. A previous cache-FIRST strategy meant any
  // deployed fix was masked by a stale precache until the cache name changed —
  // an active-development footgun. Cache is now an offline safety net only.
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy)).catch(() => {});
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
