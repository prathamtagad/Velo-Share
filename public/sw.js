// Velo Service Worker - Offline Support & Asset Cache
// Scope-relative: all URLs are resolved against the SW's own scope, so the app
// works when deployed under a subpath (e.g. GitHub Pages /velo/).
const CACHE_NAME = 'velo-cache-v5';

// Relative asset paths, resolved against the service worker scope at install.
const ASSETS_TO_CACHE = [
    './',
    './app.html',
    './index.html',
    './about.html',
    './privacy.html',
    './terms.html',
    './css/style.css',
    './js/velo-config.js', // git-ignored deployment config: caching is best-effort
    './js/config.js',
    './js/theme.js',
    './js/velo-app.js',
    './vendor/peerjs-1.5.2.min.js',
    './vendor/qrcodejs-1.0.0.min.js',
    './manifest.json',
    './icons/icon-192.png',
    './icons/icon-512.png',
    './icons/icon-maskable-192.png',
    './icons/icon-maskable-512.png',
    './icons/app-icon.svg'
];

/** Resolves a relative asset path against this SW's scope. */
function scopeUrl(path) {
    return new URL(path, self.registration.scope).href;
}

// Install - Cache core assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(async (cache) => {
            // Add assets resiliently: one failure must not break the rest
            await Promise.all(ASSETS_TO_CACHE.map(async (asset) => {
                try {
                    await cache.add(scopeUrl(asset));
                } catch (e) {
                    console.warn('[SW] Failed to pre-cache:', asset, e);
                }
            }));
        })
    );
    self.skipWaiting();
});

// Activate - Clean up stale cache versions
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
            );
        })
    );
    self.clients.claim();
});

// Fetch - Network first, fallback to cache
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Skip non-GET requests
    if (event.request.method !== 'GET') return;

    // Never cache API / token endpoints (ephemeral TURN credentials, etc.)
    if (url.pathname.includes('/api/') || url.pathname.endsWith('/turn-credentials')) return;

    // Skip cross-origin requests entirely
    if (url.origin !== self.location.origin) return;

    event.respondWith(
        fetch(event.request)
            .then((response) => {
                // If valid response, clone and cache
                if (response && response.status === 200 && response.type === 'basic') {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(event.request, clone);
                    });
                }
                return response;
            })
            .catch(() => {
                return caches.match(event.request, { ignoreSearch: true });
            })
    );
});
