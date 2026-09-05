// Velo Service Worker - Offline Support & Asset Cache
const CACHE_NAME = 'velo-cache-v3';
const ASSETS_TO_CACHE = [
    '/',
    '/app.html',
    '/index.html',
    '/css/style.css',
    '/js/config.js',
    '/js/theme.js',
    '/js/velo-app.js',
    '/manifest.json'
];

// Install - Cache core assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(async (cache) => {
            // Add assets resiliently
            for (const asset of ASSETS_TO_CACHE) {
                try {
                    await cache.add(asset);
                } catch (e) {
                    console.warn('[SW] Failed to pre-cache:', asset, e);
                }
            }
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
    // Skip non-GET requests
    if (event.request.method !== 'GET') return;

    // Skip external requests (like PeerJS CDN or external QR scripts)
    if (!event.request.url.startsWith(self.location.origin)) return;

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
                return caches.match(event.request);
            })
    );
});
