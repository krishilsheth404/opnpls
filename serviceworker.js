var staticCacheName = "pwa-v1";

self.addEventListener("install", function (e) {
    console.log("Service Worker installing...");

    e.waitUntil(
        caches.open(staticCacheName).then(function (cache) {
            console.log("Caching static assets...");
            return cache.addAll([
                '/', // Cache the root of the application
                '/home.html', // Add specific files you want to cache
            ]);
        })
    );
});

self.addEventListener("fetch", function (event) {
    console.log("Fetching:", event.request.url);

    event.respondWith(
        caches.match(event.request).then(function (response) {
            // Serve the cached file if available, otherwise fetch from network
            return response || fetch(event.request);
        })
    );
});

self.addEventListener("activate", function (e) {
    console.log("Service Worker activating...");

    e.waitUntil(
        caches.keys().then(function (cacheNames) {
            return Promise.all(
                cacheNames.map(function (cache) {
                    if (cache !== staticCacheName) {
                        console.log("Deleting old cache:", cache);
                        return caches.delete(cache);
                    }
                })
            );
        })
    );
});
