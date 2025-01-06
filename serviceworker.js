const staticCacheName = "static-cache-v1";
const dynamicCacheName = "dynamic-cache-v1";

// List of essential assets to cache for offline use
const assets = [
  "./manifest.json",
  "./",
  "./home.html", 
];

// Installing service worker and caching assets
self.addEventListener("install", (e) => {
  e.waitUntil(
    caches
      .open(staticCacheName)
      .then((cache) => cache.addAll(assets))
      .catch((err) => {
        console.log("❌ SW Installation Error", err);
      })
  );
  self.skipWaiting();
});

// Activating service worker and cleaning up old caches
self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((keys) => {
        return Promise.all(
          keys
            .filter((key) => key !== staticCacheName && key !== dynamicCacheName)
            .map((key) => caches.delete(key))
        );
      })
      .catch((err) => {
        console.log("❌ SW Activation Error", err);
      })
  );
});

// Fetching resources (both static and dynamic) and caching new dynamic content
self.addEventListener("fetch", (e) => {
  e.respondWith(
    caches
      .match(e.request)
      .then((cacheRes) => {
        return (
          cacheRes ||
          fetch(e.request)
            .then((fetchRes) => {
              // Cache dynamic content (API responses, search results, etc.)
              return caches.open(dynamicCacheName).then((cache) => {
                // Check if the request is for an API that retrieves product prices or comparisons
                if (e.request.url.indexOf("/api/") > -1) {
                  cache.put(e.request.url, fetchRes.clone());
                }
                return fetchRes;
              });
            })
            .catch((err) => {
              console.log("❌ SW Fetching Error", err);
              // Provide fallback for offline or network errors
              if (e.request.url.indexOf("/api/") > -1) {
                return new Response(JSON.stringify({ message: "Offline - unable to fetch data" }), {
                  headers: { "Content-Type": "application/json" },
                });
              }

              // Return a cached home page or fallback page
              return caches.match("./home.html");
            })
        );
      })
  );
});
