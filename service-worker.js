
self.addEventListener('install', (event) => {
    event.waitUntil(
      caches.open('openpills-cache').then((cache) => {
        return cache.addAll([
          '/',
          '/index.html',
          '/index.js',
          '/icon.png',
          // Add more static assets here as needed
        ]);
      })
    );
  });
  
  self.addEventListener('fetch', (event) => {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        return cachedResponse || fetch(event.request);
      })
    );
  });
  