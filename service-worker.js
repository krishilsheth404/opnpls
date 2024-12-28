self.addEventListener('install', (event) => {
    // No caching, just skip waiting and let the service worker activate immediately
    self.skipWaiting();
  });
  
  self.addEventListener('fetch', (event) => {
    event.respondWith(
      fetch(event.request)
        .catch((error) => {
          console.error('Failed to fetch:', error);
          return new Response('Offline or failed to fetch.', { status: 500 });
        })
    );
  });
  