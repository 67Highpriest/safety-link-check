self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open('priest-link-checker').then((cache) => {
      return cache.addAll([
        'index.html',
        'styles.css',
        'script.js',
        'manifest.json',
        'images/icon-195.png',
        'images/icon-517.png'
      ]);
    })
  );
});

self.addEventListener('fetch', (e) => {
  e.respondWith(
    caches.match(e.request).then((response) => {
      return response || fetch(e.request);
    })
  );
});