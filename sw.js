// TutiKuti admin: notifications only. No caching, so the app is
// always the latest version from GitHub Pages.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = { body: e.data && e.data.text() }; }
  e.waitUntil(self.registration.showNotification(d.title || "TutiKuti", {
    body: d.body || 'New online order',
    tag: d.tag || 'order',
    renotify: true,
    requireInteraction: true,
    vibrate: [200, 100, 200, 100, 300],
    icon: 'icon-192.png',
    badge: 'icon-192.png',
    data: { url: d.url || '/', ref: d.tag },
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const ref = e.notification.data && e.notification.data.ref;
  const url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const w of wins) {
      if (new URL(w.url).origin === self.location.origin) {
        await w.focus();
        if (ref) w.postMessage({ tkOrder: ref });
        return;
      }
    }
    await self.clients.openWindow(url);
  })());
});
