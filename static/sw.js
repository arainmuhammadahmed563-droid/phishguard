const CACHE='phishguard-v1';
const SHELL=['/static/style.css','/static/icons/icon-192.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL)));self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==CACHE).map(x=>caches.delete(x)))));self.clients.claim()});
self.addEventListener('fetch',e=>{
  const r=e.request;
  if(r.method!=='GET'||new URL(r.url).pathname.startsWith('/api/'))return; // API always live
  e.respondWith(fetch(r).then(res=>{if(new URL(r.url).pathname.startsWith('/static/')){const cp=res.clone();caches.open(CACHE).then(c=>c.put(r,cp))}return res})
    .catch(()=>caches.match(r).then(m=>m||new Response('<h2 style="font-family:sans-serif;padding:20px">Offline. Internet on karein.</h2>',{headers:{'Content-Type':'text/html'}}))));
});
