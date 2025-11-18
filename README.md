## 🚀 Multithreaded Proxy Web Server

Operating System Mini Project – Caching • Filtering • Ad-Blocking • Admin UI

This project implements a Multithreaded HTTP Proxy Server with:
```
Thread Pooling

LRU Caching

Domain Blocking

Ad-Blocking

HTTP/HTTPS Support (CONNECT tunneling)

Admin Web Dashboard

This proxy sits between a client (browser) and the internet, filtering/caching requests while providing an admin interface to control behavior in real-time.
```
## ⭐ Key Features
```
✔ 1. Multithreaded Proxy

Handles multiple clients simultaneously using ThreadPoolExecutor.

✔ 2. Thread-Safe LRU Cache

Stores frequently accessed HTTP responses

Reduces bandwidth and improves speed

Honors HTTP rules (Cache-Control, no-store, max-age, vary headers)

Prevents caching huge responses (limit: 5 MB)

✔ 3. Domain Blocking

Block any website/domain via the Admin Panel, e.g.:

example.com


Proxy instantly denies the request with 403 Forbidden.

✔ 4. HTTPS Ad-Blocking (without MITM)

Even though HTTPS traffic is encrypted, ad domains can still be blocked by intercepting the CONNECT method.

This means:

✔ Normal HTTPS websites load
✔ But HTTPS ads fail to connect → ads disappear
✔ No certificate installation or MITM required

✔ 5. Admin Web Dashboard

Available at:

http://127.0.0.1:8081/


Allows:

View cache statistics

Add/remove blocked domains

Add/remove ad domains

Clear cache

Live status monitoring

✔ 6. Real-Time Logging

Proxy prints:

Incoming requests

Cache HIT / MISS

Blocked domains

CONNECT requests

Upstream/downstream headers (debug)
```
## 🧱 Project Architecture
<pre>
┌────────────────────────┐        ┌────────────────────────┐
│         Client         │        │       Admin Panel       │
│  Browser / Curl / App  │        │  http://127.0.0.1:8081  │
└───────────┬────────────┘        └──────────────┬─────────┘
            │                                     │
            ▼                                     │
      ┌──────────────┐     Admin Commands         │
      │ Proxy Server │ <──────────────────────────┘
      │  ThreadPool  │
      └───────┬──────┘
              │
              ▼
     ┌──────────────────┐
     │ Filtering Engine │  Blocked / Ad domains
     └──────────────────┘
              │
              ▼
       ┌────────────┐
       │   Cache     │  (LRU, TTL)
       └────────────┘
              │
              ▼
       ┌────────────┐
       │ Origin Web │
       │   Server   │
       └────────────┘
</pre>
## 📦 Folder Structure
<pre>
project/
│
├── server.py               # Main proxy server
├── admin_server.py         # Dashboard
├── cache.py                # LRU Cache implementation
├── filter_engine.py        # Blocked + Ad domain logic
│
└── data/
    ├── blocked_domains.txt
    └── ad_domains.txt
</pre>
## ▶️ Running the Project
```
1. Install dependencies (Python 3.x)
pip install flask

2. Run the proxy server
python server.py


You should see:

[admin] Admin server running at http://127.0.0.1:8081/
[proxy] Listening on 127.0.0.1:8888 ...

## 🌐 Configuring Browser to Use Proxy
Windows (Chrome / Edge / System)

Open Windows Proxy Settings

Turn ON: Use a proxy server

Set:

Address: 127.0.0.1

Port: 8888

Save.

Firefox (independent proxy config)
Settings → Network → Manual Proxy
HTTP Proxy: 127.0.0.1
Port: 8888
Check: Use proxy for all protocols


Now all HTTP/HTTPS traffic goes through your proxy.
```
## 🛠️ Admin Panel Usage
```
Visit:

http://127.0.0.1:8081/

Features:

✔ Add blocked domains
✔ Add ad-block domains
✔ Clear cache
✔ See cache size + entries
✔ Status page
```
## 🎯 Demo Scenarios (For Viva Presentation)
```
1. HTTP Caching Demo
Step 1

Visit:

http://example.com


Logs:

[cache] MISS GET example.com:80 /

Step 2

Refresh the page

Logs:

[cache] HIT GET example.com:80 /


✔ Shows caching is working

2. Domain Blocking Demo
Step 1

Open Admin Panel → Blocked Domains → Add:

example.com

Step 2

Again visit:

http://example.com/


Output:

403 Forbidden


Logs:

[proxy] BLOCKED example.com


✔ Domain blocking works

3. Ad-Blocking Demo (BEST SHOWCASE)
Step 1 — Add real ad domains

In Admin Panel → Add:

googleads.g.doubleclick.net
pagead2.googlesyndication.com
adservice.google.com

Step 2 — Visit any ad-heavy site:
http://www.cricbuzz.com/

Step 3 — Observe:

Ads disappear from the page

Logs show:

[proxy] CONNECT to pagead2.googlesyndication.com:443
[proxy] BLOCKED CONNECT to pagead2.googlesyndication.com (ad)


✔ HTTPS ads blocked BEFORE TLS handshake
✔ Normal HTTPS website still loads
✔ Perfect demo
```
## ⚠️ Limitations
```
1. HTTPS content itself is not cached or inspected

The proxy only tunnels HTTPS without MITM.

2. Cache works only for HTTP URLs

Because HTTPS data is encrypted.

3. No content rewriting (by design)

Proxy blocks entire domains, not partial page elements.

4. System proxy must be enabled for browser demo

Otherwise browser bypasses the proxy.
```
## 🚀 Future Enhancements (Optional)
```

Full HTTPS inspection with MITM (certificate installation required)

Auto-update ad-list from public sources (EasyList)

Detailed analytics dashboard

Cache persistence across restarts

Rate limiting per client

Compression/Decompression support
```
## 👨‍💻 Authors
```
Mayank Bhatt
Ankit Bhandari
Akhil Badoni
Divyansh Chauhan
```
Operating System PBL Project

Multithreaded Proxy Server (Python)#

