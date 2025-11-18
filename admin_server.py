"""
Admin web UI (very small) to inspect cache and manage blocklist.
Runs on a separate port (8081 by default).
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse as up
import threading
from cache import ThreadSafeLRUCache
import filter_engine

# admin server will be created with a reference to the cache instance
class AdminHandler(BaseHTTPRequestHandler):
    cache: ThreadSafeLRUCache = None  # injected

    def do_GET(self):
        parsed = up.urlparse(self.path)
        if parsed.path == '/':
            self._send_dashboard()
        elif parsed.path == '/blocked':
            self._send_blocked()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')

    def do_POST(self):
        parsed = up.urlparse(self.path)
        length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(length).decode('utf-8') if length else ''
        form = up.parse_qs(body)
        if parsed.path == '/flush':
            self.cache.flush()
            self._redirect('/')
        elif parsed.path == '/blocked':
            domain = form.get('domain', [''])[0]
            if domain:
                filter_engine.add_blocked(domain)
            self._redirect('/blocked')
        elif parsed.path == '/blocked/delete':
            domain = form.get('domain', [''])[0]
            if domain:
                filter_engine.remove_blocked(domain)
            self._redirect('/blocked')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')

    def _redirect(self, path):
        self.send_response(303)
        self.send_header('Location', path)
        self.end_headers()

    def _send_dashboard(self):
        stats = self.cache.stats()
        html = f"""
        <html><head><title>Proxy Admin</title></head><body>
        <h1>Proxy Admin Dashboard</h1>
        <p>Cached items: {stats['items']}</p>
        <p>Total bytes (approx): {stats['total_bytes']}</p>
        <p>Max cache bytes: {stats['max_bytes']}</p>
        <form method="post" action="/flush">
            <button type="submit">Flush Cache</button>
        </form>
        <h2>Blocked domains</h2>
        <a href="/blocked">Manage blocked domains</a>
        </body></html>
        """
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def _send_blocked(self):
        items = sorted(filter_engine.blocked_domains)
        rows = ''.join(f"<tr><td>{i}</td><td><form method='post' action='/blocked/delete' style='display:inline'><input name='domain' value='{i}' hidden><button>Delete</button></form></td></tr>" for i in items)
        html = f"""
        <html><head><title>Blocked Domains</title></head><body>
        <h1>Blocked Domains</h1>
        <table border="1">
        <tr><th>Domain</th><th>Action</th></tr>
        {rows}
        </table>
        <h3>Add domain</h3>
        <form method="post" action="/blocked">
            <input name="domain" placeholder="example.com or .example.com (suffix match)">
            <button type="submit">Add</button>
        </form>
        <p><a href="/">Back</a></p>
        </body></html>
        """
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))


def run_admin_server(cache: ThreadSafeLRUCache, host='127.0.0.1', port=8081):
    AdminHandler.cache = cache
    server = HTTPServer((host, port), AdminHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True, name='AdminServerThread')
    t.start()
    print(f"[admin] Admin server running at http://{host}:{port}/")
    return server
