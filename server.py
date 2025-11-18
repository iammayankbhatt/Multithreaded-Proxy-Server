#!/usr/bin/env python3
"""
Main proxy server implementing:
- Threaded HTTP proxy using ThreadPoolExecutor
- Thread-safe LRU cache integration
- Content filter (domain blocking + ad-block domains)
- CONNECT tunneling for HTTPS (no MITM) (configurable)
- Admin UI (admin_server.py) to manage cache and blocks
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import sys
import signal
from http.client import HTTPConnection, HTTPResponse
from urllib.parse import urlsplit, urlunsplit
import time

from cache import ThreadSafeLRUCache
import filter_engine
from admin_server import run_admin_server

LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 8888
MAX_WORKERS = 32
CACHE_MAX_BYTES = 20 * 1024 * 1024  # 20 MB
DEFAULT_TTL = 60  # seconds default if none provided
# maximum response size to cache (bytes) — avoid caching huge responses
MAX_CACHE_OBJECT_BYTES = 5 * 1024 * 1024  # 5 MB

# Toggle whether CONNECT (HTTPS tunneling) is allowed.
# Set to False to enforce HTTP-only proxy (CONNECT rejected with 403).
ENABLE_CONNECT = True

class ProxyServer:
    def __init__(self, host=LISTEN_HOST, port=LISTEN_PORT, max_workers=MAX_WORKERS):
        self.host = host
        self.port = port
        self.cache = ThreadSafeLRUCache(max_bytes=CACHE_MAX_BYTES)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.shutdown_event = threading.Event()

    def start(self):
        # start admin UI
        self.admin = run_admin_server(self.cache, host='127.0.0.1', port=8081)

        # start main socket listener
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(200)
        print(f"[proxy] Listening on {self.host}:{self.port} ...")
        try:
            while not self.shutdown_event.is_set():
                try:
                    client_conn, client_addr = sock.accept()
                except OSError:
                    break
                print(f"[proxy] Accepted connection from {client_addr}")
                self.executor.submit(self.handle_client, client_conn, client_addr)
        except KeyboardInterrupt:
            print("Shutting down due to keyboard interrupt.")
        finally:
            self.shutdown()

    def shutdown(self):
        print("[proxy] shutting down...")
        self.shutdown_event.set()
        self.executor.shutdown(wait=False)
        try:
            self.admin.shutdown()
        except Exception:
            pass

    def handle_client(self, client_conn: socket.socket, client_addr):
        client_conn.settimeout(10)
        try:
            data = self._recv_until_double_crlf(client_conn)
            if not data:
                client_conn.close()
                return
            request_line, headers, body = self._parse_http_request(data)
            if not request_line:
                client_conn.close()
                return
            method, target, version = request_line.split(' ', 2)
            target = target.strip()
            if method.upper() == 'CONNECT':
                if not ENABLE_CONNECT:
                    self._reject_connect(client_conn, target, client_addr)
                else:
                    self._handle_connect(client_conn, target, client_addr)
            else:
                self._handle_http_method(client_conn, method.upper(), target, version, headers, body)
        except Exception as e:
            print("[proxy] Error handling client:", e)
        finally:
            try:
                client_conn.close()
            except Exception:
                pass

    def _recv_until_double_crlf(self, conn: socket.socket):
        data = b''
        while b'\r\n\r\n' not in data:
            part = conn.recv(4096)
            if not part:
                break
            data += part
            if len(data) > 65536:
                break
        return data

    def _parse_http_request(self, raw: bytes):
        try:
            s = raw.decode('iso-8859-1')
            head, _, rest = s.partition('\r\n\r\n')
            lines = head.split('\r\n')
            request_line = lines[0]
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip().lower()] = v.strip()
            body = rest.encode('iso-8859-1')
            return request_line, headers, body
        except Exception:
            return None, None, None

    def _reject_connect(self, client_conn: socket.socket, target, client_addr):
        # explicit rejection for HTTP-only mode
        print(f"[proxy] REJECT CONNECT to {target} from {client_addr} (HTTP-only mode)")
        resp = ("HTTP/1.1 403 Forbidden\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 61\r\n"
                "Connection: close\r\n"
                "\r\n"
                "403 Forbidden: This proxy only supports HTTP (no CONNECT/HTTPS).\n")
        try:
            client_conn.sendall(resp.encode('utf-8'))
        except Exception:
            pass

    
        # original tunneling behavior
    def _handle_connect(self, client_conn: socket.socket, target, client_addr):
        # target is host:port
        host = target.split(':', 1)[0]
        print(f"[proxy] CONNECT to {target} from {client_addr}")
        if filter_engine.is_blocked_host(host) or filter_engine.is_ad_host(host):
            # log the block clearly and return 403
            print(f"[proxy] BLOCKED CONNECT to {host} (ad/blocklist match) from {client_addr}")
            resp = ("HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 11\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "Forbidden\n")
            try:
                client_conn.sendall(resp.encode('utf-8'))
            except Exception:
                pass
            return
        

        # establish tcp tunnel
        try:
            remote = socket.create_connection((host, int(target.split(':',1)[1])), timeout=10)
        except Exception:
            try:
                client_conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception:
                pass
            return
        # send 200 Connection established
        try:
            client_conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except Exception:
            pass
        # now relay data both ways
        self._tunnel(client_conn, remote)

    def _tunnel(self, a: socket.socket, b: socket.socket):
        # simple bi-directional relay using threads
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
        t1 = threading.Thread(target=forward, args=(a,b), daemon=True)
        t2 = threading.Thread(target=forward, args=(b,a), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()

    def _handle_http_method(self, client_conn, method, target, version, headers, body):
        # target might be absolute URL or path. If absolute, parse host from it.
        parsed = urlsplit(target)
        if parsed.scheme:
            host = parsed.hostname
            port = parsed.port or (80 if parsed.scheme == 'http' else 80)
            path = urlunsplit(('', '', parsed.path or '/', parsed.query or '', ''))
        else:
            # relative path; Host header required
            host_header = headers.get('host', '')
            host = host_header.split(':',1)[0]
            port = int(host_header.split(':',1)[1]) if ':' in host_header else 80
            path = target

        # block checks
        if filter_engine.is_blocked_host(host):
            try:
                client_conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nForbidden\n")
            except Exception:
                pass
            return
        if filter_engine.is_ad_host(host):
            try:
                client_conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nBlocked (ad)\n")
            except Exception:
                pass
            return

        cache_key = f"{method} {host}:{port} {path}"
        # only cache GET
        if method == 'GET':
            cached = self.cache.get(cache_key)
            if cached:
                print("[cache] HIT", cache_key)
                self._send_cached_response(client_conn, cached)
                return
            else:
                print("[cache] MISS", cache_key)

        # forward to origin server using HTTPConnection
        try:
            conn = HTTPConnection(host, port, timeout=10)

            # rebuild headers, remove hop-by-hop headers, sanitize values
            send_headers = {}
            for k, v in headers.items():
                if k.lower() in ('proxy-Connection','proxy-connection','connection','keep-alive','transfer-encoding','te','proxy-authenticate','proxy-authorization','upgrade'):
                    continue
                # sanitize header values (strip CR/LF and surrounding whitespace)
                safe_val = v.replace('\r', ' ').replace('\n', ' ').strip()
                header_name = k if k.lower() not in ('host',) else 'Host'
                send_headers[header_name] = safe_val

            # Ensure exactly one Host header (remove duplicates) and set correct host[:port]
            send_headers.pop('host', None)
            send_headers.pop('Host', None)

            host_header = headers.get('host', '').strip()
            if host_header:
                send_headers['Host'] = host_header
            else:
                if port and port != 80:
                    send_headers['Host'] = f"{host}:{port}"
                else:
                    send_headers['Host'] = host

            # DEBUG: log outgoing request (useful for diagnosing 400 responses)
            print(f"[upstream] {method} {path} -> {host}:{port}")
            for hk, hv in send_headers.items():
                print(f"[upstream-header] {hk}: {hv}")

            conn.request(method, path, body if body else None, headers=send_headers)

            resp: HTTPResponse = conn.getresponse()
            status = resp.status
            reason = resp.reason
            resp_headers = resp.getheaders()

            # read full body (be careful: large responses can be big)
            body_bytes = resp.read()

            # --------- DEBUG: log response headers (helps diagnose misses) ----------
            print(f"[downstream] {host}:{port} {path} -> {status} {reason}")
            for hk, hv in resp_headers:
                print(f"[downstream-header] {hk}: {hv}")

            # sanitize Content-Length header values if present (remove commas)
            sanitized_headers = []
            for k, v in resp_headers:
                if k.lower() == 'content-length':
                    v = v.replace(',', '').strip()
                sanitized_headers.append((k, v))

            # build response bytes to send back to client (skip hop-by-hop headers)
            status_line = f"HTTP/1.1 {status} {reason}\r\n"
            headers_buf = ''
            for k, v in sanitized_headers:
                if k.lower() in ('connection','keep-alive','proxy-authenticate','proxy-authorization','transfer-encoding','te','upgrade'):
                    continue
                headers_buf += f"{k}: {v}\r\n"
            full_resp = status_line + headers_buf + f"Content-Length: {len(body_bytes)}\r\n\r\n"
            client_conn.sendall(full_resp.encode('iso-8859-1') + body_bytes)

            # ------------------ decide caching --------------------
            # only for GET + 200 OK
            if method == 'GET' and status == 200:
                # read Cache-Control header (if any)
                cc = None
                vary = None
                tcn = None
                for (hk, hv) in sanitized_headers:
                    lk = hk.lower()
                    if lk == 'cache-control':
                        cc = hv
                    elif lk == 'vary':
                        vary = hv
                    elif lk == 'tcn':
                        tcn = hv

                # if origin says no-store -> don't cache
                if cc and 'no-store' in cc.lower():
                    cacheable = False
                else:
                    cacheable = True

                # if server indicates multiple choices or content negotiation that isn't safe,
                # be conservative and don't cache
                if tcn and tcn.lower() == 'choice':
                    cacheable = False
                if vary and '*' in vary:
                    cacheable = False

                # enforce object size limit and non-empty body
                body_len = len(body_bytes)
                if body_len == 0 or body_len > MAX_CACHE_OBJECT_BYTES:
                    cacheable = False

                if cacheable:
                    # determine TTL from max-age, else fallback to DEFAULT_TTL
                    ttl = None
                    if cc and 'max-age' in cc:
                        try:
                            parts = [p.strip() for p in cc.split(',')]
                            for p in parts:
                                if p.startswith('max-age'):
                                    ttl = int(p.split('=',1)[1])
                                    break
                        except Exception:
                            ttl = None
                    if ttl is None:
                        ttl = DEFAULT_TTL

                    # Build vary suffix *generically*: include the client header values
                    vary_suffix = ''
                    if vary:
                        try:
                            vary_fields = [v.strip() for v in vary.split(',') if v.strip()]
                        except Exception:
                            vary_fields = []
                        parts = []
                        for field in vary_fields:
                            field_l = field.lower()
                            client_val = headers.get(field_l, '')
                            client_val_norm = client_val.replace('\r',' ').replace('\n',' ').strip()
                            if 'gzip' in client_val_norm:
                                token = 'gzip'
                            elif 'deflate' in client_val_norm:
                                token = 'deflate'
                            elif client_val_norm == '':
                                token = 'none'
                            else:
                                token = client_val_norm.replace(' ', '_')
                            parts.append(f"{field_l}={token}")
                        if parts:
                            vary_suffix = " VARY:" + "|".join(parts)

                    cache_entry = {
                        'status': status,
                        'reason': reason,
                        'headers': sanitized_headers,
                        'body': body_bytes
                    }
                    cache_key_final = cache_key + vary_suffix
                    print(f"[cache-put] key={cache_key_final!r} size={body_len} ttl={ttl}s")
                    self.cache.put(cache_key_final, cache_entry, ttl)

        except Exception as e:
            print("[proxy] error fetching origin:", e)
            try:
                client_conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception:
                pass

    def _send_cached_response(self, client_conn: socket.socket, cached):
        status = cached.get('status', 200)
        reason = cached.get('reason', 'OK')
        headers = cached.get('headers', [])
        body = cached.get('body', b'')
        status_line = f"HTTP/1.1 {status} {reason}\r\n"
        headers_buf = ''
        for k,v in headers:
            if k.lower() in ('connection','keep-alive','proxy-authenticate','proxy-authorization','transfer-encoding','te','upgrade'):
                continue
            headers_buf += f"{k}: {v}\r\n"
        resp = status_line + headers_buf + f"Content-Length: {len(body)}\r\n\r\n"
        try:
            client_conn.sendall(resp.encode('iso-8859-1') + body)
        except Exception:
            pass


if __name__ == '__main__':
    proxy = ProxyServer(host=LISTEN_HOST, port=LISTEN_PORT, max_workers=MAX_WORKERS)
    def sigint_handler(sig, frame):
        proxy.shutdown()
        sys.exit(0)
    signal.signal(signal.SIGINT, sigint_handler)
    proxy.start()
