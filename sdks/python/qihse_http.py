"""QIHSE HTTP/REST Python SDK.

Provides a requests-compatible API for QIHSE's HTTP server.
"""
import socket
import json as json_module
import urllib.parse

class Error(Exception):
    pass

class ConnectionError(Error):
    pass

class Timeout(Error):
    pass

class HTTPError(Error):
    def __init__(self, message, status_code=None, response=None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class Response:
    """requests-compatible Response object."""
    def __init__(self, status_code=200, content=b'', headers=None, url=None):
        self.status_code = status_code
        self._content = content
        self.headers = headers or {}
        self.url = url
        self.encoding = 'utf-8'
    
    @property
    def content(self):
        return self._content
    
    @property
    def text(self):
        return self._content.decode(self.encoding) if self._content else ''
    
    def json(self):
        return json_module.loads(self.text) if self.text else {}
    
    @property
    def ok(self):
        return self.status_code < 400
    
    def raise_for_status(self):
        if self.status_code >= 400:
            raise HTTPError(f"HTTP {self.status_code}", status_code=self.status_code, response=self)
    
    def __repr__(self):
        return f"<Response [{self.status_code}]>"


class Session:
    """requests-compatible Session."""
    def __init__(self):
        self.headers = {}
        self.auth = None
        self.timeout = 30
        self._closed = False
    
    def request(self, method, url, **kwargs):
        return _do_request(method, url, **kwargs)
    
    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)
    
    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)
    
    def put(self, url, **kwargs):
        return self.request('PUT', url, **kwargs)
    
    def delete(self, url, **kwargs):
        return self.request('DELETE', url, **kwargs)
    
    def patch(self, url, **kwargs):
        return self.request('PATCH', url, **kwargs)
    
    def head(self, url, **kwargs):
        return self.request('HEAD', url, **kwargs)
    
    def close(self):
        self._closed = True
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def _do_request(method, url, **kwargs):
    """Execute an HTTP request."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or 'localhost'
    port = parsed.port or 80
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    
    headers = kwargs.get('headers', {})
    params = kwargs.get('params')
    if params:
        qs = urllib.parse.urlencode(params)
        path += ('&' if '?' in path else '?') + qs
    
    json_data = kwargs.get('json')
    data = kwargs.get('data')
    
    body = b''
    content_type = ''
    if json_data is not None:
        body = json_module.dumps(json_data).encode('utf-8')
        content_type = 'application/json'
    elif data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode('utf-8')
            content_type = 'application/x-www-form-urlencoded'
        elif isinstance(data, str):
            body = data.encode('utf-8')
            content_type = 'text/plain'
        elif isinstance(data, bytes):
            body = data
    
    # Build HTTP request
    req_lines = [f"{method.upper()} {path} HTTP/1.1"]
    req_lines.append(f"Host: {host}:{port}")
    if content_type:
        req_lines.append(f"Content-Type: {content_type}")
    req_lines.append(f"Content-Length: {len(body)}")
    req_lines.append("Connection: close")
    for k, v in headers.items():
        req_lines.append(f"{k}: {v}")
    req_lines.append("")
    req_lines.append("")
    
    req_data = '\r\n'.join(req_lines).encode('utf-8') + body
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(kwargs.get('timeout', 30))
        sock.connect((host, port))
        sock.sendall(req_data)
        
        response_data = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk
        sock.close()
    except socket.timeout:
        raise Timeout(f"Request to {url} timed out")
    except socket.error as e:
        raise ConnectionError(f"Failed to connect to {url}: {e}")
    
    # Parse response
    header_end = response_data.find(b'\r\n\r\n')
    if header_end < 0:
        return Response(500, response_data)
    
    header_text = response_data[:header_end].decode('utf-8', errors='replace')
    content = response_data[header_end + 4:]
    
    lines = header_text.split('\r\n')
    status_line = lines[0]
    parts = status_line.split(' ', 2)
    status_code = int(parts[1]) if len(parts) > 1 else 500
    
    resp_headers = {}
    for line in lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            resp_headers[k.strip()] = v.strip()
    
    return Response(status_code, content, resp_headers, url)


# Module-level functions (requests-compatible)
def get(url, **kwargs):
    return _do_request('GET', url, **kwargs)

def post(url, **kwargs):
    return _do_request('POST', url, **kwargs)

def put(url, **kwargs):
    return _do_request('PUT', url, **kwargs)

def delete(url, **kwargs):
    return _do_request('DELETE', url, **kwargs)

def patch(url, **kwargs):
    return _do_request('PATCH', url, **kwargs)

def head(url, **kwargs):
    return _do_request('HEAD', url, **kwargs)

def request(method, url, **kwargs):
    return _do_request(method, url, **kwargs)

def session():
    return Session()
