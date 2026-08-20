"""QIHSE elasticsearch-py-compatible Python SDK.

Provides an elasticsearch-py-compatible API for QIHSE's ES-compatible HTTP API.
"""
import qihse_http
import json as json_module

class Error(Exception):
    pass

class ConnectionError(Error):
    pass

class NotFoundError(Error):
    pass

class RequestError(Error):
    def __init__(self, status_code, error, info=None):
        super().__init__(error)
        self.status_code = status_code
        self.error = error
        self.info = info


class Hit:
    """Represents a single search hit."""
    def __init__(self, data):
        self._index = data.get('_index', '')
        self._id = data.get('_id', '')
        self._score = data.get('_score')
        self._source = data.get('_source', {})
        self._type = data.get('_type', '_doc')
    
    @property
    def index(self): return self._index
    @property
    def id(self): return self._id
    @property
    def score(self): return self._score
    @property
    def source(self): return self._source
    @property
    def type(self): return self._type
    
    def __getitem__(self, key):
        return self._source[key]
    
    def __contains__(self, key):
        return key in self._source
    
    def to_dict(self):
        return {'_index': self._index, '_id': self._id, '_score': self._score, '_source': self._source}


class Response:
    """elasticsearch-py-compatible Response object."""
    def __init__(self, data):
        self._data = data
        self._hits = [Hit(h) for h in data.get('hits', {}).get('hits', [])]
        self._took = data.get('took', 0)
        self._timed_out = data.get('timed_out', False)
        self._total = data.get('hits', {}).get('total', {}).get('value', 0)
    
    @property
    def hits(self): return self._hits
    @property
    def took(self): return self._took
    @property
    def timed_out(self): return self._timed_out
    @property
    def total(self): return self._total
    
    def __iter__(self):
        return iter(self._hits)
    
    def __len__(self):
        return len(self._hits)
    
    def __getitem__(self, index):
        return self._hits[index]


class IndicesClient:
    """elasticsearch-py-compatible IndicesClient."""
    def __init__(self, client):
        self._client = client
    
    def create(self, index, **kwargs):
        url = f"{self._client._url}/{index}"
        resp = qihse_http.put(url, json=kwargs.get('body', {}), timeout=self._client._timeout)
        return resp.json()
    
    def delete(self, index):
        url = f"{self._client._url}/{index}"
        resp = qihse_http.delete(url, timeout=self._client._timeout)
        return resp.json()
    
    def exists(self, index):
        url = f"{self._client._url}/{index}"
        resp = qihse_http.head(url, timeout=self._client._timeout)
        return resp.ok
    
    def refresh(self, index):
        url = f"{self._client._url}/{index}/_refresh"
        resp = qihse_http.post(url, timeout=self._client._timeout)
        return resp.json()
    
    def get_mapping(self, index):
        url = f"{self._client._url}/{index}/_mapping"
        resp = qihse_http.get(url, timeout=self._client._timeout)
        return resp.json()


class Elasticsearch:
    """elasticsearch-py-compatible Elasticsearch client."""
    def __init__(self, hosts="http://localhost:9200", **kwargs):
        if isinstance(hosts, str):
            self._url = hosts.rstrip('/')
        elif isinstance(hosts, list):
            self._url = hosts[0].rstrip('/') if hosts else "http://localhost:9200"
        else:
            self._url = "http://localhost:9200"
        self._timeout = kwargs.get('timeout', 30)
        self.indices = IndicesClient(self)
    
    def index(self, index, id=None, body=None, doc_type='_doc', **kwargs):
        """Index a document."""
        if id:
            url = f"{self._url}/{index}/_doc/{id}"
            resp = qihse_http.put(url, json=body or {}, timeout=self._timeout)
        else:
            url = f"{self._url}/{index}/_doc"
            resp = qihse_http.post(url, json=body or {}, timeout=self._timeout)
        return resp.json()
    
    def get(self, index, id, doc_type='_doc', **kwargs):
        """Get a document by ID."""
        url = f"{self._url}/{index}/_doc/{id}"
        resp = qihse_http.get(url, timeout=self._timeout)
        return resp.json()
    
    def exists(self, index, id, doc_type='_doc', **kwargs):
        """Check if a document exists."""
        url = f"{self._url}/{index}/_doc/{id}"
        resp = qihse_http.head(url, timeout=self._timeout)
        return resp.ok
    
    def update(self, index, id, body=None, doc_type='_doc', **kwargs):
        """Update a document."""
        url = f"{self._url}/{index}/_doc/{id}/_update"
        resp = qihse_http.post(url, json=body or {}, timeout=self._timeout)
        return resp.json()
    
    def delete(self, index, id, doc_type='_doc', **kwargs):
        """Delete a document."""
        url = f"{self._url}/{index}/_doc/{id}"
        resp = qihse_http.delete(url, timeout=self._timeout)
        return resp.json()
    
    def search(self, index=None, body=None, doc_type=None, **kwargs):
        """Search documents."""
        if index:
            url = f"{self._url}/{index}/_search"
        else:
            url = f"{self._url}/_search"
        resp = qihse_http.post(url, json=body or {}, timeout=self._timeout)
        data = resp.json()
        return Response(data)
    
    def count(self, index=None, body=None, doc_type=None, **kwargs):
        """Count documents matching a query."""
        if index:
            url = f"{self._url}/{index}/_count"
        else:
            url = f"{self._url}/_count"
        resp = qihse_http.post(url, json=body or {}, timeout=self._timeout)
        return resp.json()
    
    def bulk(self, body, index=None, **kwargs):
        """Bulk operations."""
        if isinstance(body, list):
            lines = []
            for i in range(0, len(body), 2):
                lines.append(json_module.dumps(body[i]))
                if i + 1 < len(body):
                    lines.append(json_module.dumps(body[i + 1]))
            body_str = '\n'.join(lines) + '\n'
        else:
            body_str = body
        
        url = f"{self._url}/_bulk" if not index else f"{self._url}/{index}/_bulk"
        resp = qihse_http.post(url, data=body_str, headers={'Content-Type': 'application/x-ndjson'},
                              timeout=self._timeout)
        return resp.json()
    
    def create(self, index, id, body=None, doc_type='_doc', **kwargs):
        """Create a document (fails if exists)."""
        url = f"{self._url}/{index}/_create/{id}"
        resp = qihse_http.post(url, json=body or {}, timeout=self._timeout)
        return resp.json()
    
    def info(self, **kwargs):
        """Get server info."""
        resp = qihse_http.get(self._url, timeout=self._timeout)
        return resp.json()
    
    def ping(self, **kwargs):
        """Check server connectivity."""
        try:
            resp = qihse_http.get(self._url, timeout=5)
            return resp.ok
        except:
            return False
    
    def close(self):
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
