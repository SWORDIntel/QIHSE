"""QIHSE clickhouse-driver-compatible Python SDK.

Provides a clickhouse-driver-compatible API for QIHSE's ClickHouse HTTP interface.
"""
import qihse_http
import json as json_module
import io
import csv

class Error(Exception):
    pass

class DatabaseError(Error):
    pass

class OperationalError(Error):
    pass


class Client:
    """clickhouse-driver-compatible Client."""
    def __init__(self, host="localhost", port=8123, database="default", user="default",
                 password="", **kwargs):
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self._url = f"http://{host}:{port}"
        self._timeout = kwargs.get('timeout', 30)
        self._settings = kwargs.get('settings', {})
    
    def execute(self, query, params=None, with_column_types=False, external_tables=None,
                query_id=None, settings=None):
        """Execute a query and return results."""
        if params:
            # Parameterized query
            if isinstance(params, (list, tuple)):
                for p in params:
                    if isinstance(p, (list, tuple)):
                        query = query % tuple(p)
                    else:
                        query = query % p
            elif isinstance(params, dict):
                query = query % params
        
        url = self._url + f"/?database={self.database}&default_format=TabSeparated"
        if settings:
            for k, v in settings.items():
                url += f"&{k}={v}"
        
        response = qihse_http.post(url, data=query, timeout=self._timeout)
        
        if response.status_code >= 400:
            raise OperationalError(response.text)
        
        # Parse TabSeparated response
        rows = []
        text = response.text.strip()
        if text:
            for line in text.split('\n'):
                if line:
                    rows.append(tuple(line.split('\t')))
        
        if with_column_types:
            # Would need to parse column types from response
            return rows, []
        return rows
    
    def execute_with_progress(self, query, params=None):
        """Execute with progress (simplified - same as execute)."""
        return self.execute(query, params)
    
    def query(self, query, params=None):
        """Execute a query and return a QueryResult."""
        rows = self.execute(query, params)
        return QueryResult(rows)
    
    def query_with_column_types(self, query, params=None):
        """Execute and return rows with column types."""
        rows, col_types = self.execute(query, params, with_column_types=True)
        return QueryResult(rows, col_types)
    
    def subquery(self, query, params=None):
        """Return a QueryResult iterator."""
        result = self.query(query, params)
        return iter(result)
    
    def insert(self, table, data, column_names=None):
        """Insert data into a table."""
        if column_names is None and data:
            column_names = [f"c{i}" for i in range(len(data[0]))]
        
        # Build INSERT statement with VALUES
        values = []
        for row in data:
            vals = []
            for v in row:
                if isinstance(v, str):
                    vals.append(f"'{v}'")
                elif v is None:
                    vals.append("NULL")
                else:
                    vals.append(str(v))
            values.append(f"({','.join(vals)})")
        
        query = f"INSERT INTO {table} ({','.join(column_names)}) VALUES {','.join(values)}"
        return self.execute(query)
    
    def get_format(self, query, format_name):
        """Execute query with a specific format."""
        url = self._url + f"/?query={query}&default_format={format_name}"
        response = qihse_http.get(url, timeout=self._timeout)
        return response.text
    
    def ping(self):
        """Check server connectivity."""
        try:
            response = qihse_http.get(self._url + "/ping", timeout=5)
            return response.ok
        except:
            return False
    
    def close(self):
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class QueryResult:
    """clickhouse-driver-compatible QueryResult."""
    def __init__(self, rows, column_types=None):
        self._rows = rows
        self._column_types = column_types or []
        self._position = 0
    
    @property
    def rows(self):
        return self._rows
    
    @property
    def column_types(self):
        return self._column_types
    
    def __iter__(self):
        return iter(self._rows)
    
    def __len__(self):
        return len(self._rows)
    
    def __getitem__(self, index):
        return self._rows[index]
    
    def get_result(self):
        return self._rows
