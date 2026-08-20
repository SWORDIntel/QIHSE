"""QIHSE Prometheus metrics and OpenTelemetry tracing Python SDK.

Provides prometheus-client and opentelemetry-compatible APIs.
"""
import json as json_module
import time
import random
import threading

# ---- Prometheus-compatible Metrics ----

class Counter:
    """prometheus_client-compatible Counter."""
    def __init__(self, name, documentation='', labelnames=()):
        self.name = name
        self.documentation = documentation
        self.labelnames = labelnames
        self._value = 0.0
        self._lock = threading.Lock()
    
    def inc(self, amount=1):
        with self._lock:
            self._value += amount
    
    @property
    def value(self):
        return self._value
    
    def collect(self):
        return [(self.name, self._value)]


class Gauge:
    """prometheus_client-compatible Gauge."""
    def __init__(self, name, documentation='', labelnames=()):
        self.name = name
        self.documentation = documentation
        self.labelnames = labelnames
        self._value = 0.0
        self._lock = threading.Lock()
    
    def set(self, value):
        with self._lock:
            self._value = value
    
    def inc(self, amount=1):
        with self._lock:
            self._value += amount
    
    def dec(self, amount=1):
        with self._lock:
            self._value -= amount
    
    @property
    def value(self):
        return self._value
    
    def collect(self):
        return [(self.name, self._value)]


class Histogram:
    """prometheus_client-compatible Histogram."""
    def __init__(self, name, documentation='', labelnames=(), buckets=None):
        self.name = name
        self.documentation = documentation
        self.labelnames = labelnames
        self.buckets = buckets or [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
        self._count = 0
        self._sum = 0.0
        self._bucket_counts = [0] * len(self.buckets)
        self._lock = threading.Lock()
    
    def observe(self, value):
        with self._lock:
            self._count += 1
            self._sum += value
            for i, bound in enumerate(self.buckets):
                if value <= bound:
                    self._bucket_counts[i] += 1
    
    @property
    def count(self):
        return self._count
    
    @property
    def sum(self):
        return self._sum
    
    def collect(self):
        return [(f"{self.name}_count", self._count), (f"{self.name}_sum", self._sum)]


class CollectorRegistry:
    """prometheus_client-compatible CollectorRegistry."""
    def __init__(self):
        self._collectors = {}
        self._lock = threading.Lock()
    
    def register(self, collector):
        with self._lock:
            self._collectors[collector.name] = collector
    
    def unregister(self, name):
        with self._lock:
            self._collectors.pop(name, None)
    
    def collect(self):
        for collector in self._collectors.values():
            for name, value in collector.collect():
                yield name, value
    
    def get_sample_value(self, name):
        for n, v in self.collect():
            if n == name:
                return v
        return None


REGISTRY = CollectorRegistry()

def generate_latest(registry=REGISTRY):
    """Generate Prometheus text format output."""
    lines = []
    for name, value in registry.collect():
        lines.append(f"{name} {value}")
    return '\n'.join(lines) + '\n' if lines else ''


# ---- OpenTelemetry-compatible Tracing ----

class Span:
    """opentelemetry-compatible Span."""
    def __init__(self, tracer, operation_name, parent=None):
        self._tracer = tracer
        self.operation_name = operation_name
        self.trace_id = '%032x' % random.getrandbits(128)
        self.span_id = '%016x' % random.getrandbits(64)
        self.parent_span_id = parent.span_id if parent else None
        self.start_time = time.time_ns()
        self.end_time = None
        self._attributes = {}
        self._status = 0  # 0=OK, 1=ERROR
        self._events = []
    
    def set_attribute(self, key, value):
        self._attributes[key] = value
    
    def add_event(self, name, attributes=None):
        self._events.append({'name': name, 'attributes': attributes or {}, 'timestamp': time.time_ns()})
    
    def set_status(self, status):
        self._status = status
    
    def end(self):
        self.end_time = time.time_ns()
    
    @property
    def duration_ns(self):
        if self.end_time:
            return self.end_time - self.start_time
        return 0
    
    def to_dict(self):
        return {
            'trace_id': self.trace_id,
            'span_id': self.span_id,
            'parent_span_id': self.parent_span_id,
            'operation': self.operation_name,
            'start_time_ns': self.start_time,
            'duration_ns': self.duration_ns,
            'status': self._status,
            'attributes': self._attributes,
            'events': self._events,
        }


class Tracer:
    """opentelemetry-compatible Tracer."""
    def __init__(self, name="qihse"):
        self.name = name
        self._spans = []
        self._lock = threading.Lock()
        self._enabled = True
    
    def start_span(self, operation_name, parent=None):
        span = Span(self, operation_name, parent)
        if self._enabled:
            with self._lock:
                self._spans.append(span)
        return span
    
    def start_as_current_span(self, operation_name, parent=None):
        span = self.start_span(operation_name, parent)
        return span
    
    def finish_span(self, span):
        span.end()
    
    def get_spans(self):
        with self._lock:
            return list(self._spans)
    
    def export_json(self):
        spans = self.get_spans()
        return json_module.dumps({'spans': [s.to_dict() for s in spans]})
    
    def set_enabled(self, enabled):
        self._enabled = enabled


# Global tracer instance
_tracer = Tracer()

def get_tracer(name="qihse"):
    return _tracer

def trace(operation_name):
    """Decorator for tracing functions."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            span = _tracer.start_span(operation_name)
            try:
                result = func(*args, **kwargs)
                span.set_status(0)
                return result
            except Exception as e:
                span.set_status(1)
                span.set_attribute('error', str(e))
                raise
            finally:
                span.end()
        return wrapper
    return decorator
