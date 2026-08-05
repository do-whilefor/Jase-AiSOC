"""Prometheus metrics owned by one application instance."""

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        self.http_requests = Counter(
            "blue_team_http_requests_total",
            "HTTP requests handled by the API server.",
            ("method", "route", "status"),
            registry=self.registry,
        )
        self.http_duration = Histogram(
            "blue_team_http_request_duration_seconds",
            "HTTP request latency in seconds.",
            ("method", "route"),
            registry=self.registry,
        )

    def render(self) -> bytes:
        return generate_latest(self.registry)
