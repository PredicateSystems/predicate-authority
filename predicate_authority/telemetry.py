from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Protocol, cast

from predicate_contracts import ProofEvent, TraceEmitter


class SpanLike(Protocol):
    def set_attribute(self, key: str, value: str | bool | int) -> None: ...


class TracerLike(Protocol):
    def start_as_current_span(self, name: str) -> AbstractContextManager[SpanLike]: ...


class OpenTelemetryTraceEmitter(TraceEmitter):
    """TraceEmitter backed by OpenTelemetry spans/events."""

    def __init__(self, tracer: TracerLike | None = None) -> None:
        self._tracer = tracer or self._default_tracer()

    def emit(self, event: ProofEvent) -> None:
        with self._tracer.start_as_current_span("predicate.authority.decision") as span:
            span.set_attribute("predicate.event_type", event.event_type)
            span.set_attribute("predicate.principal_id", event.principal_id)
            span.set_attribute("predicate.action", event.action)
            span.set_attribute("predicate.resource", event.resource)
            span.set_attribute("predicate.reason", event.reason.value)
            span.set_attribute("predicate.allowed", event.allowed)
            span.set_attribute("predicate.emitted_at_epoch_s", event.emitted_at_epoch_s)
            if event.mandate_id is not None:
                span.set_attribute("predicate.mandate_id", event.mandate_id)

    @staticmethod
    def _default_tracer() -> TracerLike:
        try:
            from opentelemetry import trace
        except ImportError as exc:
            raise RuntimeError(
                "OpenTelemetryTraceEmitter requires 'opentelemetry-api'. "
                "Install it or pass an explicit tracer."
            ) from exc
        return cast(TracerLike, trace.get_tracer("predicate-authority"))
