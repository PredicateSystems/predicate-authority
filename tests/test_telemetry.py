from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import Any

from predicate_authority.telemetry import OpenTelemetryTraceEmitter
from predicate_contracts import AuthorizationReason, ProofEvent


@dataclass
class FakeSpan:
    attributes: dict[str, Any] = field(default_factory=dict)

    def set_attribute(self, key: str, value: str | bool | int) -> None:
        self.attributes[key] = value


@dataclass
class FakeSpanContextManager(AbstractContextManager[FakeSpan]):
    span: FakeSpan

    def __enter__(self) -> FakeSpan:
        return self.span

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None


@dataclass
class FakeTracer:
    spans: list[FakeSpan] = field(default_factory=list)

    def start_as_current_span(self, name: str) -> FakeSpanContextManager:
        span = FakeSpan()
        span.set_attribute("span.name", name)
        self.spans.append(span)
        return FakeSpanContextManager(span=span)


def test_open_telemetry_emitter_sets_expected_attributes() -> None:
    tracer = FakeTracer()
    emitter = OpenTelemetryTraceEmitter(tracer=tracer)
    event = ProofEvent(
        event_type="authority.decision",
        principal_id="agent:ops",
        action="infra.apply",
        resource="terraform://prod",
        reason=AuthorizationReason.ALLOWED,
        allowed=True,
        mandate_id="mandate123",
        emitted_at_epoch_s=1700000000,
    )

    emitter.emit(event)

    assert len(tracer.spans) == 1
    span = tracer.spans[0]
    assert span.attributes["span.name"] == "predicate.authority.decision"
    assert span.attributes["predicate.principal_id"] == "agent:ops"
    assert span.attributes["predicate.allowed"] is True
    assert span.attributes["predicate.reason"] == "allowed"
