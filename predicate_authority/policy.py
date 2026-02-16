from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

from predicate_contracts import ActionRequest, AuthorizationReason, PolicyEffect, PolicyRule


@dataclass(frozen=True)
class PolicyMatchResult:
    allowed: bool
    reason: AuthorizationReason
    matched_rule: str | None = None
    missing_labels: tuple[str, ...] = ()


class PolicyEngine:
    def __init__(self, rules: tuple[PolicyRule, ...]) -> None:
        self._rules = rules

    def replace_rules(self, rules: tuple[PolicyRule, ...]) -> None:
        self._rules = rules

    def evaluate(self, request: ActionRequest) -> PolicyMatchResult:
        matching_rules = [rule for rule in self._rules if self._matches_rule(rule, request)]
        if not matching_rules:
            return PolicyMatchResult(
                allowed=False,
                reason=AuthorizationReason.NO_MATCHING_POLICY,
            )

        for rule in matching_rules:
            if rule.effect == PolicyEffect.DENY:
                return PolicyMatchResult(
                    allowed=False,
                    reason=AuthorizationReason.EXPLICIT_DENY,
                    matched_rule=rule.name,
                )

        for rule in matching_rules:
            if rule.effect != PolicyEffect.ALLOW:
                continue

            missing_labels = tuple(
                label
                for label in rule.required_labels
                if not request.verification_evidence.is_label_passed(label)
            )
            if missing_labels:
                return PolicyMatchResult(
                    allowed=False,
                    reason=AuthorizationReason.MISSING_REQUIRED_VERIFICATION,
                    matched_rule=rule.name,
                    missing_labels=missing_labels,
                )

            return PolicyMatchResult(
                allowed=True,
                reason=AuthorizationReason.ALLOWED,
                matched_rule=rule.name,
            )

        return PolicyMatchResult(
            allowed=False,
            reason=AuthorizationReason.NO_MATCHING_POLICY,
        )

    @staticmethod
    def _matches_rule(rule: PolicyRule, request: ActionRequest) -> bool:
        principal_ok = any(
            fnmatch(request.principal.principal_id, pattern) for pattern in rule.principals
        )
        action_ok = any(fnmatch(request.action_spec.action, pattern) for pattern in rule.actions)
        resource_ok = any(
            fnmatch(request.action_spec.resource, pattern) for pattern in rule.resources
        )
        return principal_ok and action_ok and resource_ok
