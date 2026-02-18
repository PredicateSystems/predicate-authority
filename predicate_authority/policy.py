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
    def __init__(
        self,
        rules: tuple[PolicyRule, ...],
        global_max_delegation_depth: int | None = None,
    ) -> None:
        self._rules = rules
        self._global_max_delegation_depth = global_max_delegation_depth

    def replace_rules(self, rules: tuple[PolicyRule, ...]) -> None:
        self._rules = rules

    def set_global_max_delegation_depth(self, max_depth: int | None) -> None:
        self._global_max_delegation_depth = max_depth

    def evaluate(self, request: ActionRequest, delegation_depth: int = 0) -> PolicyMatchResult:
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

        first_allow_failure: PolicyMatchResult | None = None
        for rule in matching_rules:
            if rule.effect != PolicyEffect.ALLOW:
                continue

            effective_max_depth = self._effective_max_delegation_depth(rule)
            if effective_max_depth is not None and delegation_depth > effective_max_depth:
                failure = PolicyMatchResult(
                    allowed=False,
                    reason=AuthorizationReason.MAX_DELEGATION_DEPTH_EXCEEDED,
                    matched_rule=rule.name,
                )
                if first_allow_failure is None:
                    first_allow_failure = failure
                continue

            missing_labels = tuple(
                label
                for label in rule.required_labels
                if not request.verification_evidence.is_label_passed(label)
            )
            if missing_labels:
                failure = PolicyMatchResult(
                    allowed=False,
                    reason=AuthorizationReason.MISSING_REQUIRED_VERIFICATION,
                    matched_rule=rule.name,
                    missing_labels=missing_labels,
                )
                if first_allow_failure is None:
                    first_allow_failure = failure
                continue

            return PolicyMatchResult(
                allowed=True,
                reason=AuthorizationReason.ALLOWED,
                matched_rule=rule.name,
            )

        if first_allow_failure is not None:
            return first_allow_failure

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

    def _effective_max_delegation_depth(self, rule: PolicyRule) -> int | None:
        global_max = self._global_max_delegation_depth
        rule_max = rule.max_delegation_depth
        if global_max is None:
            return rule_max
        if rule_max is None:
            return global_max
        return min(global_max, rule_max)
