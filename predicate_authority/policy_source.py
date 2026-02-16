from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from predicate_contracts import PolicyEffect, PolicyRule


@dataclass(frozen=True)
class PolicyReloadResult:
    changed: bool
    rules: tuple[PolicyRule, ...]


class PolicyFileSource:
    def __init__(self, policy_path: str) -> None:
        self._policy_path = Path(policy_path)
        self._last_mtime_ns: int | None = None

    def load_rules(self) -> tuple[PolicyRule, ...]:
        payload = json.loads(self._policy_path.read_text(encoding="utf-8"))
        rules_payload = payload.get("rules", [])
        rules: list[PolicyRule] = []
        for item in rules_payload:
            rules.append(
                PolicyRule(
                    name=item["name"],
                    effect=PolicyEffect(item["effect"]),
                    principals=tuple(item["principals"]),
                    actions=tuple(item["actions"]),
                    resources=tuple(item["resources"]),
                    required_labels=tuple(item.get("required_labels", [])),
                )
            )
        stat = self._policy_path.stat()
        self._last_mtime_ns = stat.st_mtime_ns
        return tuple(rules)

    def reload_if_changed(self) -> PolicyReloadResult:
        stat = self._policy_path.stat()
        if self._last_mtime_ns is None or stat.st_mtime_ns != self._last_mtime_ns:
            rules = self.load_rules()
            return PolicyReloadResult(changed=True, rules=rules)
        return PolicyReloadResult(changed=False, rules=())
