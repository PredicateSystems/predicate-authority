from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from predicate_contracts import PolicyEffect, PolicyRule


@dataclass(frozen=True)
class PolicyReloadResult:
    changed: bool
    rules: tuple[PolicyRule, ...]
    global_max_delegation_depth: int | None = None


class PolicyFileSource:
    def __init__(self, policy_path: str) -> None:
        self._policy_path = Path(policy_path)
        self._last_mtime_ns: int | None = None

    def load_rules(self) -> tuple[PolicyRule, ...]:
        rules, _ = self.load_policy()
        return rules

    def load_policy(self) -> tuple[tuple[PolicyRule, ...], int | None]:
        payload = self._load_payload(self._policy_path.read_text(encoding="utf-8"))
        rules, global_max_delegation_depth = parse_policy_payload(payload)
        stat = self._policy_path.stat()
        self._last_mtime_ns = stat.st_mtime_ns
        return rules, global_max_delegation_depth

    def _load_payload(self, raw: str) -> dict[str, Any]:
        suffix = self._policy_path.suffix.lower()
        if suffix in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-untyped]
            except ImportError as exc:  # pragma: no cover - env-dependent
                raise RuntimeError(
                    "YAML policy files require PyYAML. Install with: pip install pyyaml"
                ) from exc
            loaded = yaml.safe_load(raw)
        else:
            loaded = json.loads(raw)

        if not isinstance(loaded, dict):
            raise RuntimeError("Policy file must deserialize to an object.")
        return loaded

    def reload_if_changed(self) -> PolicyReloadResult:
        stat = self._policy_path.stat()
        if self._last_mtime_ns is None or stat.st_mtime_ns != self._last_mtime_ns:
            rules, global_max_delegation_depth = self.load_policy()
            return PolicyReloadResult(
                changed=True,
                rules=rules,
                global_max_delegation_depth=global_max_delegation_depth,
            )
        return PolicyReloadResult(changed=False, rules=(), global_max_delegation_depth=None)


def parse_policy_payload(payload: Mapping[str, Any]) -> tuple[tuple[PolicyRule, ...], int | None]:
    rules_payload = payload.get("rules", [])
    rules: list[PolicyRule] = []
    if isinstance(rules_payload, list):
        for item in rules_payload:
            if not isinstance(item, Mapping):
                continue
            rules.append(
                PolicyRule(
                    name=str(item["name"]),
                    effect=PolicyEffect(str(item["effect"])),
                    principals=tuple(str(value) for value in item["principals"]),
                    actions=tuple(str(value) for value in item["actions"]),
                    resources=tuple(str(value) for value in item["resources"]),
                    required_labels=tuple(str(value) for value in item.get("required_labels", [])),
                    max_delegation_depth=(
                        int(item["max_delegation_depth"])
                        if item.get("max_delegation_depth") is not None
                        else None
                    ),
                )
            )
    global_max_delegation_depth = (
        int(payload["global_max_delegation_depth"])
        if payload.get("global_max_delegation_depth") is not None
        else None
    )
    return tuple(rules), global_max_delegation_depth
