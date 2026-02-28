"""
Resource comparison functions for post-execution verification.

These functions compare authorized resources against actual resources,
handling path normalization and glob pattern matching.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch

from predicate_contracts import normalize_path


def normalize_resource(resource: str) -> str:
    """
    Normalize a resource path for comparison.

    Applies the following transformations:
    - Expands ~ to home directory
    - Collapses multiple slashes
    - Removes ./ segments
    - Removes trailing slashes
    - Resolves . and ..

    Args:
        resource: Resource path to normalize

    Returns:
        Normalized path
    """
    # Use existing normalize_path for filesystem paths
    if resource.startswith("/") or resource.startswith("~") or resource.startswith("."):
        normalized = normalize_path(resource)
        # normalize_path doesn't strip trailing slashes, so we do it here
        if len(normalized) > 1 and normalized.endswith("/"):
            normalized = normalized[:-1]
        return normalized

    # For URLs, handle protocol specially
    url_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)", resource)
    if url_match:
        protocol = url_match.group(1)  # e.g., "https://"
        rest = resource[len(protocol) :]

        # Normalize the rest (collapse slashes, remove ./, remove trailing /)
        normalized = re.sub(r"/+", "/", rest)  # Collapse multiple slashes
        normalized = re.sub(r"/\./", "/", normalized)  # Remove ./
        normalized = re.sub(r"/$", "", normalized)  # Remove trailing slash

        return protocol + normalized

    # For other non-path resources, do basic cleanup
    normalized = re.sub(r"/+", "/", resource)  # Collapse multiple slashes
    normalized = re.sub(r"/\./", "/", normalized)  # Remove ./
    normalized = re.sub(r"/$", "", normalized)  # Remove trailing slash
    return normalized


def resources_match(
    authorized: str,
    actual: str,
    *,
    allow_glob: bool = True,
) -> bool:
    """
    Check if an actual resource matches an authorized resource.

    Handles:
    - Path normalization (~ expansion, . and .., etc.)
    - Optional glob pattern matching (* wildcards)

    Args:
        authorized: Resource from the mandate (may contain glob patterns)
        actual: Resource that was actually accessed
        allow_glob: Enable glob pattern matching for authorized resource

    Returns:
        True if resources match
    """
    # Normalize both resources
    normalized_auth = normalize_resource(authorized)
    normalized_actual = normalize_resource(actual)

    # Exact match after normalization
    if normalized_auth == normalized_actual:
        return True

    # Glob pattern match (if enabled and authorized resource contains wildcards)
    if allow_glob and "*" in authorized:
        return fnmatch(normalized_actual, authorized)

    return False


def actions_match(authorized: str, actual: str) -> bool:
    """
    Check if an actual action matches an authorized action.

    Actions are compared case-sensitively after trimming whitespace.
    Supports glob patterns in the authorized action.

    Args:
        authorized: Action from the mandate (may contain glob patterns)
        actual: Action that was actually performed

    Returns:
        True if actions match
    """
    normalized_auth = authorized.strip()
    normalized_actual = actual.strip()

    # Exact match
    if normalized_auth == normalized_actual:
        return True

    # Glob pattern match (e.g., "fs.*" matches "fs.read")
    if "*" in authorized:
        return fnmatch(normalized_actual, authorized)

    return False
