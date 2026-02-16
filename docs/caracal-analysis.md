# Caracal: Pre-Execution Authority Enforcement for AI Agents

## Executive Summary

**Caracal** is a pre-execution authority enforcement system designed to control AI agent actions in production environments. It implements cryptographically-verified, time-bound authorization mandates that must be validated before any irreversible action (API calls, database writes, deployments) can execute. The system treats agent identity as a first-class cryptographic primitive with explicit delegation chains and immutable audit trails.

**Repository**: `/Users/guoliangwang/Code/Python/caracal`

---

## 1. Core Purpose & Problem Statement

### The Problem
AI agents operating in production environments can:
- Execute irreversible actions (payments, deployments, data deletion)
- Operate autonomously without human oversight
- Make decisions that have real-world consequences
- Be compromised or malfunction in unpredictable ways

Traditional approaches (API keys, role-based access control) fail because they:
- Grant broad, long-lived permissions
- Lack cryptographic verification
- Don't provide granular, context-aware control
- Can't be easily delegated or revoked

### The Caracal Solution
Caracal enforces **explicit authority**: no action executes unless there is a cryptographically verified, time-bound mandate issued under a governing policy. It sits at the boundary where decisions become actions and provides:

- **Cryptographic proof of authorization** (ECDSA P-256 signatures)
- **Time-bound mandates** (TTL-based expiration)
- **Immutable audit trails** (Merkle-tree-verified ledger)
- **Fail-closed semantics** (deny by default)
- **Delegation chains** (parent-child authority transfer)

---

## 2. How Caracal Handles Agent Identity

### 2.1 Agent Identity Model

Caracal treats agents as **Principals** - first-class identities that can hold and exercise authority.

#### Principal Attributes
```python
class Principal:
    id: UUID                    # Unique identifier (UUID v4)
    name: str                   # Human-readable, enforced unique
    owner: str                  # Owner contact/email
    key_pair: KeyPair          # ECDSA P-256 public/private keys
    parent_id: Optional[UUID]  # Hierarchical relationship
    metadata: dict              # Extensible metadata
    created_at: datetime
    updated_at: datetime
```

**Key Characteristics:**

1. **Cryptographic Identity**: Each principal has an ECDSA P-256 key pair
   - Public key: Identity attestation
   - Private key: Signs delegation tokens and mandates

2. **Hierarchical Relationships**: Agents can have parent-child relationships
   - Enables delegation chains (parent → child → grandchild)
   - Authority flows downward with scope narrowing
   - Delegation depth tracking and limits

3. **Persistent Registry**: Atomic JSON persistence with rolling backups
   - 100 backup history with atomic writes
   - ACID guarantees for identity operations
   - Corruption detection and recovery

4. **Name Uniqueness**: Human-readable names enforced as unique
   - Prevents confusion in audit trails
   - Enables natural reference in policies

### 2.2 Identity Operations

#### Creating an Agent Identity
```bash
# CLI
caracal agent register \
  --name "web-scraper-01" \
  --owner "team@company.com" \
  --metadata '{"purpose":"product-data-collection"}'

# SDK
from caracal.sdk import AuthorityClient

client = AuthorityClient()
principal = client.register_principal(
    name="web-scraper-01",
    owner="team@company.com",
    metadata={"purpose": "product-data-collection"}
)
```

#### Delegation (Parent-Child Identity)
```python
# Create delegation token
delegation_token = client.create_delegation(
    parent_principal_id="parent-agent-uuid",
    child_principal_id="child-agent-uuid",
    scope_narrowing={
        "resources": ["api:openai:gpt-3.5*"],  # Child can only use GPT-3.5
        "actions": ["api_call"],
        "max_depth": 2  # Can delegate 2 levels deep
    },
    validity_seconds=3600
)

# Child uses delegation token to request mandates
mandate = client.request_mandate(
    issuer_id="parent-agent-uuid",
    subject_id="child-agent-uuid",
    delegation_token=delegation_token,
    resource_scope=["api:openai:gpt-3.5-turbo"],
    action_scope=["api_call"]
)
```

### 2.3 Identity in Authorization Flow

Every action in Caracal is tied to a principal's identity:

```
┌─────────────────────────────────────────────────┐
│  Agent Identity (Principal)                     │
│  ├─ UUID: 550e8400-e29b-41d4-a716-446655440000 │
│  ├─ Name: "data-collector-01"                   │
│  ├─ Public Key: 0x04a1b2c3...                   │
│  └─ Parent: "orchestrator-agent"                │
└───────────────────┬─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  Authority Policy (Who can do what)             │
│  ├─ Principal: data-collector-01                │
│  ├─ Resources: ["api:serper:*", "db:products"]  │
│  ├─ Actions: ["GET", "POST", "db_read"]         │
│  └─ Conditions: {"time": "business_hours"}      │
└───────────────────┬─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  Execution Mandate (Time-bound authorization)   │
│  ├─ Mandate ID: mandate-abc123                  │
│  ├─ Subject: data-collector-01                  │
│  ├─ Issued At: 2025-01-15T10:00:00Z            │
│  ├─ Expires At: 2025-01-15T11:00:00Z           │
│  ├─ Signature: ES256(issuer_private_key)        │
│  └─ Scope: matches policy                       │
└───────────────────┬─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  Action Execution                                │
│  Request Header: X-Execution-Mandate: abc123    │
│  ├─ AuthorityEvaluator validates mandate        │
│  ├─ Checks: signature, expiration, scope        │
│  └─ Decision: ALLOW or DENY                     │
└───────────────────┬─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  Authority Ledger (Immutable Audit Trail)       │
│  ├─ Principal: data-collector-01                │
│  ├─ Action: api_call("serper.dev/search")       │
│  ├─ Decision: ALLOWED                           │
│  ├─ Timestamp: 2025-01-15T10:15:23Z            │
│  └─ Merkle Root: 0xabcd1234... (verified)       │
└─────────────────────────────────────────────────┘
```

---

## 3. Architecture Overview

### 3.1 System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Caracal Architecture                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  CLI Tools   │  │ Caracal Flow │  │    Web UI    │     │
│  │   (Click)    │  │    (TUI)     │  │   (React)    │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                  │                  │             │
│         └──────────────────┼──────────────────┘             │
│                            │                                │
│                            ▼                                │
│         ┌────────────────────────────────────┐             │
│         │       SDK / Authority Client       │             │
│         │  ├─ Mandate Request/Validation     │             │
│         │  ├─ Principal Management           │             │
│         │  └─ Ledger Queries                 │             │
│         └────────────┬───────────────────────┘             │
│                      │                                      │
│                      ▼                                      │
│  ┌──────────────────────────────────────────────────┐     │
│  │         Authority Gateway (Enforcement)           │     │
│  │  ├─ Mandate Validation                            │     │
│  │  ├─ Replay Protection                             │     │
│  │  ├─ Rate Limiting                                 │     │
│  │  └─ Circuit Breaker                               │     │
│  └───────────────┬──────────────────────────────────┘     │
│                  │                                          │
│                  ▼                                          │
│  ┌──────────────────────────────────────────────────┐     │
│  │              Core Authority Engine                │     │
│  │  ├─ Principal Identity (identity.py)              │     │
│  │  ├─ Authority Evaluation (authority.py)           │     │
│  │  ├─ Mandate Management (mandate.py)               │     │
│  │  ├─ Delegation (delegation.py)                    │     │
│  │  └─ Crypto Operations (crypto.py)                 │     │
│  └───────────────┬──────────────────────────────────┘     │
│                  │                                          │
│         ┌────────┴─────────┐                               │
│         │                  │                               │
│         ▼                  ▼                               │
│  ┌──────────────┐  ┌────────────────────┐                │
│  │   Database   │  │  Authority Ledger   │                │
│  │  (PostgreSQL)│  │ ├─ Immutable Events │                │
│  │  ├─ Principals│  │ ├─ Merkle Tree     │                │
│  │  ├─ Policies  │  │ ├─ Kafka Stream    │                │
│  │  ├─ Mandates  │  │ └─ Redis Cache     │                │
│  │  └─ Audit Log │  └────────────────────┘                │
│  └──────────────┘                                          │
│                                                              │
│  ┌────────────────────────────────────────────────────┐   │
│  │         MCP Integration (Optional)                  │   │
│  │  ├─ Tool Call Interception                         │   │
│  │  ├─ Resource Read Enforcement                      │   │
│  │  └─ Agentic Workflow Control                       │   │
│  └────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Key Components

#### Core Authority Engine (`caracal/core/`)
- **identity.py**: Principal management with cryptographic key pairs
- **authority.py**: Policy evaluation and authorization decisions
- **mandate.py**: Time-bound authorization issuance and validation
- **delegation.py**: Parent-child authority delegation
- **crypto.py**: ECDSA P-256 signing and verification

#### Database Layer (`caracal/db/`)
- SQLAlchemy models for principals, policies, mandates, ledger events
- PostgreSQL (JSONB), SQLite support
- Alembic migrations

#### Gateway (`caracal/gateway/`)
- **authority_proxy.py**: Request interception and mandate validation
- **replay_protection.py**: Prevents mandate reuse attacks
- **metering_interceptor.py**: Resource usage tracking

#### MCP Integration (`caracal/mcp/`)
- **adapter.py**: Intercepts MCP tool calls
- **service.py**: HTTP API for MCP request proxying
- Integrates with Model Context Protocol for agentic workflows

#### Cryptographic Integrity (`caracal/merkle/`)
- Merkle tree construction with SHA-256 hashing
- Root signing and verification
- Batch-based snapshot scheduling
- Immutable ledger integrity

#### SDK (`caracal/sdk/`)
- High-level Python SDK for developers
- Async/await support
- Fail-closed semantics

#### CLI & TUI
- **CLI** (`caracal/cli/`): Command-line tools
- **Caracal Flow** (`caracal/flow/`): Interactive terminal UI with onboarding wizard

---

## 4. Agent Identity in Practice

### 4.1 Agent Registration Workflow

```python
# Step 1: Register principal identity
from caracal.core.identity import PrincipalRegistry

registry = PrincipalRegistry()
principal = registry.register_principal(
    name="sentiment-analyzer",
    owner="ai-team@company.com",
    metadata={
        "team": "nlp",
        "purpose": "sentiment-analysis",
        "model": "gpt-4"
    }
)

# Principal receives:
# - UUID: 550e8400-e29b-41d4-a716-446655440000
# - ECDSA P-256 key pair (public/private)
# - Persistent storage with atomic writes
```

### 4.2 Authority Policy Creation

```python
# Step 2: Define what the agent can do
from caracal.core.authority import AuthorityPolicy

policy = AuthorityPolicy.create(
    principal_id=principal.id,
    resource_scope=[
        "api:openai:gpt-4",
        "db:reviews:read",
        "s3:sentiment-results:write"
    ],
    action_scope=[
        "api_call",
        "db_read",
        "s3_write"
    ],
    conditions={
        "time_window": "business_hours",
        "cost_limit_usd": 100.00
    }
)
```

### 4.3 Mandate Issuance

```python
# Step 3: Issue time-bound mandate
from caracal.core.mandate import MandateManager

mandate_mgr = MandateManager()
mandate = mandate_mgr.issue_mandate(
    issuer_id="admin-principal-id",
    subject_id=principal.id,
    resource_scope=policy.resource_scope,
    action_scope=policy.action_scope,
    validity_seconds=3600  # 1 hour
)

# Mandate contains:
# - Cryptographic signature (ES256)
# - Expiration timestamp
# - Scope constraints
# - Revocation status
```

### 4.4 Action Execution with Identity Verification

```python
# Step 4: Agent executes action with mandate
from caracal.gateway import caracal_require_mandate

@caracal_require_mandate(
    required_action="api_call",
    required_resource="api:openai:gpt-4"
)
def analyze_sentiment(text: str, mandate: dict):
    """
    Mandate is validated BEFORE this function executes.

    Validation checks:
    - Principal identity (signature verification)
    - Mandate expiration
    - Resource/action scope match
    - Revocation status
    - Replay protection
    """
    # Call OpenAI API
    result = openai.chat.completions.create(...)
    return result

# Usage
result = analyze_sentiment(
    text="This product is amazing!",
    mandate=mandate  # Passed in request context
)
```

### 4.5 Delegation to Child Agents

```python
# Step 5: Parent agent delegates to child
from caracal.core.delegation import DelegationManager

delegation_mgr = DelegationManager()

# Parent: sentiment-analyzer
# Child: tweet-sentiment-worker

delegation_token = delegation_mgr.create_delegation_token(
    parent_principal_id=principal.id,
    child_principal_id="tweet-worker-id",
    scope_narrowing={
        "resources": ["api:openai:gpt-3.5-turbo"],  # More restricted
        "actions": ["api_call"],
        "max_cost_usd": 10.00,  # Lower limit
        "max_delegation_depth": 1  # Can't delegate further
    },
    validity_seconds=1800  # 30 minutes
)

# Child can now request mandates with delegation token
child_mandate = mandate_mgr.issue_mandate(
    issuer_id=principal.id,
    subject_id="tweet-worker-id",
    delegation_token=delegation_token,
    resource_scope=["api:openai:gpt-3.5-turbo"],
    action_scope=["api_call"]
)
```

### 4.6 Audit Trail with Identity

```python
# Step 6: Query audit trail by identity
from caracal.core.authority_ledger import AuthorityLedger

ledger = AuthorityLedger()

# Query all actions by principal
events = ledger.query_events(
    principal_id=principal.id,
    time_range="24h",
    event_types=["MANDATE_VALIDATED", "ACTION_ALLOWED", "ACTION_DENIED"]
)

# Example event
{
    "event_id": "evt-abc123",
    "event_type": "ACTION_ALLOWED",
    "timestamp": "2025-01-15T10:15:23Z",
    "principal_id": "550e8400-e29b-41d4-a716-446655440000",
    "principal_name": "sentiment-analyzer",
    "mandate_id": "mandate-xyz789",
    "resource": "api:openai:gpt-4",
    "action": "api_call",
    "decision": "ALLOWED",
    "correlation_id": "req-456",
    "merkle_root": "0xabcd1234...",
    "signature_verified": true
}
```

---

## 5. Agent Identity Issues Addressed

### 5.1 Identity Theft & Impersonation

**Problem**: Agent credentials (API keys) can be stolen or leaked.

**Caracal Solution**:
- Cryptographic signatures (ECDSA P-256) for every mandate
- Private keys never transmitted over network
- Mandate tied to specific principal identity
- Signature verification on every request

```python
# Attacker cannot forge mandate without private key
def validate_mandate_signature(mandate: dict, principal: Principal) -> bool:
    signature = mandate["signature"]
    message = f"{mandate['id']}:{mandate['subject_id']}:{mandate['expires_at']}"

    # Verify signature with principal's public key
    return verify_ecdsa_signature(
        message=message,
        signature=signature,
        public_key=principal.key_pair.public_key
    )
```

### 5.2 Privilege Escalation

**Problem**: Agent gains more permissions than intended.

**Caracal Solution**:
- Explicit scope in every mandate (resources + actions)
- No implicit permissions or wildcard grants
- Delegation can only narrow scope, never broaden
- Policy evaluation fails closed (deny by default)

```python
# Example: Parent can delegate to child, but only with narrower scope
parent_mandate_scope = ["api:openai:*", "db:*"]
child_mandate_scope = ["api:openai:gpt-3.5-turbo", "db:reviews:read"]

# This is ALLOWED (narrowing)
assert is_scope_narrower(child_mandate_scope, parent_mandate_scope)

# This would be DENIED (broadening)
child_invalid_scope = ["api:openai:*", "db:*", "s3:*"]
assert not is_scope_narrower(child_invalid_scope, parent_mandate_scope)
```

### 5.3 Long-Lived Credentials

**Problem**: Static API keys live forever, can't be easily revoked.

**Caracal Solution**:
- All mandates have TTL (time-to-live)
- Short-lived by default (1-24 hours typical)
- Automatic expiration enforcement
- Can be revoked at any time

```python
# Mandate automatically expires
mandate = {
    "issued_at": "2025-01-15T10:00:00Z",
    "expires_at": "2025-01-15T11:00:00Z",
    "revoked": False
}

# Validation checks expiration
def is_mandate_valid(mandate: dict) -> bool:
    now = datetime.utcnow()

    if mandate["revoked"]:
        return False

    if now > mandate["expires_at"]:
        return False  # Expired

    return True
```

### 5.4 Lack of Audit Trail

**Problem**: No record of what agent did, when, and with what authority.

**Caracal Solution**:
- Immutable authority ledger
- Every decision logged (allowed/denied)
- Merkle tree integrity verification
- Optional Kafka streaming for real-time monitoring

```python
# Every action creates ledger event
ledger_event = {
    "event_id": str(uuid.uuid4()),
    "event_type": "ACTION_ALLOWED",
    "timestamp": datetime.utcnow().isoformat(),
    "principal_id": principal.id,
    "principal_name": principal.name,
    "mandate_id": mandate.id,
    "resource": "api:openai:gpt-4",
    "action": "api_call",
    "decision": "ALLOWED",
    "decision_reason": "Mandate valid and scope matches",
    "correlation_id": request.headers.get("X-Correlation-ID"),
    "metadata": {...}
}

# Append to ledger (immutable)
ledger.append(ledger_event)

# Periodically create Merkle tree snapshot
merkle_root = create_merkle_tree(ledger_events_batch)
sign_merkle_root(merkle_root, issuer_private_key)
```

### 5.5 Replay Attacks

**Problem**: Attacker intercepts mandate and reuses it multiple times.

**Caracal Solution**:
- Nonce-based replay protection
- One-time use enforcement (optional)
- Request deduplication with Redis
- TTL on replay cache

```python
from caracal.gateway.replay_protection import ReplayProtector

protector = ReplayProtector(redis_client=redis)

# Check if mandate already used
def validate_no_replay(mandate_id: str, nonce: str) -> bool:
    cache_key = f"mandate:{mandate_id}:nonce:{nonce}"

    # Atomic check-and-set
    if protector.is_nonce_seen(cache_key):
        raise ReplayAttackDetected(f"Mandate {mandate_id} already used")

    # Mark as seen (with TTL matching mandate expiration)
    protector.mark_nonce_seen(cache_key, ttl_seconds=mandate_ttl)
    return True
```

### 5.6 Delegation Without Control

**Problem**: Agent delegates authority without oversight or limits.

**Caracal Solution**:
- Explicit delegation tokens (JWT-based)
- Scope narrowing enforcement (child can't have more than parent)
- Delegation depth limits
- Delegation chain verification

```python
# Delegation token structure
delegation_token = {
    "parent_principal_id": "parent-uuid",
    "child_principal_id": "child-uuid",
    "scope": {
        "resources": ["api:openai:gpt-3.5-turbo"],  # Must be subset of parent
        "actions": ["api_call"],
        "max_cost_usd": 10.00
    },
    "delegation_depth": 1,  # Current depth in chain
    "max_delegation_depth": 2,  # Can delegate 1 more level
    "issued_at": "2025-01-15T10:00:00Z",
    "expires_at": "2025-01-15T12:00:00Z",
    "signature": "ES256(parent_private_key, ...)"
}

# Validation
def validate_delegation(token: dict, child_mandate_scope: list) -> bool:
    # 1. Verify parent signature
    verify_signature(token, parent_public_key)

    # 2. Check expiration
    assert token["expires_at"] > now()

    # 3. Enforce scope narrowing
    assert is_scope_narrower(child_mandate_scope, token["scope"])

    # 4. Check delegation depth
    assert token["delegation_depth"] < token["max_delegation_depth"]

    return True
```

### 5.7 Identity Confusion in Multi-Agent Systems

**Problem**: Multiple agents, unclear who did what.

**Caracal Solution**:
- Unique UUID per principal
- Human-readable names (enforced unique)
- Parent-child relationships tracked
- Correlation IDs across request chains

```python
# Clear identity in logs
{
    "event_type": "ACTION_ALLOWED",
    "principal_id": "550e8400-e29b-41d4-a716-446655440000",
    "principal_name": "sentiment-analyzer",
    "parent_principal_name": "orchestrator-agent",
    "delegation_chain": [
        "orchestrator-agent",
        "sentiment-analyzer",
        "tweet-worker"
    ],
    "correlation_id": "req-abc123",
    "resource": "api:openai:gpt-4",
    "action": "api_call"
}
```

---

## 6. Technical Implementation Details

### 6.1 Cryptographic Components

#### Key Generation (ECDSA P-256)
```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_key_pair():
    # Generate ECDSA P-256 private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Derive public key
    public_key = private_key.public_key()

    # Serialize for storage
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return KeyPair(private_key=private_pem, public_key=public_pem)
```

#### Mandate Signing
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def sign_mandate(mandate: dict, private_key: ec.EllipticCurvePrivateKey) -> str:
    # Create canonical message
    message = f"{mandate['id']}:{mandate['subject_id']}:{mandate['expires_at']}:{mandate['resource_scope']}"
    message_bytes = message.encode('utf-8')

    # Sign with ECDSA
    signature = private_key.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA256())
    )

    # Base64 encode signature
    return base64.b64encode(signature).decode('utf-8')
```

### 6.2 Authority Evaluation Algorithm

```python
def evaluate_authority(
    mandate: dict,
    principal: Principal,
    requested_action: str,
    requested_resource: str
) -> AuthorityDecision:
    """
    Fail-closed authority evaluation.
    Any uncertainty or error results in DENY.
    """
    try:
        # 1. Verify mandate exists
        if not mandate:
            return AuthorityDecision(allowed=False, reason="No mandate provided")

        # 2. Verify signature (cryptographic identity proof)
        if not verify_mandate_signature(mandate, principal):
            return AuthorityDecision(allowed=False, reason="Invalid signature")

        # 3. Check expiration
        if is_expired(mandate):
            return AuthorityDecision(allowed=False, reason="Mandate expired")

        # 4. Check revocation
        if is_revoked(mandate):
            return AuthorityDecision(allowed=False, reason="Mandate revoked")

        # 5. Verify scope match
        if not scope_matches(mandate, requested_action, requested_resource):
            return AuthorityDecision(allowed=False, reason="Scope mismatch")

        # 6. Check delegation chain (if delegated)
        if mandate.get("delegation_token"):
            if not validate_delegation_chain(mandate["delegation_token"]):
                return AuthorityDecision(allowed=False, reason="Invalid delegation")

        # 7. Check replay protection
        if is_replay(mandate):
            return AuthorityDecision(allowed=False, reason="Replay detected")

        # All checks passed
        return AuthorityDecision(allowed=True, reason="All checks passed")

    except Exception as e:
        # Fail closed on any error
        log.error(f"Authority evaluation error: {e}")
        return AuthorityDecision(allowed=False, reason=f"Evaluation error: {e}")
```

### 6.3 Merkle Tree Integrity

```python
import hashlib
from typing import List

def create_merkle_tree(events: List[dict]) -> str:
    """
    Create Merkle tree from ledger events for cryptographic integrity.
    """
    # Hash each event
    leaf_hashes = [
        hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
        for event in events
    ]

    # Build tree bottom-up
    while len(leaf_hashes) > 1:
        next_level = []
        for i in range(0, len(leaf_hashes), 2):
            left = leaf_hashes[i]
            right = leaf_hashes[i+1] if i+1 < len(leaf_hashes) else left

            combined = left + right
            parent_hash = hashlib.sha256(combined.encode()).hexdigest()
            next_level.append(parent_hash)

        leaf_hashes = next_level

    # Root hash
    return leaf_hashes[0]

def verify_merkle_proof(event: dict, merkle_proof: List[str], merkle_root: str) -> bool:
    """
    Verify that an event is part of a Merkle tree with given root.
    """
    current_hash = hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()

    for sibling_hash in merkle_proof:
        combined = current_hash + sibling_hash
        current_hash = hashlib.sha256(combined.encode()).hexdigest()

    return current_hash == merkle_root
```

---

## 7. Deployment & Operations

### 7.1 Infrastructure Setup

```bash
# Using Caracal Flow (TUI) - one-click setup
caracal-flow
# Navigate to "Infrastructure" → "Provision" → Select PostgreSQL + Kafka

# Or manual setup
docker-compose up -d  # PostgreSQL + Redis + Kafka

# Initialize database
caracal db migrate upgrade head

# Create admin principal
caracal agent register \
  --name "admin" \
  --owner "security@company.com" \
  --admin
```

### 7.2 Integration Patterns

#### Pattern 1: SDK Integration (Python)
```python
from caracal.sdk import AuthorityClient

# Initialize client
client = AuthorityClient(base_url="http://caracal.internal:8000")

# Request mandate before action
mandate = client.request_mandate(
    issuer_id=admin_principal_id,
    subject_id=agent_principal_id,
    resource_scope=["api:stripe:charges"],
    action_scope=["create_charge"],
    validity_seconds=300  # 5 minutes for this transaction
)

# Validate before executing sensitive action
decision = client.validate_mandate(
    mandate_id=mandate["mandate_id"],
    requested_action="create_charge",
    requested_resource="api:stripe:charges"
)

if decision["allowed"]:
    # Execute action with mandate in context
    result = stripe.Charge.create(
        amount=1000,
        currency="usd",
        headers={"X-Execution-Mandate": mandate["mandate_id"]}
    )
```

#### Pattern 2: Gateway Proxy (HTTP Middleware)
```python
from fastapi import FastAPI, Header, HTTPException
from caracal.gateway import AuthorityEvaluator

app = FastAPI()
evaluator = AuthorityEvaluator()

@app.middleware("http")
async def authority_enforcement(request: Request, call_next):
    # Extract mandate from header
    mandate_id = request.headers.get("X-Execution-Mandate")

    if not mandate_id:
        raise HTTPException(status_code=401, detail="No mandate provided")

    # Validate mandate
    decision = evaluator.evaluate(
        mandate_id=mandate_id,
        requested_action=request.method,
        requested_resource=request.url.path
    )

    if not decision.allowed:
        raise HTTPException(status_code=403, detail=decision.reason)

    # Proceed with request
    response = await call_next(request)
    return response
```

#### Pattern 3: MCP Integration (Model Context Protocol)
```python
from caracal.mcp import MCPAdapter, MCPContext

# Initialize MCP adapter
adapter = MCPAdapter(authority_evaluator=evaluator)

# Intercept tool calls
async def handle_mcp_request(request: MCPRequest):
    # Extract agent identity and mandate from context
    context = MCPContext(
        principal_id=request.agent_id,
        mandate_id=request.headers.get("X-Execution-Mandate")
    )

    # Validate before executing tool
    result = await adapter.intercept_tool_call(
        tool_name=request.tool_name,
        tool_args=request.tool_args,
        mcp_context=context
    )

    return result
```

### 7.3 Monitoring & Observability

```python
# Prometheus metrics
from caracal.monitoring import CaracalMetrics

metrics = CaracalMetrics()

# Authority decisions
metrics.authority_decisions_total.labels(
    principal="agent-01",
    decision="allowed"
).inc()

# Mandate issuance
metrics.mandates_issued_total.labels(
    issuer="admin",
    subject="agent-01"
).inc()

# Delegation depth
metrics.delegation_depth.labels(
    principal="agent-01"
).set(2)

# Ledger events
metrics.ledger_events_total.labels(
    event_type="ACTION_ALLOWED"
).inc()
```

---

## 8. Key Strengths & Limitations

### Strengths

1. **Cryptographic Identity**: Agents have verifiable, unforgeable identities
2. **Explicit Authority**: No action without explicit mandate
3. **Time-Bound**: All permissions expire automatically
4. **Immutable Audit**: Complete trail of all decisions
5. **Fail-Closed**: Deny by default on any error
6. **Delegation Control**: Parent-child authority with scope narrowing
7. **Replay Protection**: Prevents mandate reuse attacks
8. **MCP Integration**: Works with agentic frameworks

### Limitations

1. **Performance Overhead**: Cryptographic operations add latency (~10-50ms per request)
2. **Infrastructure Complexity**: Requires PostgreSQL, Redis, optional Kafka
3. **Key Management**: Private keys must be securely stored and rotated
4. **Learning Curve**: Developers must understand authority model
5. **Single Point of Failure**: Authority gateway must be highly available
6. **Not for Real-Time**: Validation latency unsuitable for sub-millisecond systems

---

## 9. Comparison to Traditional Approaches

| Aspect | API Keys | OAuth 2.0 | RBAC | Caracal |
|--------|----------|-----------|------|---------|
| **Identity Verification** | None | Token-based | Role-based | Cryptographic (ECDSA) |
| **Authority Granularity** | All-or-nothing | Scope-based | Role-based | Resource + Action + Conditions |
| **Time-Bound** | No (long-lived) | Yes (access tokens) | No | Yes (TTL mandates) |
| **Audit Trail** | Optional | Optional | Optional | Immutable (always) |
| **Delegation** | Not supported | Delegation tokens | Role inheritance | Cryptographic chain |
| **Revocation** | Delete key | Revoke token | Change role | Instant revocation |
| **Fail Semantics** | Fail open | Fail open | Fail open | Fail closed |
| **Replay Protection** | No | No | No | Yes (nonce-based) |
| **Agent-Specific** | No | No | No | Yes (designed for agents) |

---

## 10. Use Cases

### Use Case 1: Autonomous Trading Bot
```python
# Problem: Bot can access trading API 24/7 with static API key
# Solution: Time-bound mandates with cost limits

# Register trading bot identity
trading_bot = registry.register_principal(
    name="trading-bot-prod",
    owner="quant-team@hedge.fund"
)

# Create policy: can only trade during market hours
policy = AuthorityPolicy.create(
    principal_id=trading_bot.id,
    resource_scope=["api:alpaca:orders"],
    action_scope=["place_order"],
    conditions={
        "time_window": "market_hours",
        "max_order_value_usd": 10000,
        "max_daily_trades": 100
    }
)

# Issue mandate (expires in 1 hour)
mandate = mandate_mgr.issue_mandate(
    subject_id=trading_bot.id,
    validity_seconds=3600
)

# Bot must renew mandate every hour
# If bot malfunctions, mandate expires and trading stops
```

### Use Case 2: Multi-Agent Customer Support
```python
# Problem: Parent orchestrator delegates to specialized agents
# Solution: Delegation chains with scope narrowing

# Orchestrator (parent)
orchestrator = registry.register_principal(name="support-orchestrator")

# Specialized agents (children)
email_agent = registry.register_principal(name="email-responder")
ticket_agent = registry.register_principal(name="ticket-creator")

# Orchestrator delegates limited authority to email agent
delegation_token = delegation_mgr.create_delegation_token(
    parent_principal_id=orchestrator.id,
    child_principal_id=email_agent.id,
    scope_narrowing={
        "resources": ["api:gmail:send"],  # Can only send emails
        "actions": ["send_email"],
        "max_emails_per_hour": 50
    },
    validity_seconds=3600
)

# Email agent requests mandate with delegation token
email_mandate = mandate_mgr.issue_mandate(
    issuer_id=orchestrator.id,
    subject_id=email_agent.id,
    delegation_token=delegation_token
)

# Complete audit trail shows delegation chain
# orchestrator → email_agent → [email sent]
```

### Use Case 3: Data Pipeline with Multiple Agents
```python
# Problem: Complex pipeline with 5 agents, unclear who modified data
# Solution: Identity tracking through pipeline

# Register pipeline agents
scraper = registry.register_principal(name="web-scraper")
cleaner = registry.register_principal(name="data-cleaner")
enricher = registry.register_principal(name="data-enricher")
validator = registry.register_principal(name="data-validator")
publisher = registry.register_principal(name="data-publisher")

# Each agent gets narrow mandate for its step
scraper_mandate = mandate_mgr.issue_mandate(
    subject_id=scraper.id,
    resource_scope=["web:target-site.com"],
    action_scope=["http_get"],
    validity_seconds=1800
)

cleaner_mandate = mandate_mgr.issue_mandate(
    subject_id=cleaner.id,
    resource_scope=["db:raw_data:read", "db:clean_data:write"],
    action_scope=["db_read", "db_write"]
)

# Ledger shows complete lineage
# scraper → raw_data → cleaner → clean_data → enricher → ...
```

---

## 11. Summary & Key Takeaways

### What Makes Caracal Different

Caracal is **not** another authentication/authorization system. It's a pre-execution authority enforcement layer specifically designed for AI agents in production.

**Key Differentiators:**

1. **Agent-First Design**: Every concept (principals, mandates, delegation) designed for autonomous agents, not humans
2. **Cryptographic Proof**: ECDSA signatures provide unforgeable proof of authorization
3. **Fail-Closed Everywhere**: Any error or uncertainty results in denial, not execution
4. **Time-Bound Everything**: No long-lived credentials; all authority expires
5. **Immutable Audit**: Merkle-tree-verified ledger provides cryptographic proof of all decisions
6. **Explicit Delegation**: Parent-child authority transfer with cryptographic chain and scope narrowing

### Agent Identity Model

Caracal treats agent identity as a **cryptographic primitive**:

- **Unique identity**: UUID + human-readable name
- **Cryptographic proof**: ECDSA P-256 key pair
- **Hierarchical relationships**: Parent-child delegation chains
- **Persistent registry**: Atomic writes with corruption protection
- **Complete audit**: Every action tied to principal identity

### When to Use Caracal

**Good fit:**
- Production AI agents executing irreversible actions
- Multi-agent systems with complex delegation
- Regulated industries requiring audit trails
- High-value transactions (financial, healthcare, legal)
- Autonomous systems requiring human oversight

**Poor fit:**
- Prototype/demo agents
- Real-time systems requiring sub-millisecond latency
- Simple single-agent scripts
- Low-risk read-only operations

### Getting Started

```bash
# Install
pip install caracal-authority

# Start Caracal Flow (interactive TUI)
caracal-flow

# Or use CLI
caracal agent register --name "my-first-agent" --owner "me@company.com"
caracal policies create --principal-id <ID> --resources "*" --actions "*"
caracal mandates issue --principal-id <ID> --ttl 3600

# Integrate in code
from caracal.sdk import AuthorityClient
client = AuthorityClient()
mandate = client.request_mandate(...)
```

---

## References

- **Repository**: `/Users/guoliangwang/Code/Python/caracal`
- **Documentation**: `caracal/docs/`
- **Examples**: `caracal/examples/`
- **Tests**: `caracal/tests/`

---

*Document created: 2026-02-16*
*Analysis of Caracal v0.x.x*
