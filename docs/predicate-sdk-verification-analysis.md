# Predicate Python SDK: Adding Determinism to AI Agents Through Verification

## Executive Summary

The **Predicate Python SDK** (formerly Sentience SDK) is a verification-first runtime layer that transforms browser-based AI agents from probabilistic "hope-based" automation to deterministic, observable, and reproducible systems. It implements a **predicate-based verification system** that gates agent progress, ensures actions have effects, and provides complete observability through traces and artifacts.

**Repository**: `/Users/guoliangwang/Code/Sentience/sdk-python`

**Core Value Proposition**: *"Replace hope with proof in AI agent automation"*

---

## 1. The Determinism Problem in AI Agents

### 1.1 Traditional Agent Failures

Without verification, AI agents exhibit non-deterministic behaviors:

```python
# Traditional agent code (no verification)
await page.goto("https://example.com")
await page.click("button")  # Did it work? Unknown.
await page.scroll(600)       # Did page advance? Unknown.
# Agent continues blindly...
```

**Problems:**
- **Silent failures**: Actions fail but agent continues
- **Scroll ghosts**: `scroll()` returns but page didn't advance (overlay, focus issue)
- **Navigation failures**: Page loads but critical elements missing
- **Non-reproducible**: Same code produces different outcomes
- **Expensive**: Every step requires vision model ($$$)
- **No debugging**: When failure occurs, no evidence preserved

### 1.2 The Core Insight

> **Probabilistic reasoning cannot produce deterministic accountability.**

Agents make probabilistic decisions (via LLMs), but **action effects should be deterministically verified**.

---

## 2. Predicate's Verification System

### 2.1 Core Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Execution Loop                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────┐                                         │
│  │  Agent Action  │  (LLM-driven: probabilistic)            │
│  │  click/scroll  │                                         │
│  └───────┬────────┘                                         │
│          │                                                   │
│          ▼                                                   │
│  ┌────────────────┐                                         │
│  │   Snapshot     │  Capture current page state            │
│  │ (DOM + Screen) │                                         │
│  └───────┬────────┘                                         │
│          │                                                   │
│          ▼                                                   │
│  ┌────────────────────────────────┐                        │
│  │   Predicate Verification       │  (Deterministic)        │
│  │  ├─ url_contains("cart")       │                        │
│  │  ├─ exists("role=button")      │                        │
│  │  └─ scroll_advanced(min=50px)  │                        │
│  └───────┬────────────────────────┘                        │
│          │                                                   │
│      ┌───┴───┐                                              │
│      │       │                                              │
│   PASS    FAIL                                              │
│      │       │                                              │
│      ▼       ▼                                              │
│  Continue  Halt + Capture Artifacts                        │
│            (trace, clip, snapshot, diagnostics)            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 The Predicate Type

At the core is a simple, composable type:

```python
from typing import Callable
from dataclasses import dataclass

# A predicate is a function that checks current state
type Predicate = Callable[[AssertContext], AssertOutcome]

@dataclass
class AssertContext:
    """Context passed to predicates for evaluation"""
    snapshot: Snapshot | None    # Current page snapshot
    url: str | None              # Current URL
    step_id: str | None          # For trace correlation
    downloads: list[dict]        # Download tracking

@dataclass
class AssertOutcome:
    """Result of predicate evaluation"""
    passed: bool                 # Did it pass?
    reason: str                  # Human-readable reason
    details: dict               # Structured details (matched elements, etc.)
```

**Key Design**: Predicates are **pure functions** - no side effects, just state → boolean + reason.

### 2.3 Three Verification Methods

```python
class AgentRuntime:
    def assert_(
        self,
        predicate: Predicate,
        label: str,
        required: bool = False
    ) -> bool:
        """
        Evaluate predicate immediately, record outcome.

        If required=True and fails:
        - Persist failure artifacts (frames, clip, snapshot)
        - Emit 'verification' trace event
        - Optionally halt execution

        Returns: passed (bool)
        """

    def check(
        self,
        predicate: Predicate,
        label: str,
        required: bool = False
    ) -> AssertionHandle:
        """
        Fluent form for retry logic.

        Usage:
            result = await runtime.check(
                exists("role=heading"),
                label="page_stable"
            ).eventually(timeout_s=10, poll_ms=250)

        Returns: AssertionHandle for .once() or .eventually()
        """

    def assert_done(
        self,
        predicate: Predicate,
        label: str
    ) -> bool:
        """
        Task completion marker.

        Equivalent to assert_(predicate, label, required=True)
        but also sets self._task_done = True.

        Used to mark successful task completion.
        """
```

---

## 3. Predicate Library: Deterministic Checks

### 3.1 URL Predicates

```python
from predicate.verification import url_contains, url_matches

# Substring match
runtime.assert_(
    url_contains("/cart"),
    label="on_cart_page",
    required=True
)

# Regex match
runtime.assert_(
    url_matches(r"^https://.*\.example\.com/checkout"),
    label="on_checkout_subdomain"
)
```

**Determinism**: URL checks are 100% deterministic - no model inference needed.

### 3.2 Element Existence Predicates

```python
from predicate.verification import exists, not_exists, element_count

# Element exists
runtime.assert_(
    exists("role=button text~'Add to Cart'"),
    label="add_to_cart_button_visible",
    required=True
)

# Element does NOT exist (e.g., loading spinner gone)
runtime.assert_(
    not_exists("text~'Loading...'"),
    label="page_loaded"
)

# Element count bounds
runtime.assert_(
    element_count("role=listitem", min=5, max=20),
    label="search_results_count"
)
```

**Determinism**: Uses semantic selector engine (role, text, value matchers) with deterministic DOM traversal.

### 3.3 State-Aware Predicates (Pro/Enterprise)

Require SmartElements with state fields:

```python
from predicate.verification import (
    is_enabled, is_disabled, is_checked,
    value_equals, value_contains
)

# Checkbox/radio state
runtime.assert_(
    is_checked("role=checkbox label~'Terms'"),
    label="terms_accepted",
    required=True
)

# Input value
runtime.assert_(
    value_equals("role=textbox name~'email'", "user@example.com"),
    label="email_entered"
)

# Button state
runtime.assert_(
    is_enabled("role=button text~'Submit'"),
    label="submit_enabled"
)
```

**Determinism**: Direct state inspection (not model-inferred) from browser's accessibility tree.

### 3.4 Combinator Predicates

```python
from predicate.verification import all_of, any_of, custom

# AND logic - all must pass
page_ready = runtime.assert_(
    all_of(
        url_contains("/dashboard"),
        exists("role=heading"),
        not_exists("text~'Loading'")
    ),
    label="dashboard_fully_loaded",
    required=True
)

# OR logic - any can pass
has_success_indicator = runtime.assert_(
    any_of(
        exists("text~'Success'"),
        exists("text~'Completed'"),
        exists("role=alert text~'Done'")
    ),
    label="task_succeeded"
)

# Custom predicate
def cart_total_exceeds(min_usd: float):
    def predicate(ctx: AssertContext) -> AssertOutcome:
        # Parse cart total from snapshot
        total = parse_cart_total(ctx.snapshot)
        passed = total >= min_usd
        return AssertOutcome(
            passed=passed,
            reason=f"Cart total ${total} >= ${min_usd}" if passed else f"Cart total ${total} < ${min_usd}",
            details={"total_usd": total, "min_usd": min_usd}
        )
    return predicate

runtime.assert_(
    custom(cart_total_exceeds(100.0), label="min_total"),
    label="cart_minimum_met",
    required=True
)
```

---

## 4. How Verification Adds Determinism

### 4.1 Gated Progress (Core Principle)

**Without Verification** (probabilistic):
```python
# Traditional agent - no gates
await page.goto("https://example.com")
await page.click("button")  # Hope it worked
await page.scroll(600)       # Hope page advanced
result = await extract_data()  # Hope data is there
```

**With Verification** (deterministic):
```python
# Predicate agent - explicit gates
runtime.begin_step("Navigate and verify")

await page.goto("https://example.com")
await runtime.snapshot()

# GATE: Verify page loaded before proceeding
runtime.assert_(
    all_of(
        url_contains("example.com"),
        exists("role=heading"),
        not_exists("text~'Error'")
    ),
    label="page_loaded",
    required=True  # <-- HALT if fails
)

# Only reached if assertion passed
await page.click("button")
await runtime.snapshot()

# GATE: Verify click had effect
runtime.assert_(
    exists("role=dialog"),
    label="dialog_opened",
    required=True
)

# GATE: Verify scroll advanced
ok = await runtime.scroll_by(600, verify=True, min_delta_px=50)
if not ok:
    raise RuntimeError("Scroll blocked - likely overlay or nested scroller")

# Extract data only after all gates passed
result = await extract_data()
```

**Determinism Added**:
- Actions only proceed after verification
- Failures detected immediately (not later)
- Evidence captured at point of failure
- Reproducible: same gates trigger on same failures

### 4.2 Deterministic Scroll Verification (Unique)

**The Problem**: `scroll()` returns success but page didn't advance (overlay, focus issue, nested scroller).

**Predicate's Solution**:
```python
ok = await runtime.scroll_by(
    dy=600,
    verify=True,           # Check scrollTop actually changed
    min_delta_px=50,       # Minimum pixel movement required
    label="scroll_effective",
    required=True,
    timeout_s=5.0
)

if not ok:
    # Scroll was blocked - diagnose why
    snapshot = await runtime.snapshot()
    # Check for overlay: exists("role=dialog")
    # Check for focus: exists("[aria-hidden='false']")
```

**Implementation** (from `agent_runtime.py` lines 778-856):
```python
async def scroll_by(self, dy: int, verify: bool = False, min_delta_px: int = 50):
    # 1. Get initial scroll position
    before = await self.backend.refresh_page_info()
    initial_scroll_top = before.scroll_top

    # 2. Execute scroll
    await self.backend.wheel(delta_y=dy)
    await asyncio.sleep(0.3)  # Allow scroll to complete

    # 3. Get final scroll position
    after = await self.backend.refresh_page_info()
    final_scroll_top = after.scroll_top

    # 4. Verify scroll advanced
    delta = abs(final_scroll_top - initial_scroll_top)
    advanced = delta >= min_delta_px

    # 5. Record outcome
    if verify:
        outcome = AssertOutcome(
            passed=advanced,
            reason=f"Scroll advanced {delta}px (min: {min_delta_px}px)",
            details={
                "initial_scroll_top": initial_scroll_top,
                "final_scroll_top": final_scroll_top,
                "delta_px": delta,
                "min_delta_px": min_delta_px
            }
        )
        self._record_outcome(outcome, label, required=False, kind="scroll_verify")

    return advanced
```

**Determinism**: Scroll success is **provable** (pixel delta >= threshold), not assumed.

### 4.3 Failure Detection with Evidence

**Without Verification**:
```python
# Agent fails silently, no evidence
await page.click("nonexistent-button")  # Silently fails
# ... 50 steps later ...
# Task fails with "data not found" - no idea where it broke
```

**With Verification**:
```python
runtime.begin_step("Click submit button")
await runtime.snapshot()

# This assertion will fail if button doesn't exist
runtime.assert_(
    exists("role=button text~'Submit'"),
    label="submit_button_exists",
    required=True  # <-- Triggers artifact capture
)

# When assertion fails:
# 1. Last 15s of frames captured
# 2. MP4 clip generated (via ffmpeg)
# 3. Snapshot + diagnostics saved
# 4. Trace event emitted with failure reason
# 5. Run halts (if required=True)
```

**Artifacts Captured** (from `failure_artifacts.py`):

| Artifact | Purpose |
|----------|---------|
| **Frame buffer** | Last 15s of viewport screenshots (JPEG @ 0.5-2 fps) |
| **Video clip** | MP4 generated from frames |
| **Snapshot** | HTML representation of DOM at failure |
| **Diagnostics** | Layout analysis, modals, CAPTCHA detection, ordinality hints |
| **Trace event** | Timestamped event with reason code, details, correlation ID |

**Determinism**: Failures are **observable** and **reproducible** via trace replay in Studio.

### 4.4 Bounded Retries (Not Infinite Loops)

**Without Verification**:
```python
# Agent retries forever, wasting time/cost
while True:
    try:
        element = page.locator("button")
        element.click()
        break
    except:
        await asyncio.sleep(1)  # Infinite loop
```

**With Verification**:
```python
# Bounded retry with .eventually()
result = await runtime.check(
    exists("role=button text~'Submit'"),
    label="submit_button_visible"
).eventually(
    timeout_s=10,     # Max 10 seconds
    poll_ms=250       # Poll every 250ms
)

if result.passed:
    # Element appeared within timeout
    await page.click("role=button text~'Submit'")
else:
    # Timeout reached, element never appeared
    # Failure artifacts captured
    raise RuntimeError(f"Button not found: {result.reason}")
```

**Determinism**: Retries are **bounded** (timeout) and **recorded** (trace events show poll attempts).

### 4.5 Smart Failure Intelligence

When assertions fail, Predicate computes **why**:

```python
# Example: Assertion fails
runtime.assert_(
    exists("role=button text~'Submitt'"),  # Typo: "Submitt"
    label="submit_button",
    required=True
)

# Outcome includes suggestions:
outcome = AssertOutcome(
    passed=False,
    reason="No element matches selector",
    details={
        "reason_code": "selector_not_found",
        "nearest_matches": [
            {
                "selector": "role=button text~'Submit'",  # <-- Close match
                "similarity": 0.95,
                "text": "Submit"
            },
            {
                "selector": "role=button text~'Cancel'",
                "similarity": 0.4,
                "text": "Cancel"
            }
        ],
        "suggestions": [
            "Did you mean: role=button text~'Submit'?",
            "Check for typos in selector"
        ]
    }
)
```

**Determinism**: Failures are **actionable** with suggestions, not just "element not found".

---

## 5. Step-Based Verification Flow

### 5.1 Complete Flow Example

```python
from predicate import AgentRuntime, get_extension_dir
from predicate.verification import exists, url_contains, all_of

# Initialize runtime
runtime = AgentRuntime.from_playwright_page(page, tracer=tracer)

# ========================================
# Step 1: Navigate and verify page load
# ========================================
runtime.begin_step("Navigate to example.com")

await page.goto("https://example.com")
await runtime.snapshot()

# Verify page loaded correctly
page_loaded = runtime.assert_(
    all_of(
        url_contains("example.com"),
        exists("role=heading"),
        not_exists("text~'Error'")
    ),
    label="page_loaded",
    required=True
)

await runtime.emit_step_end()

# ========================================
# Step 2: Verify interactive elements
# ========================================
runtime.begin_step("Check interactive elements")

await runtime.snapshot()

# Check multiple elements
runtime.assert_(exists("role=link"), "has_links")
runtime.assert_(exists("role=heading"), "has_heading")
runtime.assert_(element_count("role=link", min=1), "link_count")

# Composite check with bounded retry
page_ready = await runtime.check(
    all_of(
        exists("role=link"),
        not_exists("text~'Loading'")
    ),
    label="page_fully_ready"
).eventually(timeout_s=10, poll_ms=250)

await runtime.emit_step_end()

# ========================================
# Step 3: Task completion
# ========================================
runtime.begin_step("Verify task completion")

await runtime.snapshot()

# Mark task as done
task_done = runtime.assert_done(
    exists("text~'Example Domain'"),
    label="reached_goal"
)

await runtime.emit_step_end()
```

### 5.2 Trace Events Emitted

For each step, these events are emitted to `Tracer`:

1. **snapshot** - Page state captured (includes screenshot_base64, elements)
2. **verification** - Each assertion result (passed, reason, details)
3. **step_end** - Step complete with accumulated assertions

**Example trace event** (verification):
```json
{
  "type": "verification",
  "timestamp": "2025-01-15T10:15:23.456Z",
  "step_id": "step-1",
  "label": "page_loaded",
  "passed": true,
  "required": true,
  "reason": "All predicates passed",
  "details": {
    "predicates": [
      {
        "type": "url_contains",
        "substring": "example.com",
        "matched": true
      },
      {
        "type": "exists",
        "selector": "role=heading",
        "matched": true,
        "element_id": "elem-42"
      }
    ]
  },
  "correlation_id": "run-abc123"
}
```

---

## 6. Integration with Agent Frameworks

### 6.1 Browser-Use Integration

```python
from browser_use import BrowserSession, BrowserProfile
from predicate import get_extension_dir, AgentRuntime
from predicate.backends import BrowserUseAdapter

# 1. Load Predicate extension in browser-use
extension_dir = get_extension_dir()
profile = BrowserProfile(args=[f"--load-extension={extension_dir}"])
session = BrowserSession(browser_profile=profile)
await session.start()

# 2. Create BrowserBackend from session
adapter = BrowserUseAdapter(session)
backend = await adapter.create_backend()

# 3. Create runtime
runtime = AgentRuntime(backend=backend, tracer=tracer)

# 4. browser-use drives navigation, Predicate verifies
page = await session.get_current_page()
await page.goto("https://example.com")

runtime.begin_step("Verify page loaded")
await runtime.snapshot()
runtime.assert_(exists("role=heading"), label="has_heading", required=True)
await runtime.emit_step_end()
```

**Key Design**: Predicate's `BrowserBackend` protocol is minimal (10 methods):
- `refresh_page_info()` - viewport + scroll
- `eval(js)` / `call(fn, args)` - JavaScript execution
- `screenshot_png()` / `screenshot_jpeg()`
- `mouse_move()` / `mouse_click()` / `wheel()`
- `type_text()` / `press_key()`

Any browser automation framework can implement this protocol.

### 6.2 Playwright Integration (Direct)

```python
from playwright.async_api import async_playwright
from predicate import AgentRuntime

async with async_playwright() as p:
    browser = await p.chromium.launch()
    page = await browser.new_page()

    # Direct Playwright page → AgentRuntime
    runtime = AgentRuntime.from_playwright_page(page=page, tracer=tracer)

    # Use runtime for verification
    await page.goto("https://example.com")
    await runtime.snapshot()
    runtime.assert_(exists("role=heading"), "has_heading", required=True)
```

### 6.3 Sidecar Mode (Attach to Existing Agents)

```python
from predicate import SentienceDebugger

# Your framework (LangGraph, AutoGen, custom) drives execution
# Predicate just snapshots + verifies

dbg = SentienceDebugger.attach(page, tracer=tracer)

async with dbg.step("agent_step: navigate"):
    # Your agent does work
    await your_agent.navigate_to_page()

    # Snapshot result
    await dbg.snapshot()

    # Verify with bounded retry
    result = await dbg.check(
        exists("role=heading"),
        label="heading_present"
    ).eventually(timeout_s=10)

    if not result.passed:
        raise RuntimeError(f"Navigation failed: {result.reason}")
```

### 6.4 LangChain Integration (Tools-based)

From `/predicate/integrations/langchain/`:

```python
from langchain.agents import AgentExecutor
from predicate.integrations.langchain import get_langchain_tools

# Get LLM-callable tools
tools = get_langchain_tools(runtime)
# tools = [
#   "sentience_snapshot",
#   "sentience_click",
#   "sentience_type_text",
#   "sentience_scroll",
#   "sentience_assert_exists",
#   ...
# ]

agent = AgentExecutor.from_llm_and_tools(
    llm=llm,
    tools=tools,
    verbose=True
)

result = agent.run("Navigate to example.com and verify heading exists")
```

---

## 7. Controlled Perception (Token Efficiency)

### 7.1 The Token Problem

**Without Predicate**:
```python
# Full DOM dump to LLM (thousands of tokens)
html = await page.content()
prompt = f"Find the submit button in: {html}"  # 10,000+ tokens
response = llm.complete(prompt)  # $$$ expensive
```

**With Predicate**:
```python
# Semantic snapshot with pruning
snapshot = await runtime.snapshot(
    limit=50,              # Max 50 elements
    filter=SnapshotFilter(
        clickable_only=True,
        in_viewport_only=True,
        min_importance=100
    ),
    screenshot=False  # No vision model needed
)

# Snapshot contains 50 SmartElements (with state)
# vs. 1000s of raw DOM nodes
# → Lower token cost, faster LLM inference
```

### 7.2 SmartElements (Pro/Enterprise)

Server-side refinement adds state fields:

```json
{
  "id": "elem-42",
  "role": "button",
  "text": "Submit",
  "value": null,
  "state": {
    "enabled": true,
    "disabled": false,
    "checked": false,
    "expanded": false
  },
  "bbox": {"x": 100, "y": 200, "width": 80, "height": 40},
  "importance": 250
}
```

**Determinism**: State fields are directly inspected (not model-inferred) from browser's accessibility tree.

---

## 8. Failure Artifacts & Debugging

### 8.1 Automatic Artifact Capture

When `required=True` assertion fails:

```python
# Automatically triggered
self._persist_failure_artifacts(reason="assert_failed:selector_not_found")
```

**Captured Artifacts**:

| Artifact | Purpose | Size |
|----------|---------|------|
| **Frame buffer** | Last 15s of viewport screenshots (JPEG @ 0.5-2 fps) | ~300KB/frame |
| **Video clip** | MP4 generated from frames (requires ffmpeg) | ~5MB for 15s |
| **Snapshot** | HTML representation of DOM at failure | ~50KB |
| **Diagnostics** | Layout analysis, modals, CAPTCHA detection | ~10KB |
| **Trace event** | Timestamped event with reason code, details | ~5KB |

**Configuration**:
```python
from predicate.failure_artifacts import FailureArtifactsOptions

options = FailureArtifactsOptions(
    buffer_seconds=15.0,
    persist_mode="onFail",  # or "always"
    frame_format="jpeg",
    fps=0.5,
    redact_snapshot_values=True,  # PII masking
)

runtime = AgentRuntime(..., failure_artifacts_options=options)
```

### 8.2 Studio Replay

All trace events → Sentience Studio for:
- Step-by-step replay
- Snapshot inspection at each step
- Assertion timeline (passed/failed)
- Video clip playback
- Diagnostics analysis

**Determinism**: Full run is **reproducible** via trace replay.

---

## 9. Comparison: With vs. Without Verification

| Aspect | Without Predicate | With Predicate |
|--------|-------------------|----------------|
| **Action Verification** | "Hope it worked" | `assert_(exists(...))` - proved |
| **Scroll Verification** | Returns but page didn't advance | `scroll_by(verify=True)` - checked |
| **Failure Detection** | Silent, discovered later | Immediate with evidence |
| **Debugging** | No artifacts, guess where it broke | Trace + clip + snapshot + diagnostics |
| **Retries** | Infinite loops or hardcoded | Bounded `.eventually(timeout_s=10)` |
| **Token Cost** | Full DOM dump (10K+ tokens) | Semantic snapshot (50 elements) |
| **Vision Models** | Required for every step | Optional (local 3B models sufficient) |
| **Reproducibility** | Non-deterministic | Trace-driven replay |
| **Privacy** | Screenshots sent to LLM | Optional redaction, local processing |
| **Observability** | Logs if lucky | Full trace with correlation IDs |

---

## 10. Key Design Principles

### 10.1 Minimal Backend Protocol

Only 10 methods required to implement `BrowserBackend`:

```python
class BrowserBackend(Protocol):
    async def refresh_page_info(self) -> PageInfo: ...
    async def eval(self, js: str) -> Any: ...
    async def call(self, fn: str, args: list) -> Any: ...
    async def screenshot_png(self) -> bytes: ...
    async def screenshot_jpeg(self, quality: int) -> bytes: ...
    async def mouse_move(self, x: int, y: int): ...
    async def mouse_click(self, x: int, y: int): ...
    async def wheel(self, delta_y: int): ...
    async def type_text(self, text: str): ...
    async def press_key(self, key: str): ...
```

**Result**: Works with Playwright, Puppeteer, CDP, browser-use, Selenium (via adapters).

### 10.2 Composable Predicates

Predicates are **pure functions** - easy to compose:

```python
# Base predicates
p1 = url_contains("/cart")
p2 = exists("role=button")
p3 = not_exists("text~'Loading'")

# Composite predicates
page_ready = all_of(p1, p2, p3)
has_success = any_of(
    exists("text~'Success'"),
    exists("text~'Done'")
)
```

### 10.3 Fail-Closed Semantics

When `required=True`, failures **halt execution**:

```python
runtime.assert_(
    exists("role=button"),
    label="button_exists",
    required=True  # <-- HALT if fails
)

# This line only reached if assertion passed
await page.click("role=button")
```

**Result**: Failures detected immediately, not propagated silently.

### 10.4 Trace-Driven Observability

Every event indexed + queryable:

```python
# Query trace events
events = tracer.query(
    step_id="step-1",
    event_type="verification",
    passed=False  # Only failures
)

for event in events:
    print(f"Failed: {event['label']} - {event['reason']}")
```

---

## 11. Real-World Example: E-Commerce Checkout

### Without Verification (Hope-Based)

```python
# Traditional agent - no verification
await page.goto("https://shop.example.com")
await page.click("text=Add to Cart")  # Hope it worked
await page.click("text=Checkout")      # Hope cart has items
await page.fill("input[name=email]", "user@example.com")
await page.click("text=Submit")        # Hope form valid
# ... agent continues blindly
```

**Problems**:
- If "Add to Cart" fails (out of stock), agent continues
- If cart is empty, checkout fails silently
- If form validation fails, agent doesn't know
- No evidence of what went wrong

### With Verification (Proof-Based)

```python
from predicate import AgentRuntime
from predicate.verification import exists, url_contains, all_of

runtime = AgentRuntime.from_playwright_page(page, tracer=tracer)

# ========================================
# Step 1: Add product to cart
# ========================================
runtime.begin_step("Add product to cart")

await page.goto("https://shop.example.com/products/widget")
await runtime.snapshot()

# Verify product page loaded
runtime.assert_(
    all_of(
        url_contains("/products/"),
        exists("role=button text~'Add to Cart'"),
        not_exists("text~'Out of Stock'")
    ),
    label="product_page_ready",
    required=True
)

await page.click("role=button text~'Add to Cart'")
await runtime.snapshot()

# Verify item added to cart
cart_updated = await runtime.check(
    exists("text~'Item added to cart'"),
    label="cart_confirmation"
).eventually(timeout_s=5)

if not cart_updated.passed:
    raise RuntimeError("Failed to add item to cart")

await runtime.emit_step_end()

# ========================================
# Step 2: Proceed to checkout
# ========================================
runtime.begin_step("Navigate to checkout")

await page.click("text=View Cart")
await runtime.snapshot()

# Verify cart has items
runtime.assert_(
    all_of(
        url_contains("/cart"),
        exists("role=button text~'Checkout'"),
        element_count("role=row", min=1)  # At least 1 cart item
    ),
    label="cart_has_items",
    required=True
)

await page.click("role=button text~'Checkout'")
await runtime.snapshot()

# Verify checkout page loaded
runtime.assert_(
    url_contains("/checkout"),
    label="on_checkout_page",
    required=True
)

await runtime.emit_step_end()

# ========================================
# Step 3: Fill checkout form
# ========================================
runtime.begin_step("Fill checkout form")

await runtime.snapshot()

# Verify form visible
runtime.assert_(
    all_of(
        exists("role=textbox name~'email'"),
        exists("role=textbox name~'address'"),
        exists("role=button text~'Submit'")
    ),
    label="checkout_form_visible",
    required=True
)

await page.fill("role=textbox name~'email'", "user@example.com")
await page.fill("role=textbox name~'address'", "123 Main St")
await runtime.snapshot()

# Verify form filled
runtime.assert_(
    all_of(
        value_equals("role=textbox name~'email'", "user@example.com"),
        value_contains("role=textbox name~'address'", "Main St")
    ),
    label="form_filled_correctly",
    required=True
)

await page.click("role=button text~'Submit'")
await runtime.snapshot()

# Verify order success
order_success = await runtime.check(
    any_of(
        exists("text~'Order Confirmed'"),
        exists("text~'Thank you for your order'")
    ),
    label="order_confirmed"
).eventually(timeout_s=10)

if not order_success.passed:
    raise RuntimeError("Order submission failed")

await runtime.emit_step_end()

# ========================================
# Step 4: Mark task done
# ========================================
runtime.begin_step("Task completion")

await runtime.snapshot()

task_done = runtime.assert_done(
    exists("text~'Order #'),
    label="order_number_visible"
)

await runtime.emit_step_end()
```

**Benefits**:
- Every step is gated with verification
- Failures detected immediately with evidence
- Trace shows exact step where failure occurred
- Artifacts available for debugging
- Reproducible via trace replay

---

## 12. Summary: How Verification Adds Determinism

### Core Transformation

```
┌─────────────────────────────────────────────────────────────┐
│                     From → To                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Probabilistic         →  Deterministic                     │
│  "Hope it worked"      →  "Proved it worked"                │
│  Silent failures       →  Immediate detection + evidence    │
│  Non-reproducible      →  Trace-driven replay               │
│  Expensive (vision)    →  Cost-aware (semantic snapshots)   │
│  Flaky retries         →  Bounded .eventually()             │
│  No debugging          →  Full observability (trace/clips)  │
│  Hope-based automation →  Proof-based automation            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Key Determinism Mechanisms

1. **Gated Progress**: Actions only proceed after verification passes
2. **Proof of Effect**: Scroll, click, type all verified (not assumed)
3. **Fail-Closed**: Failures halt execution (not silent propagation)
4. **Bounded Retries**: `.eventually(timeout_s=10)` vs. infinite loops
5. **Evidence Capture**: Artifacts at point of failure (trace, clip, snapshot)
6. **Trace-Driven Replay**: Full run reproducible in Studio
7. **Smart Failures**: Reason codes + suggestions (not just "failed")
8. **State Inspection**: Direct state fields (not model-inferred)

### When to Use Predicate

**Good fit:**
- Production browser automation
- Multi-step workflows requiring reliability
- Cost-sensitive deployments (reduce vision model usage)
- Privacy/compliance (local processing, redaction)
- Debugging complex agent failures

**Poor fit:**
- Prototype/demo agents (overhead not justified)
- Real-time systems (verification adds latency)
- Simple single-step scripts

---

## 13. Getting Started

### Installation

```bash
pip install predicate-sdk
```

### Basic Usage

```python
from playwright.async_api import async_playwright
from predicate import AgentRuntime, get_extension_dir
from predicate.verification import exists, url_contains

async with async_playwright() as p:
    # Launch browser with Predicate extension
    extension_dir = get_extension_dir()
    browser = await p.chromium.launch_persistent_context(
        user_data_dir="./browser-data",
        args=[f"--load-extension={extension_dir}"]
    )
    page = await browser.new_page()

    # Create runtime
    runtime = AgentRuntime.from_playwright_page(page)

    # Navigate and verify
    await page.goto("https://example.com")
    await runtime.snapshot()

    runtime.assert_(
        url_contains("example.com"),
        label="on_correct_domain",
        required=True
    )

    runtime.assert_(
        exists("role=heading"),
        label="has_heading",
        required=True
    )

    # Task completion
    runtime.assert_done(
        exists("text~'Example Domain'"),
        label="task_complete"
    )

    await browser.close()
```

---

## References

- **Repository**: `/Users/guoliangwang/Code/Sentience/sdk-python`
- **Documentation**: `sdk-python/docs/`
- **Examples**: `sdk-python/examples/`
- **Tests**: `sdk-python/tests/`

---

*Document created: 2026-02-16*
*Analysis of Predicate SDK v2.x.x*
