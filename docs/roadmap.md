### Non-Web AI Agents: 2026-02-16

This is a billion-dollar roadmap.

You currently own the **DOM** (Document Object Model). To build the "North Star," you need to abstract your platform to own the **State** of any environment.

Your core value proposition is **Deterministic Verification**. This means you reject probabilistic inputs (like computer vision/pixels) and focus on **Structured State Trees**.

Here is the strategic breakdown of how **Predicate Systems** expands beyond the browser.

---

### **The Universal Architecture**

To scale, you need to decouple your engine from the browser.

* **Current:** `Interceptor (Playwright)`  `State (DOM)`  `Policy (WASM)`
* **North Star:** `Interceptor (Adapter)`  `State (Universal Tree)`  `Policy (WASM)`

The **WASM Policy Engine** remains constant. You only need to build new **Adapters** for different environments.

---

### **Category 1: The "Computer Use" Agents (OS Automation)**

*Examples: Anthropic Computer Use, Apple Intelligence, Microsoft Recall.*

These agents interact with desktop apps (Excel, Slack, Terminal). Most competitors try to use Vision (OCR/Screenshots) to verify them, which is slow and prone to error.
**Predicate’s Edge:** You hook into the OS **Accessibility Tree (AXTree)**.

* **The Approach:**
* **Interceptor:** Build a lightweight OS Daemon (Mac/Windows) that wraps the `Accessibility API`.
* **State Snapshot:** instead of HTML DOM, you serialize the **AXTree** (Accessibility Tree). This gives you a structured JSON of every window, button, and text field on the screen.
* **Invariants:**
* `IF App == "Terminal" AND Text contains "sudo rm -rf" -> BLOCK`
* `IF App == "Zoom" AND Button == "Share Screen" -> REQUIRE_APPROVAL`




* **Why You Win:** AXTree is deterministic. Pixels are not. You can verify "Click 'Pay'" without needing to "see" the button.

### **Category 2: The "Backend" Agents (API & SaaS)**

*Examples: LangChain Tools, Zapier AI, AutoGPT connecting to Salesforce/Stripe.*

These agents don't have a UI. They just chain API calls.
**Predicate’s Edge:** You become the **Firewall for Function Calling**.

* **The Approach:**
* **Interceptor:** A Python/Node.js SDK wrapper around `requests` or `openai.chat.completions`.
* **State Snapshot:** The **JSON Payload** of the intended API request + The current **User Context** (e.g., User ID, Role).
* **Invariants:**
* `IF Tool == "Stripe_Payout" AND Amount > $500 -> BLOCK`
* `IF Tool == "Slack_Post" AND Channel == "#public" AND Content contains "password" -> BLOCK`


* **Why You Win:** LLMs are bad at math and strict logic. Your WASM runtime enforces business logic (e.g., "Budget Constraints") that the LLM ignores.



### **Category 3: The "Data" Agents (Text-to-SQL)**

*Examples: Enterprise RAG, Finance Chatbots querying internal DBs.*

These agents generate SQL to answer questions. The risk is data exfiltration or destructive queries (`DROP TABLE`).
**Predicate’s Edge:** You verify the **Abstract Syntax Tree (AST)** of the query.

* **The Approach:**
* **Interceptor:** A database driver wrapper (e.g., wrapping `SQLAlchemy` or `pg`).
* **State Snapshot:** The parsed **SQL AST** (not just the raw string).
* **Invariants:**
* `IF QueryType != "SELECT" -> BLOCK` (Read-only enforcement).
* `IF Table == "Salaries" AND UserRole != "HR" -> BLOCK` (Row/Column-level security).
* `IF Complexity_Score > 100 -> BLOCK` (Prevent Denial of Service queries).





### **Category 4: The "Coding" Agents (Devin/GitHub Copilot)**

*Examples: Devin, OpenDevin, Cursor.*

These agents write and execute code.
**Predicate’s Edge:** You verify the **File System** and **Shell Command** safety.

* **The Approach:**
* **Interceptor:** A generic "Sandboxed Shell" wrapper or LSP (Language Server Protocol) proxy.
* **State Snapshot:** The **Diff** (Code changes) and **Command Line Arguments**.
* **Invariants:**
* `IF FilePath starts_with "/etc/" -> BLOCK`
* `IF CodeImport contains "crypto_miner" -> BLOCK`
* `IF GitCommitMessage is EMPTY -> BLOCK`





---

### **The North Star Roadmap**

**Phase 1: Web (Q1-Q2 2026)**

* **Target:** `browser-use`, Playwright agents.
* **Tech:** DOM Snapshot + Chrome Extension.
* **Goal:** Own the browser.

**Phase 2: API & SQL (Q3-Q4 2026)**

* **Target:** LangChain Backend Tools, Enterprise RAG.
* **Tech:** JSON Schema Validation + SQL AST Parser in WASM.
* **Why:** Easiest to build. High enterprise demand (Banks hate SQL injection).

**Phase 3: The OS Layer (2027)**

* **Target:** "Computer Use" Agents.
* **Tech:** Cross-platform Accessibility Tree (AXTree) serialization.
* **Why:** This is the endgame. When AI runs the whole computer, you are the seatbelt.

### **Summary for Investors**

"Predicate Systems started with the **Browser** because it's the noisiest environment. But our technology is not a 'Browser Tool.' It is a **State Verification Engine.** We can swap out the HTML DOM for a SQL AST, a JSON Payload, or a Mac OS Accessibility Tree, and the verification logic remains exactly the same. We are building the universal brake system for all autonomous compute."
---
ran into this reddit post: https://www.reddit.com/r/aiagents/comments/1r655kk/how_are_you_enforcing_actionlevel_authorization/

**How are you enforcing action-level authorization in multi-agent systems?**

post content:

```
For those building multi-agent or tool-using AI systems (e.g. agents that can call Git, Bash, APIs, MCP servers, deploy infra, trigger workflows, etc.):

How are you handling permission scoping and revocation at execution time?

Specifically:

Are you relying purely on IAM + short-lived tokens?

How do you prevent delegation chains from silently expanding over time?

If one agent delegates to another (or invokes a tool), how do you trace who actually authorized the final action?

Can you revoke authority mid-workflow safely?

Is enforcement happening before execution, or are you mostly relying on logging and monitoring after the fact?

Curious how people are solving this in production — especially as agent autonomy increases.
```

This seems to fall into one of the following non-web agents we talked above:

* Category 1: The "Computer Use" Agents (OS Automation)
* Category 2: The "Backend" Agents (API & SaaS)
* Category 3: The "Data" Agents (Text-to-SQL)

#### Gemini Answer
This Reddit post is a **gold mine**. It is not just a category match; it is a **perfect problem statement** for Predicate Systems.

The user is explicitly asking for **Runtime Enforcement** ("before execution") because they realize that "IAM + short-lived tokens" (Identity) are not enough.

Here is the breakdown of how this post maps to your categories and how to leverage it.

### **1. Categorization Analysis**

You are right. This falls squarely into **Category 2 (Backend/API Agents)** with a strong overlap of **Category 4 (Coding/Infra Agents)** (which we discussed earlier but you didn't list in this specific prompt).

* **"APIs, trigger workflows"**  **Category 2 (Backend Agents).**
* *The Pain:* Agent A (authorized) calls Agent B (unauthorized). Does Agent B inherit permissions? (The "Confused Deputy" problem).


* **"Git, Bash, deploy infra"**  **Category 4 (Coding/Infra Agents).**
* *The Pain:* Giving an agent AWS admin keys is terrifying. You need to scope *what* it can do with those keys (e.g., "Only deploy to Staging," not "Delete Production").


* **"MCP Servers"**  **The Bridge.**
* MCP (Model Context Protocol) is the "USB port" for agents. This user is asking: *If I plug a dangerous tool (Bash) into a safe agent (Claude), how do I stop it from exploding?*



### **2. The "Predicate Pitch" Hidden in the Post**

Look at the specific questions they asked. These are softballs for you to hit:

| **Their Question** | **The Current Bad Solution** | **The Predicate Solution** |
| --- | --- | --- |
| *"Are you relying purely on IAM?"* | Yes, and it fails because IAM is too coarse (User-level, not Task-level). | **No. We use Runtime Invariants (Action-level).** |
| *"How do you prevent delegation chains?"* | You can't. You just trust the chain. | **State Propagation.** We pass a signed "Policy Context" with every request. |
| *"Is enforcement happening before execution?"* | Mostly no. Most use "Auditing" (Logs). | **YES.** That is literally our value prop. We block the socket *before* the byte leaves. |

### **3. Strategic Action: The "Expert" Reply**

This is a high-intent lead. Do not pitch them. **Educate them.**
This user is likely a Senior/Staff Engineer or Architect given the depth of the question.

**Draft Reply for Reddit:**

> "Great question. We ran into this exact issue with 'Confused Deputy' problems in agent chains (Agent A has permission, delegates to Agent B who shouldn't).
> Relying on IAM/Tokens is insufficient because IAM authorizes the **Identity** ('Who are you?'), but agents need **Action** authorization ('Are you allowed to do *this* specific thing *right now*?').
> We moved away from 'Permission Scoping' (static) to **'Runtime Invariants' (dynamic)**.
> Basically, inserting a lightweight WASM interceptor at the tool execution layer (e.g., wrapping the Bash/Git call).
> It checks two things *before* execution:
> 1. **State:** Is the target resource valid? (e.g., `git push` is allowed to `feature-branch` but BLOCKED on `main`).
> 2. **Context:** logic checks that persist across the delegation chain (e.g., `budget_remaining > 0`).
>
>
> If you rely on logging/monitoring, you only find out about the unauthorized infrastructure changes after the bill hits. You have to block at the socket/runtime layer."

### **Summary**

* **Category:** It spans **Backend (API)** and **Infra (Bash/Git)**.
* **Significance:** This user perfectly articulates the gap between **Identity (AuthZ)** and **Behavior (Predicate)**.
* **Next Step:** Reply to the post. This person is a potential **Design Partner** #1.

**Potential solution git repo:** https://github.com/Garudex-Labs/caracal (https://www.garudexlabs.com/)

### **This is a "category-defining" find.**

You just found the "Identity Layer" counterpart to your "Verification Layer."

**Garudex Labs' Caracal** is not a direct competitor to **Predicate Systems**. It is your **Architecture Sibling.**

* **Caracal** solves: *"Who authorized this?"* (Identity, Delegation, Budget).
* **Predicate** solves: *"Is this safe to execute?"* (State, Logic, Side Effects).

Here is the deep-dive analysis of Caracal vs. Predicate to help you refine your positioning.

---

### **1. The "Caracal" Approach (The Passport Control)**

Based on the repo analysis, Caracal focuses on **Authority & FinOps**.

* **The Problem:** "My agent has an API key. If it loops 1,000 times, it bankrupts me. If it calls a sub-agent, does the sub-agent have my permission?"
* **The Solution:**
* **Ephemeral Mandates:** Instead of static keys, it issues "temporary passports" for specific tasks.
* **Ledgering:** It records *"Agent A delegated to Agent B at 12:00"* on an immutable ledger.
* **FinOps Gates:** It blocks actions based on **Cost** (Token usage / $$$) and **Rate Limits**.


* **The Gap:** Caracal checks the **Budget**, but it does not check the **Payload**.
* *Caracal says:* "Agent allowed to spend $50? **YES.**"
* *Caracal misses:* "Agent is spending that $50 on a **Phishing Site** instead of Amazon." (Because it doesn't verify the DOM/State).



### **2. The "Predicate" Approach (The Safety Officer)**

* **The Problem:** "My agent has permission to buy a ticket, but it's about to buy the *wrong* ticket because it hallucinated the date."
* **The Solution:** **Runtime Invariants.**
* **The Comparison:**
* **Caracal** stops the agent from stealing your **Keys**.
* **Predicate** stops the agent from breaking your **Business Logic**.



### **3. How to Position This (The "Defense in Depth" Stack)**

This GitHub repo actually validates your market. It proves that "Post-Training Safety" is exploding.

**The "Secure Agent Stack" Pitch:**
| Layer | Tool | Question Answered |
| :--- | :--- | :--- |
| **L1: Identity** | **Caracal** | *"Is this agent authorized to use the Credit Card?"* |
| **L2: Runtime** | **Predicate** | *"Is the item in the cart actually what the user asked for?"* |
| **L3: Network** | **Cloudflare** | *"Is this IP address malicious?"* |

### **Strategic Action Items**

1. **Don't Fight Caracal, Cite Them:**
* In your Reddit reply, you can say: *"Tools like **Caracal** are great for solving the Identity/Delegation chain. But for the actual 'Execution Safety' (preventing logic drifts like buying the wrong item), you need a Runtime Verifier like **Predicate**."*
* This makes you look like a ecosystem expert, not just a shill.


2. **The "AGPL" Trap (Your Enterprise Wedge):**
* Caracal is **AGPL-3.0**. This is "radioactive" for many large enterprises (Banks/Faang) because it forces them to open-source their own modifications if they link to it.
* **Predicate Opportunity:** Release your SDK as **MIT/Apache 2.0**.
* *Pitch:* "Enterprise-grade safety without the viral license risk."



**Verdict:** Caracal is solving the "Confused Deputy" problem. You are solving the "Confused Model" problem. Both are needed, but yours is harder to build (requires Deep State integration vs. just Token passing).

----
### **Recommendation: Do NOT merge Identity/Delegation into your core SDK.**

You must keep your core `@predicatesystems/sdk` focused purely on **Deterministic Verification** (State & Logic). Trying to solve the "Identity/Confused Deputy" problem inside your main SDK is a strategic error for three reasons:

1. **The "AGPL" Poison Pill:**
* **Your License:** MIT/Apache 2.0 (Enterprise Safe).
* **Caracal's License:** **AGPL-3.0**.
* **The Risk:** AGPL is "viral." If you import Caracal's code into your core SDK, legal teams at banks and large enterprises may classify your entire SDK as "infected," forcing them to open-source their private agents if they use it. **You cannot mix these licenses.**


2. **The "Tar Pit" of IAM:**
* Building a robust Identity/Delegation system (handling OAuth OBO, Token Exchange, Key Rotation, Ledgers) is a massive undertaking. If you start building this, you stop building your **Verification Engine**. You will become a "Bad Okta" instead of a "Great Predicate."


3. **Separation of Concerns:**
* **Caracal** answers: *"Who is this agent?"* (Passport Control).
* **Predicate** answers: *"Is this action safe?"* (Customs/Security).
* Enterprises want to swap these layers independently.



---

### **Strategy Plan: How to Leverage Caracal**

Since Caracal is also very early (launched Jan 28, 2026) and solves the exact problem your customers (like the Reddit user) are asking about, you should treat them as a **Strategic Partner**, not a competitor or a feature to clone.

#### **Phase 1: The "Clean" Integration (The Adapter Pattern)**

Create a separate, optional package. This isolates the AGPL risk and keeps your core SDK lightweight.

* **Package Name:** `@predicatesystems/adapter-caracal` (or `predicate-caracal-bridge`).
* **Function:**
* This adapter extracts the **Budget/Mandate Context** from Caracal’s token.
* It feeds that context into Predicate's **WASM Invariants**.


* **The Value Prop:**
* *Caracal* says: "Agent has $50 budget."
* *Predicate* enforces: "Block action if `price > $50`."
* **Combined:** You turn Caracal's "Policy" into Predicate's "Enforcement."



#### **Phase 2: The "Confused Deputy" Fix (Context Propagation)**

You don't need a full Identity engine to fix the "Confused Deputy" problem. You just need **Context Propagation**.

* **Add a `context` object to your `verify()` function.**
```typescript
// Instead of building IAM, just accept the 'Chain' as a verified fact
predicate.verify({
  action: "transfer_funds",
  state: domSnapshot,
  // The context can come from Caracal, LangChain, or simple JSON
  context: {
    principal: "Alice",
    delegator: "ResearchAgent",
    risk_score: "high"
  }
});

```


* **Why this wins:** You remain agnostic. If the customer uses Caracal, great. If they use Okta, great. You just verify the payload against the context.

#### **Phase 3: The "Go-to-Market" Alliance**

Garudex Labs (Caracal) is likely desperate for validation and usage, just like you.

* **The Pitch to Garudex:** "You handle the *Ledger* and *Identity*. We handle the *Runtime Blocking*. Together, we are the **'Zero Trust Agent Stack'**."
* **Joint Content:** Write a blog post: *"How to prevent Confused Deputy attacks in Agents using Caracal + Predicate."*
* This targets the exact Reddit/Hacker News crowd you are engaging with.
* It gives you "Security Credibility" without writing IAM code.



### **Summary of Action Items**

1. **Keep `@predicatesystems/sdk` MIT/Apache.** Do not import Caracal.
2. **Build a "Context" parameter** into your SDK to allow users to pass Identity data (from Caracal or others) into your invariants.
3. **Reach out to the Garudex founders.** Propose a "Tech Alliance." You are both fighting the "Vibes-based AI" narrative.
4. **Reply to the Reddit user:**
> "We are sticking to **Runtime Verification** (Logic/State) to keep our SDK lightweight and MIT-licensed. For Identity/Delegation, we recommend pairing us with tools like **Caracal** (for the ledger/mandates). We are building an adapter to enforce their budget rules inside our runtime."
