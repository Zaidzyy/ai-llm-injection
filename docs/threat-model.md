# Threat model

Stating this explicitly because "I made the chatbot say something bad" is not a threat model,
and most published LLM red-teaming skips this section entirely.

## Actors

| Actor | Controls | Cares about |
|---|---|---|
| **Account holder** | Their own prompts, their own configuration fields | Getting output the vendor's policy withholds |
| **Remote content author** | A web page, email, ticket, PDF, repo file an agent may ingest | Making someone else's agent act for them |
| **Upstream supplier** | A tool endpoint, retrieval corpus, MCP server, plugin | Persistent influence over many sessions |

## What each can actually achieve

### Account holder — direct injection

Writes to a channel they are already authorised to write to: the chat box, or a vendor-provided
configuration field. Success means the model produces content the vendor's policy withholds.

**Impact ceiling: low.** No other user is affected. No credential is obtained. The gain is
bounded by the marginal difficulty of getting the same content elsewhere — for most
categories, that margin is small, which is why this class is rated low here even when the
bypass fully succeeds.

**It is still worth reporting.** A vendor that publishes *"these rules cannot be overridden
under any circumstances"* has made a testable claim, and a gap between stated policy and
observed behaviour is a real finding regardless of impact. That is the shape of
[`FINDING-001`](findings/FINDING-001.md).

**What inflates this class dishonestly:** describing it as though the attacker were remote.
If your write-up does not name the delivery channel, a reader will assume the worse one.

### Remote content author — indirect injection

Never touches the target account. Plants instructions in content an agent later reads.

**Impact ceiling: high, and it scales.** The agent acts with the victim's privileges. If it
holds tools — email, file access, code execution, purchases — the injection inherits them.
One poisoned document reaches every agent that reads it.

**This is the class that makes LLM security a security discipline** rather than a content-policy
question. Covered by `P-004` and `P-005`.

### Upstream supplier — supply chain

Controls a component many sessions depend on: a retrieval corpus, a tool endpoint, an MCP
server, a plugin.

**Impact ceiling: high and persistent.** Not directly covered by this harness; noted because
`tool-output-trust` (`P-005`) is its delivery mechanism, and a pipeline that fences tool output
correctly is substantially harder to attack this way.

## Assets

1. **Model behaviour** — the model acting outside operator policy.
2. **Downstream privilege** — tools and credentials the model can reach. *The real prize.*
3. **Session data** — conversation contents, retrieved documents, user data in context.
4. **Operator instructions** — assume public; never a secret worth protecting.

Asset 2 is where consequences live. A bypass on a model with no tools is an embarrassment;
the same bypass on an agent with a mailbox is an incident.

## Explicitly out of scope

- Model weights, training data, alignment internals
- Vendor infrastructure — no scanning, no auth testing, no DoS
- Other users' data or sessions
- Third-party products encountered incidentally during testing

That last one is a real boundary, not a formality. Testing that surfaces a vulnerability in
someone *else's* software creates a **separate disclosure obligation to that vendor**, and
publishing it under an "AI safety research" heading does not discharge it. Anything of that
kind found during this work is withheld pending its own disclosure process — see
[`redaction-policy.md`](redaction-policy.md).

## Testing constraints observed

- Personal account, vendor-provided interfaces only
- Ordinary interactive rates — no automation against production endpoints, no load testing
- No attempt to access other users' data
- No attempt to reach infrastructure behind the model
- Findings reported to the vendor before publication
