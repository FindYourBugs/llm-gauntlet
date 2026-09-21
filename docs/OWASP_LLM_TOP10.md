# OWASP Top 10 for LLM Applications (2026) — coverage in this lab

All 10 categories have a hands-on level on the ladder. Seven are faithful,
direct demonstrations of the real vulnerability class using nothing but
chat messages and HTTP requests. Three (LLM04, LLM05, LLM09) normally
involve infrastructure this lab deliberately doesn't ship — a package/
plugin registry, a training pipeline, a real vector database — so they're
simulated with the same *architectural bug* a real system would have,
using plain Python instead of that heavier infrastructure. This document
is explicit about which is which.

## Faithful, direct demonstrations

| ID | Category | Level(s) | How it's demonstrated |
|---|---|---|---|
| LLM01 | Prompt Injection | 2, 5 | Level 2: the user directly tries to override the system prompt's instruction not to reveal a secret — the classic direct-injection case, no defenses. Level 5 revisits the same premise (a different flag) behind an input filter that blocks the request outright if you name the secret directly, teaching that you have to describe what you want instead of asking for it by name. |
| LLM02 | Sensitive Information Disclosure | 3 | The bot has other customers' PII in its context "for lookup convenience." A pretext (claiming to be a different customer, or an admin) gets it to disclose someone else's data — the AI equivalent of an IDOR. |
| LLM03 | Excessive Agency | 4 | The bot has a real (simulated) side-effecting capability — issuing a refund — gated only by an instruction in its own system prompt, not by an external authorization check. A social-engineering pretext gets it to exceed its own stated policy. |
| LLM06 | Unbounded Consumption | Bonus | No/weak/real server-enforced rate limiting depending on difficulty passed to the script. `scripts/unbounded_consumption_demo.sh` demonstrates both the raw resource-exhaustion effect and, at "medium," a real identity-spoofing bypass of a naive per-header limiter. Not part of the main ladder since it isn't a flag-hunt exercise. |
| LLM07 | Misinformation | 1 | The ladder's tutorial level — no code needed to demonstrate the underlying phenomenon, ask Nova something outside its context (a discount policy) and it answers fluently and wrong. Marked honor-system in the app because there's no reliable server-side way to verify a claim is false. |
| LLM08 | Hidden Context Exposure | 6 | The (2026-list) broadened successor to "system prompt leakage" - the system prompt embeds a fake internal API key, protected by the same input-filter mechanic introduced in Level 5. Extraction techniques (asking what Nova has access to / was set up with) target the whole context, not just one named secret. |
| LLM10 | Improper Output Handling | 10 | The finale. A downstream viewer (the "Agent Dashboard") trusts the model's output enough to render it as raw HTML. At this level's difficulty, the system prompt refuses all HTML outright - you need a real jailbreak layered on top of the underlying output-handling bug to win. |

## Simulated (same architectural bug, lighter-weight implementation)

| ID | Category | Level | What's real vs. simplified |
|---|---|---|---|
| LLM04 | Supply Chain | 8 — The Poisoned Plugin | **Real:** a third-party component's self-reported metadata is trusted without verification, and that metadata can carry a prompt-injection payload that grants itself new authority — the same failure mode as a malicious ChatGPT plugin, a compromised MCP server's tool description, or a backdoored LangChain tool. **Simplified:** there's no real plugin execution sandbox or package registry — "installing" a plugin just triggers a keyword-matched text injection from a flat file (`app/data/plugins/marketplace.txt`). |
| LLM05 | Data and Model Poisoning | 7 — The Poisoned Article | **Real:** a retrieval corpus (a "knowledge base article") was tampered with ahead of time by an attacker with write access to it, and the model treats its content as trustworthy context rather than untrusted data — this is exactly what the 2026 OWASP definition means by "retrieval corpora are tampered with." **Simplified:** there's no actual document-authoring/versioning pipeline to compromise — the poisoned file just already exists on disk. There is no training-time poisoning demonstrated at all (backdoored weights, tampered fine-tuning data) since this lab never trains anything. |
| LLM09 | Vector and Embedding Weaknesses | 9 — Cross-Tenant Leak | **Real:** a similarity search with no per-tenant access-control check, so a semantically-close query from one user's session retrieves another user's private document — this is the single most common real-world RAG vulnerability (missing row-level security on the vector index). **Simplified:** the "similarity search" is plain keyword-overlap scoring in Python (`keyword_overlap_score()` in `app/app.py`), not real embeddings or an actual vector database. The exploit technique (phrase your query around content, not identity, to route around a naive keyword filter) transfers directly to a real embedding-based system - a keyword filter on a query doesn't become a real access-control check just because the retrieval step now uses vectors. |

## Why the ladder order isn't LLM01→LLM10

The levels are ordered by escalating *technique*, not by OWASP numbering:
start with zero-skill orientation (Level 1), then bare secret-extraction
(Level 2), then a new attack surface each level (actions in Level 4,
indirect injection via a document in Level 7, a third-party plugin in
Level 8), while re-visiting the same premise at a harder defensive tier
partway through (Levels 2→5, 6) to prove the earlier technique still needs
adapting, not just repeating. This mirrors how Gandalf/Prompt Airlines
structure their own ladders - defenses stack, they don't just get "worded
more sternly."

## Suggested classroom framing

Position this lab as "the OWASP LLM Top 10 as one continuous climb": each
level is a different real *deployment* mistake, not a different model
weakness - the underlying LLM is the same small model at every level.
That's the point of the whole Top 10 list: these are application-layer
bugs the *developer* introduced (trusting third-party metadata, trusting a
retrieval corpus, trusting output, over-granting agency, stuffing secrets
into a prompt, skipping access control on a search), as distinct from
model-inherent behavior like hallucination (which gets its own category,
LLM07, precisely because it *isn't* a deployment mistake in the same
sense).

If you want a follow-on lab that builds the "real" version of LLM04/05/09
with actual infrastructure (a mock package registry with dependency
confusion, a small fine-tuning pipeline you can poison, a real
pgvector/Chroma index with a genuine multi-tenant leak), that's a
reasonable next project - this lab is deliberately scoped to stay a single
lightweight container.
