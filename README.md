# Hivemind

Hivemind is a Rust-first implementation workbench for generic AI on Swarm. It turns the architecture writeups into executable contracts for AI packages, Swarm-backed storage references, registry discovery, runner routing, marketplace records, validation, receipts, access control, and audit trails.

The project is not a production decentralized AI network yet. Its current value is that teams can model the end-to-end lifecycle locally, verify protocol behavior, test integration boundaries, and harden the contracts before live payment settlement, production runner isolation, decentralized governance, and real miner operations are introduced.

The core boundary is deliberate: Swarm stores packages, data references, publication records, access evidence, receipts, and audit history. Runners do computation in browser, local, remote GPU, miner, batch, confidential, or validator contexts.

## Current Scope

Hivemind can currently:

- Scaffold, validate, sign, publish, inspect, and install SwarmAI package manifests through the `swarm-ai` CLI.
- Publish to local development storage or Bee-compatible storage providers through the Rust storage abstraction.
- Describe browser-native storage providers and verify browser storage consent, session, purchase, receipt, and state-report contracts.
- Run a mock-first browser Weeb-3 publish-one pilot that probes capabilities, quotes and authorizes storage, opens a session, uploads bytes, retrieves them, verifies the hash, updates feeds, resets storage, clears sensitive browser state, and emits signed V2 storage receipts.
- Rebuild searchable local registries from packages, publications, feeds, validation reports, marketplace offers, governance records, and benchmark evidence.
- Route AI execution requests across browser, local, remote, marketplace, and miner-capacity candidates using trust, privacy, verification, price, cache, capacity, fallback, and reputation signals.
- Project route decisions into V2 route plans with selected and rejected runner explanations, capacity reservations, signed failure analyses, and retry decisions for timeout, privacy/policy, quote-expiry, and overload cases.
- Execute deterministic local-development runner flows and produce signed receipts, stream events, partial receipts, job lifecycle records, and audit summaries.
- Run OpenAI-compatible chat and embedding requests through the local execution and receipt path with a model-runner layer: deterministic mock inference by default, and Ollama-backed local inference behind explicit environment opt-in.
- Run an isolated provider/consumer LLM pilot: `serve-provider` advertises one configured model offer over a local or authenticated LAN/test endpoint with model lifecycle, managed start/stop, session, prompt, context, output, and concurrency limits; `provider-chat` connects to a known provider URL, requests a quote, opens, resumes, or closes a pseudopayment session, starts a cold model when policy allows it, asks chat questions, saves receipts and closed-session summaries, and records local session metadata while the provider persists model lifecycle, sessions, ledger events, issued receipts, and closed-session summaries.
- Expose OpenAI-compatible and provider-shaped API surfaces for chat, Responses, embeddings, files, vector stores, batches, fine-tuning, realtime sessions, evals, image, audio, moderation, Anthropic-style, Gemini-style, and Hugging Face-style requests.
- Model marketplace listing, shortlisting, quote, payment authorization, escrow, settlement, dispute, refund, rejection, audit, and slashing records as local signed contracts, including V2 payment authorization, escrow, settlement, dispute, audit-event, and slashing-decision interface objects for downstream teams.
- Model AI miner participation through hardware-resource offers, miner profiles, heartbeats, benchmark evidence, onboarding plans, and dashboard summaries.
- Model RAG and research workflows with document collection, chunk, embedding, vector-index, retrieval, citation, evaluation, reproducibility, and result-record contracts.
- Model agent and tool runtime audit with signed tool invocations, tool results, agent run state, human approval requests, and scoped memory writes.
- Run a local Swarm RAG One pilot for plain text and Markdown documents: upload to local Swarm-like storage, chunk, embed deterministically, build a vector index snapshot, search with access checks, generate an extractive answer, cite chunks, and emit an answer receipt.
- Serve a Rust/WASM dashboard from the local API server.

The implementation remains strongest as a protocol workbench. Real browser Weeb-3 runtime integration, production model serving backends, live miner operations, live settlement, production sandbox enforcement, validator challenge traffic, and production reliability gates are still future work.

## Generated Inventories

The complete API and schema inventories are generated from source code:

- [API routes](docs/generated/api-routes.md)
- [Schema commands](docs/generated/schemas.md)
- [Provider/consumer quickstart](docs/provider-consumer/quickstart.md)

Regenerate and verify them with:

```powershell
cargo run -p hivemind-server -- docs generate
cargo run -p hivemind-server -- docs check
```

The README is intentionally not a full route or schema registry. Generated docs are the compatibility source of truth for public route paths and `swarm-ai schema ...` commands.

## Repository Layout

The repository is one Cargo workspace with separate crates for the major components:

- `crates/core`: shared protocol contracts, canonical IDs, access objects, AI request/response objects, job orders, receipts, privacy and integrity tiers, trust policies, and error catalogs.
- `crates/storage` and `crates/weeb3-adapter`: local/Bee storage providers, browser storage contracts, browser Swarm provider descriptors, mock-first browser publish-one lifecycle handling, receipt mapping, and security assessment objects.
- `crates/package`, `crates/publisher`, and `crates/registry`: package manifests, publication records, feed pointers, searchable indexes, shard manifests, and registry verification.
- `crates/browser-runner`, `crates/local-runner`, `crates/remote-runner`, `crates/router`, `crates/jobs`, and `crates/streams`: execution candidates, route planning, local runner behavior, mock and Ollama local model descriptors, job lifecycle records, stream events, and partial receipt handling.
- `crates/openai-compat` and `crates/provider-compat`: OpenAI-compatible and provider-shaped request/response adapters backed by the Hivemind contract layer.
- `crates/marketplace` and `crates/miner`: listings, offers, quotes, payment records, V2 escrow and settlement interface objects, disputes, audit events, slashing decisions, hardware capacity, miner profiles, heartbeats, benchmarks, and onboarding records.
- `crates/access`, `crates/policy`, `crates/validator`, `crates/receipts`, and `crates/observability`: licensing, paid access, permission inspection, validation evidence, receipt verification, redaction, correctness assessment, and operational snapshots.
- `crates/vector`, `crates/workflow`, `crates/batch`, `crates/fine-tune`, `crates/realtime`, `crates/media`, `crates/moderation`, `crates/evals`, `crates/benchmarks`, `crates/research`, and `crates/governance`: higher-level AI workflows, agent/tool runtime records, research/R&D records, evaluation suites, readiness records, and governance objects.
- `crates/sdk`: compatibility helpers, builders, mock providers/runners, supported schema declarations, and client-facing utilities.
- `crates/server`: the `swarm-ai` CLI, Axum API server, generated-docs command, and dashboard composition layer.
- `crates/web`: Rust/Yew WASM dashboard.

## Practical Use Cases

An application developer can search the local registry, resolve a package, inspect trust evidence, plan a route, call OpenAI-compatible endpoints, and receive Hivemind receipts that preserve the underlying package, runner, access, route, and audit context.

A browser application team can design against the browser storage contracts before connecting a live Weeb-3 implementation. They can run the mock-first publish-one lifecycle locally, verify user consent and storage purchase authorization, inspect session scope, validate upload/retrieval receipts, model feed updates, and test sensitive-state clearing and service-worker or IndexedDB risk controls.

A runner or miner operator can publish local service or hardware-resource offers, generate quotes, expose capacity and benchmark evidence, execute local-development jobs, and produce records that later settlement, reputation, or dispute workflows can inspect.

A marketplace integrator can exercise the economic lifecycle without claiming live custody: listing, shortlist, quote, V2 payment authorization, escrow, settlement, dispute, audit event, refund, rejection, and evidence-gated slashing decision records can be projected from current local flows, signed, verified, and checked for tampering.

A research team can define benchmark suites, hidden challenge commitments, eval runs, research experiments, reproducibility bundles, vector indexes, RAG citation traces, and signed result records so later teams can reproduce or challenge claims from stable references.

## Quick Start

Run the core checks:

```powershell
cargo fmt --all -- --check
cargo test --workspace
cargo run -p hivemind-server -- docs check
```

Scaffold and validate a package:

```powershell
cargo run -p hivemind-server -- init .\.swarm-ai-cache\scaffolds\hello-init --package-id local/hello-init
cargo run -p hivemind-server -- validate .\examples\packages\hello-embedding
cargo run -p hivemind-server -- publish-dry-run .\examples\packages\hello-embedding
```

Publish locally and resolve the feed:

```powershell
cargo run -p hivemind-server -- sign .\examples\packages\hello-embedding
cargo run -p hivemind-server -- publish .\examples\packages\hello-embedding --channel latest,stable
cargo run -p hivemind-server -- resolve-feed hivemind/hello-embedding --channel latest
```

Run and inspect a local development execution:

```powershell
cargo run -p hivemind-server -- run-ref bzz://local-dir-reference --task embedding --text "hello ref" --receipts-dir .\.swarm-ai-cache\receipts
cargo run -p hivemind-server -- receipts list
cargo run -p hivemind-server -- receipts audit
```

Run the local Swarm RAG One pilot:

```powershell
cargo run -p hivemind-server -- rag ingest .\README.md --collection local/readme --force
cargo run -p hivemind-server -- rag search local/readme --query "what can hivemind do?" --include-text
cargo run -p hivemind-server -- rag ask local/readme --query "what can hivemind do?" --receipt
```

Use a local Ollama engine for OpenAI-compatible chat and embeddings:

```powershell
$env:HIVEMIND_LOCAL_MODEL_ENGINE="ollama"
$env:HIVEMIND_OLLAMA_URL="http://127.0.0.1:11434"
$env:HIVEMIND_OLLAMA_CHAT_MODEL="llama3.2"
$env:HIVEMIND_OLLAMA_EMBED_MODEL="nomic-embed-text"
cargo run -p hivemind-server -- serve --port 8787
```

Run the direct provider/consumer pilot with a mock backend:

```powershell
# Terminal 1
cargo run -p hivemind-server -- serve-provider --config .\examples\provider\mock-provider.json

# Terminal 2
cargo run -p hivemind-server -- provider-chat --config .\examples\consumer\local-chat.json --message "hello provider"
```

Resume the same provider session after a provider restart:

```powershell
cargo run -p hivemind-server -- provider-chat --provider http://127.0.0.1:8788 --resume-session-id <provider-session-id> --message "continue"
```

Provider mode refuses unsafe external serving unless an explicit security mode and auth policy are configured. It supports bearer-token LAN auth and an MVP local-dev signed request envelope mode with body-hash, expiry, and nonce replay checks. Pseudopayment is local-dev/test accounting: usage increases session debt, forgiveness lowers it over time, and the provider can refuse work when the debt ceiling is reached. Provider model lifecycle, sessions, issued receipts, and final closed-session summaries survive restart through the configured state file and can be queried through the provider API; `provider-chat --close-session` also stores that final summary locally. For OpenAI-compatible backends, the provider can optionally start and stop an operator-configured managed process without shell interpolation; stop is refused while jobs are active and is not exposed for unmanaged external backends. It is not real settlement or production custody.

Start the local API and dashboard:

```powershell
cargo run -p hivemind-server -- serve --port 8787
```

Example API calls:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/models -Method Get
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/chat/completions -Method Post -ContentType application/json -Body '{"model":"hivemind/hello-chat","messages":[{"role":"user","content":"hello"}]}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/hivemind/ai/plan -Method Post -ContentType application/json -Body '{"schemaVersion":"hivemind.request.v1","requestId":"ai-plan-demo-1","requester":"local-dev","apiSurface":"hivemind_native","packageSelector":{"model":"hivemind/hello-chat"},"inputs":[{"type":"text","content":"plan this request"}],"task":"chat"}'
```

## Readiness Boundary

Readiness labels are conservative:

- `mock`: deterministic placeholder behavior for protocol tests.
- `local`: executable local-development behavior without decentralized production guarantees.
- `gateway`: integration through a gateway or external service boundary.
- `browser-test`: browser-facing contract or mock integration that still needs live browser runtime proof.
- `testnet`: intended for future externally networked pilots.
- `production`: reserved for components with real tests, security review, operational metrics, documented failure handling, and no known critical blockers.

Most current surfaces are `local`, `gateway`, or `browser-test`. The generated route inventory carries conservative readiness defaults, and governance readiness records can separately describe component-specific evidence.

## Development Direction

The next engineering priorities from the current writeups are:

1. Keep generated route and schema inventories current.
2. Harden the provider/consumer pilot with live Ollama or vLLM smoke tests, real streaming transport, cancellation, signed request replay protection, and clearer LAN demo docs.
3. Connect the browser Weeb-3 publish-one pilot to live browser-runtime tests behind explicit wallet, Bee, and spend opt-in flags.
4. Expand the opt-in Ollama local inference pilot with field support checks, rejection behavior, streaming conformance, and additional model engines.
5. Expand Swarm RAG One with live embedding backends, browser file selection, richer file parsing, and OpenAI file-search compatibility behavior.
6. Continue contract alignment for generic extensions and production marketplace operations beyond the local V2 interface objects.
7. Add production readiness gates for labels, fixtures, operational evidence, and documentation freshness.

This ordering is intentional: visibility first, then one real storage path, one real model path, one real data workflow, and then broader economic and routing hardening.
