# Hivemind

Rust-first implementation scaffold for the SwarmAI architecture writeups.

## Current Scope

Hivemind is a Rust-first implementation of a Swarm-backed AI package network. The current codebase is a local-first protocol workbench: it turns the architecture into executable contracts for packages, storage, registry discovery, runner routing, marketplace records, validation reports, receipts, and audit trails.

Today, Hivemind can scaffold and validate `swarm-ai.json` packages, publish them to local or Bee-style storage, describe browser-native storage providers, verify browser storage consent/session/receipt contracts, rebuild searchable registries, route requests across browser, local, and remote runner contracts, produce signed receipts and reports, and expose those flows through a CLI, JSON API, OpenAI-compatible endpoints, and a Rust/WASM dashboard.

It is not yet a production decentralized AI network. Its value right now is that teams can run the end-to-end lifecycle locally, verify protocol behavior, test integrations, and harden the component boundaries before real economic settlement, live decentralized feeds, production runner isolation, and decentralized governance processes are introduced.

## Practical Scenarios

- A model publisher can create an embedding or chat package, validate its manifest and artifacts, sign a publication record, publish the package to development storage, and update feed pointers so clients can resolve the latest release.
- A browser application team can inspect provider descriptors for local development, Bee HTTP, bee-js gateway, Weeb-3 npm, or hosted relay flows, record explicit user consent for storage purchase or upload actions, open a scoped storage session, and verify storage event receipts before treating a browser-originated publication as auditable evidence.
- An application developer can search the local registry for a package, inspect its trust evidence, route an execution request, run it through the local development runner, list compatible models through `/v1/models`, create reference-backed vector stores, start contract-only batch, fine-tuning, realtime, evaluation, image, or audio jobs, or use OpenAI-compatible and provider-shaped compatibility endpoints while keeping the underlying SwarmAI contracts visible.
- A registry or mirror operator can rebuild a public index from packages, publications, feeds, validation reports, and benchmark results, then emit shard files and verify shard manifests before trusting another catalog.
- A runner or miner operator can model browser, local, remote GPU, or marketplace capacity, publish service and hardware-resource offers, create miner profiles, report signed heartbeats and benchmark evidence, quote work, execute requests through the runner contract, and attach signed receipts that downstream settlement or dispute flows can inspect.
- A validator can run compatibility checks or benchmark suites, sign the resulting reports, store them through the same provider abstraction as packages, and contribute evidence that the registry can summarize into reputation data.
- A marketplace integrator can exercise listing, shortlisting, quote, payment authorization, settlement, dispute, refund, and rejection records without pretending the local implementation is already a live payment system.
- A protocol implementer can use the Rust crates, JSON schemas, SDK facade, CLI commands, and tests as concrete compatibility references for an independent implementation.

The intended direction is to preserve these working contracts while replacing local simulations with production-grade Swarm/Bee publication, real runner backends, wallet-bound identity and payment proofs, stronger sandboxing, and decentralized operating processes.

The repository is a single Cargo workspace with separate crates for the major R&D components:

- `hivemind-core`: shared SwarmAI contract types, v0.3 universal capabilities, asset descriptors, workload projections, review-4 privacy tier catalog/assessment contracts, typed integrity tiers, trust policies, standard error catalog, canonical JSON hashing, and common validators.
- `hivemind-identity`: Ed25519 identity keypairs, public identity documents, canonical JSON signature envelopes, and verification reports.
- `hivemind-package`: PackageManifestV1 scaffolding, v02 manifest projection support, folder loading, path validation, and compact package validation audit records with manifest parse and validation timing summaries.
- `hivemind-publisher`: publisher dry-run, deterministic local-dev signing, Ed25519 publication signatures, PublicationRecordV1 verification, local publication/feed audit indexing, and local feed updates/resolution.
- `hivemind-registry`: local registry indexing, grant-aware paginated search, compact search audit records with latency summaries, v0.2 discovery filters for modality, API surface, privacy, verification, browser, GPU, size, validation, and price hints, signed publication/feed trust evidence, package detail lookup, public snapshot filtering, and mirrorable facet shard output/verification.
- `hivemind-storage`: StorageProvider trait, in-memory provider, local directory storage, Bee HTTP storage, browser-native provider descriptors, explicit browser storage consent/session/receipt/security-assessment contracts, review-5 capability probe, purchase quote/authorization, v2 session, v2 receipt, and browser state report objects, transfer timing metrics, storage transfer audit summaries, cache inspection, feed pointer operations, and pin/unpin support.
- `hivemind-weeb3-adapter`: browser Swarm/weeb-3 provider contract, fallback retrieval, cache status, and compatibility/security reports.
- `hivemind-browser-runner`: browser capability detection, artifact selection, prepare plans, deterministic browser execution, and receipt metadata.
- `hivemind-local-runner`: deterministic Rust development runner with installable artifact cache and sensitive-cache markers for protected packages.
- `hivemind-remote-runner`: remote GPU runner API contract, health/load/pricing status, prepare records, deterministic remote execution, cancellation, and receipts.
- `hivemind-router`: multi-runner route planning, marketplace offer-backed and miner-capacity-backed route candidates, summarized runner reputation evidence, trust-policy enforcement, cost quotes, policy scoring, and fallback route ordering.
- `hivemind-jobs`: JobRecordV1 lifecycle audit records, local job order/quote/lease/execution status/cancellation storage, lifecycle timelines, production lifecycle coverage, evidence linking, expiration sweeps, job-store audit summaries, and job lookup.
- `hivemind-observability`: operational metric snapshot contracts, deterministic local-dev signatures, verification, store helpers, and aggregate metrics derived from job, receipt, package-validation, registry-search, validation-report, storage, stream, route, marketplace, miner, and governance/readiness audit stores.
- `hivemind-streams`: native StreamingEventV1 store/read/write helpers, stream summaries, stream audit summaries with time-to-first-output timing, SSE rendering, and cancellation stream-event persistence.
- `hivemind-openai-compat`: OpenAI-style model discovery, file references, vector-store search planning, batch, fine-tuning, realtime session, eval, image, and audio adapters, chat completion, streamed chat chunks, Responses, streamed Responses events, embedding, and moderation request/response adapters backed by SwarmAI execution.
- `hivemind-provider-compat`: provider-shaped Anthropic Messages, Gemini Generate Content, Gemini Live session, and Hugging Face-style inference request/response adapters backed by SwarmAI execution and realtime contracts.
- `hivemind-marketplace`: local-dev and Ed25519 signed package listings, review-4 `MarketplaceListingV2` category separation, runner offers, hardware resource offers, service quotes, escrow records, settlement events, dispute/refund/reject resolutions, signed refund records, evidence-gated slashing records, marketplace shortlists/ranking, offer/hardware-offer/quote/payment/escrow/refund verification, local-dev and Ed25519 payment authorizations, verified settlement results, and local payment/escrow/settlement/refund/resolution audit stores.
- `hivemind-miner`: AI miner daemon profile, heartbeat, benchmark evidence, onboarding plan, dashboard summary, and local audit indexing contracts built around hardware-resource offers without treating Swarm/Bee as compute.
- `hivemind-access`: license policy, canonical v1/v2 access-policy projection, review-5 `AssetAccessRuleV2` and `AccessGrantV3` contracts, paid-access quote/evaluation objects, access request, asset-scoped `AccessGrantV2` contracts, local-dev and Ed25519 signed package grants, grant/revocation audit indexing, grant revocation, verification, and access evaluation.
- `hivemind-batch`: BatchJobV1 contracts, checkpoint and partial-result policies, privacy/integrity tiers, local-dev and Ed25519 signatures, verification, execution planning, and local job audit indexing for large offline work.
- `hivemind-fine-tune`: FineTuneJobV1 contracts, training/validation dataset refs, output policies, privacy/cost/validation metadata, local-dev and Ed25519 signatures, verification, lease-oriented execution planning, and local job audit indexing.
- `hivemind-media`: MediaJobV1 contracts for image generation/editing, speech-to-text, and text-to-speech, with privacy/integrity tiers, local-dev and Ed25519 signatures, verification, runner-side execution planning, and local job audit indexing.
- `hivemind-realtime`: RealtimeSessionV1 contracts, modality/transport metadata, tool refs, privacy settings, local-dev and Ed25519 signatures, verification, runner-side connection planning, and local session audit indexing for live interactions.
- `hivemind-moderation`: moderation policy and request contracts, category thresholds, action rules, privacy/integrity metadata, local-dev and Ed25519 signatures, verification, local audit indexing, and OpenAI-compatible moderation planning.
- `hivemind-governance`: governance policy, schema release, component readiness, and security advisory contracts, local-dev and Ed25519 signatures, verification, security response planning, and local audit indexing for operator and protocol processes.
- `hivemind-validator`: compatibility reports, validation challenges, task-specific validation method registry, local-dev and Ed25519 signed scoring reports, v02 validation/reputation projections, integrity evidence for TEE/proof hooks, local report/evidence audit indexing, storage upload/download, verification, and reputation profiles.
- `hivemind-receipts`: local-dev and Ed25519 signed receipt handling, signed batch and partial receipts, receipt correctness assessments, batch receipt indexing and audit summaries, stream-linked receipt summaries, policy-documented redacted audit views, embedded policy evidence, storage upload/download, dispute evidence, verification, capture, and local audit trail storage.
- `hivemind-policy`: permission manifests, review-4 permission manifest projections, consent records, tool permission grants, policy decisions, sandbox requirements, trust-policy audit indexing, and risk inspection reports.
- `hivemind-benchmarks`: benchmark packages, signed benchmark suites, signed `BenchmarkPackV1` projections, dataset entries, scoring rules, hidden challenge commitments, V1 and production-oriented V2 evaluation results, local benchmark audit indexing, and verification.
- `hivemind-evals`: signed EvalManifestV1 and EvalRunV1 contracts, privacy/integrity tiers, run verification, runner-side evaluation planning, and local audit indexing for model, RAG, safety, human-review, and regression workflows.
- `hivemind-research`: signed research experiment/run records, evaluation-run v2 contracts, signed result records, reproducibility bundles, R&D package-kind references, verification, and local experiment audit indexing.
- `hivemind-vector`: vector store manifests, review-4 document collection/chunk/embedding/vector-index/RAG-pipeline/citation-trace contracts, access/privacy metadata, signing, verification, retrieval/search planning, and local manifest audit indexing for RAG workflows.
- `hivemind-workflow`: tool manifests, workflow manifests, permission-aware signatures, verification, ordered execution planning, and local audit indexing for agents and RAG pipelines.
- `hivemind-sdk`: SDK facade, mock storage/runner, route-planner and marketplace builders, access and validation helpers, OpenAI-compatible adapter helpers, streaming event parser and order validator, v0.3 schema advertisement, and compatibility certification reports.
- `hivemind-server`: `swarm-ai` CLI plus Axum API/UI composition layer.
- `hivemind-web`: Yew/WASM dashboard built in Rust with registry, route/run, trust-policy audit, receipt, job, marketplace, and governance views.

## Useful Commands

```powershell
cargo test
cargo run -p hivemind-server -- init .\.swarm-ai-cache\scaffolds\hello-init --package-id local/hello-init
cargo run -p hivemind-server -- validate .\examples\packages\hello-embedding
cargo run -p hivemind-server -- search --capability embedding
cargo run -p hivemind-server -- search --capability embedding --grant .\.swarm-ai-cache\private.grant.json --requester local-dev --runner-id local-dev-runner
cargo run -p hivemind-server -- publish-dry-run .\examples\packages\hello-embedding
cargo run -p hivemind-server -- sign .\examples\packages\hello-embedding
cargo run -p hivemind-server -- identity generate --subject 0x0000000000000000000000000000000000000000 --output .\.swarm-ai-cache\identity\publisher.identity.json
cargo run -p hivemind-server -- identity public .\.swarm-ai-cache\identity\publisher.identity.json
cargo run -p hivemind-server -- identity sign-publication .\.swarm-ai-cache\publications\hivemind-hello-embedding-0-1-0.publication.json --identity .\.swarm-ai-cache\identity\publisher.identity.json --output .\.swarm-ai-cache\publications\hivemind-hello-embedding-0-1-0.identity.publication.json
cargo run -p hivemind-server -- publish .\examples\packages\hello-embedding --channel latest,stable
cargo run -p hivemind-server -- verify-publication .\.swarm-ai-cache\publications\hivemind-hello-embedding-0-1-0.publication.json
cargo run -p hivemind-server -- publication-records
cargo run -p hivemind-server -- get-publication publication-id
cargo run -p hivemind-server -- update-feed .\.swarm-ai-cache\publications\hivemind-hello-embedding-0-1-0.publication.json
cargo run -p hivemind-server -- resolve-feed hivemind/hello-embedding --channel latest
cargo run -p hivemind-server -- feed-pointers
cargo run -p hivemind-server -- get-feed hivemind/hello-embedding --channel latest
cargo run -p hivemind-server -- validate-ref bzz://local-dir-reference
cargo run -p hivemind-server -- inspect bzz://local-dir-reference
cargo run -p hivemind-server -- cache status
cargo run -p hivemind-server -- cache list
cargo run -p hivemind-server -- cache pin bzz://local-dir-reference
cargo run -p hivemind-server -- cache unpin bzz://local-dir-reference
cargo run -p hivemind-server -- cache create-feed --topic latest --owner 0xPublisher
cargo run -p hivemind-server -- cache update-feed --topic latest --owner 0xPublisher bzz://local-dir-reference
cargo run -p hivemind-server -- cache resolve-feed bzz://local-feed-reference
cargo run -p hivemind-server -- policy catalog
cargo run -p hivemind-server -- policy inspect .\examples\packages\hello-embedding
cargo run -p hivemind-server -- policy inspect-v2 .\examples\packages\hello-embedding
cargo run -p hivemind-server -- policy trust local-only --owner local-dev --output .\.swarm-ai-cache\trust\local-only.trust-policy.json
cargo run -p hivemind-server -- policy trust open-marketplace --owner local-dev --output .\.swarm-ai-cache\trust\open-marketplace.trust-policy.json
cargo run -p hivemind-server -- policy trust sign .\.swarm-ai-cache\trust\local-only.trust-policy.json --output .\.swarm-ai-cache\trust\local-only.signed.trust-policy.json
cargo run -p hivemind-server -- policy trust verify .\.swarm-ai-cache\trust\local-only.trust-policy.json
cargo run -p hivemind-server -- policy trust list
cargo run -p hivemind-server -- policy trust get trust-policy-id
cargo run -p hivemind-server -- install bzz://local-dir-reference
cargo run -p hivemind-server -- runner-cache list
cargo run -p hivemind-server -- runner-cache clean bzz://local-dir-reference
cargo run -p hivemind-server -- run-ref bzz://local-dir-reference --task embedding --text "hello ref" --receipts-dir .\.swarm-ai-cache\receipts
cargo run -p hivemind-server -- receipts list
cargo run -p hivemind-server -- receipts audit
cargo run -p hivemind-server -- receipts get receipt-id
cargo run -p hivemind-server -- receipts list-batches
cargo run -p hivemind-server -- receipts audit-batches
cargo run -p hivemind-server -- receipts get-batch batch-receipt-id
cargo run -p hivemind-server -- receipts verify .\.swarm-ai-cache\receipts\receipt-id.json
cargo run -p hivemind-server -- receipts verify-v2 .\.swarm-ai-cache\receipts\receipt-id.v2.json --source .\.swarm-ai-cache\receipts\receipt-id.json
cargo run -p hivemind-server -- receipts verify-batch .\.swarm-ai-cache\receipts\batch-receipt-id.json
cargo run -p hivemind-server -- receipts verify-partial .\.swarm-ai-cache\receipts\partial-receipt-id.json
cargo run -p hivemind-server -- receipts redact .\.swarm-ai-cache\receipts\receipt-id.json --profile public-audit --output .\.swarm-ai-cache\receipts\receipt-id.public-redacted.json
cargo run -p hivemind-server -- receipts verify-redaction .\.swarm-ai-cache\receipts\receipt-id.public-redacted.json
cargo run -p hivemind-server -- receipts sign .\.swarm-ai-cache\receipts\receipt-id.json --identity .\.swarm-ai-cache\identity\runner.identity.json --output .\.swarm-ai-cache\receipts\receipt-id.identity.json
cargo run -p hivemind-server -- receipts upload .\.swarm-ai-cache\receipts\receipt-id.json
cargo run -p hivemind-server -- receipts download bzz://local-bytes-reference
cargo run -p hivemind-server -- receipts dispute .\.swarm-ai-cache\receipts\receipt-id.json --claimant local-dev --claim-kind output-mismatch --summary "receipt output is disputed" --evidence-ref bzz://evidence-ref --identity .\.swarm-ai-cache\identity\local-dev.identity.json
cargo run -p hivemind-server -- receipts list-disputes
cargo run -p hivemind-server -- receipts get-dispute dispute-id
cargo run -p hivemind-server -- receipts verify-dispute .\.swarm-ai-cache\disputes\dispute-id.json
cargo run -p hivemind-server -- browser capabilities
cargo run -p hivemind-server -- browser assess .\examples\packages\hello-embedding
cargo run -p hivemind-server -- browser prepare .\examples\packages\hello-embedding
cargo run -p hivemind-server -- browser run .\examples\packages\hello-embedding --task embedding --text "browser hello" --receipts-dir .\.swarm-ai-cache\receipts
cargo run -p hivemind-server -- browser-swarm descriptor
cargo run -p hivemind-server -- browser-swarm status
cargo run -p hivemind-server -- browser-swarm compatibility
cargo run -p hivemind-server -- browser-swarm manifest bzz://local-dir-reference
cargo run -p hivemind-server -- browser-swarm file bzz://local-dir-reference --path swarm-ai.json
cargo run -p hivemind-server -- remote api
cargo run -p hivemind-server -- remote health
cargo run -p hivemind-server -- remote prepare .\examples\packages\hello-embedding
cargo run -p hivemind-server -- remote run .\examples\packages\hello-embedding --task embedding --text "remote hello" --receipts-dir .\.swarm-ai-cache\receipts
cargo run -p hivemind-server -- route .\examples\packages\hello-embedding --package-ref bzz://published-hello-embedding-reference --task embedding --text "route me" --policy balanced --marketplace-offers .\.swarm-ai-cache\marketplace\offers --max-marketplace-results 3 --marketplace-hardware-offers .\.swarm-ai-cache\marketplace\hardware-offers --miner .\.swarm-ai-cache\miner --trust-policy .\.swarm-ai-cache\trust\local-only.trust-policy.json
cargo run -p hivemind-server -- jobs list
cargo run -p hivemind-server -- jobs get job-id
cargo run -p hivemind-server -- jobs timeline job-id
cargo run -p hivemind-server -- jobs lifecycle job-id
cargo run -p hivemind-server -- jobs lifecycle-audit
cargo run -p hivemind-server -- jobs link-evidence job-id --kind validation-report --ref local://validation/report-id --evidence-id report-id --linked-by validator-1
cargo run -p hivemind-server -- jobs audit --observed-at 2026-06-02T00:10:00Z
cargo run -p hivemind-server -- jobs expire --observed-at 2026-06-02T00:10:00Z
cargo run -p hivemind-server -- jobs stream job-id
cargo run -p hivemind-server -- jobs stream job-id --format sse
cargo run -p hivemind-server -- jobs partial-receipts job-id
cargo run -p hivemind-server -- jobs cancel job-id --cancelled-by local-dev --reason "user requested stop"
cargo run -p hivemind-server -- observability snapshot --package-audit-dir .\.swarm-ai-cache\package-audit --registry-audit-dir .\.swarm-ai-cache\registry-audit --validation-reports-dir .\.swarm-ai-cache\validations --storage-audit-dir .\.swarm-ai-cache\storage-audit --streams-dir .\.swarm-ai-cache\streams --miner-dir .\.swarm-ai-cache\miner --governance-dir .\.swarm-ai-cache\governance --output-dir .\.swarm-ai-cache\observability
cargo run -p hivemind-server -- serve
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/models -Method Get
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/policy/trust/local-only -Method Post -ContentType application/json -Body '{"owner":"local-dev","sign":true}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/policy/trust -Method Get
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/policy/trust/trust-policy-id -Method Get
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/policy/trust/verify -Method Post -ContentType application/json -Body (Get-Content -Raw .\.swarm-ai-cache\trust\local-only.signed.trust-policy.json)
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/models/hivemind/hello-chat -Method Get
Invoke-RestMethod -Uri 'http://127.0.0.1:8787/v1/hivemind/packages?kind=model&capability=chat' -Method Get
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/hivemind/resolve -Method Post -ContentType application/json -Body '{"packageId":"hivemind/hello-chat","requester":"local-dev","requestedUse":"personal"}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/hivemind/policy/evaluate -Method Post -ContentType application/json -Body '{"packageId":"hivemind/hello-chat","requester":"local-dev","requestedUse":"personal","runnerId":"local-dev-runner"}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/hivemind/marketplace/listings -Method Get
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/hivemind/receipts/receipt-id -Method Get
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/hivemind/validations/validation-report-id -Method Get
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/files -Method Post -ContentType application/json -Body '{"purpose":"assistants","filename":"docs.jsonl","ref":"bzz://document-collection","bytes":1024}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/vector_stores -Method Post -ContentType application/json -Body '{"name":"Company Docs","file_ids":["file-reference-id"],"embedding_model":"hivemind/hello-embedding","dimensions":384}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/vector_stores/vector-store-id/search -Method Post -ContentType application/json -Body '{"query":"security policy","max_num_results":5}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/batches -Method Post -ContentType application/json -Body '{"input_file_id":"file-reference-id","endpoint":"/v1/embeddings","completion_window":"24h","model":"hivemind/hello-embedding","package_ref":"bzz://embedding-package"}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/fine_tuning/jobs -Method Post -ContentType application/json -Body '{"model":"hivemind/hello-chat","training_file":"file-training-data","validation_file":"file-validation-data","hyperparameters":{"n_epochs":2},"recipe_ref":"bzz://fine-tune-recipe","privacy_tier":"tee-confidential"}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/realtime/sessions -Method Post -ContentType application/json -Body '{"model":"hivemind/realtime-agent","modalities":["audio","text"],"voice":"alloy","transport":"websocket","latency_target_ms":200,"metadata":{"requester":"local-dev"}}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/evals -Method Post -ContentType application/json -Body '{"name":"RAG answer quality","model":"hivemind/rag-agent","data_source":{"file_id":"file-eval-dataset"},"testing_criteria":[{"type":"model_grader","model":"hivemind/grader","criteria":"answer correctness"}],"metadata":{"requester":"local-dev"}}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/evals/eval-id/runs -Method Post -ContentType application/json -Body '{"model":"hivemind/rag-agent","data_source":{"file_ids":["file-eval-dataset"]},"sample_count":25,"metadata":{"requester":"local-dev","privacyTier":"no-log"}}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/images/generations -Method Post -ContentType application/json -Body '{"model":"hivemind/image","prompt":"a Swarm-backed AI package network","n":1,"size":"1024x1024","response_format":"url","metadata":{"requester":"local-dev"}}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/images/edits -Method Post -ContentType application/json -Body '{"model":"hivemind/image-edit","image":"file-source-image","mask":"file-edit-mask","prompt":"replace the background with a clean studio","n":1,"size":"1024x1024","response_format":"url","metadata":{"requester":"local-dev"}}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/audio/transcriptions -Method Post -ContentType application/json -Body '{"model":"hivemind/transcribe","file":"file-audio-sample","language":"en","metadata":{"requester":"local-dev"}}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/audio/speech -Method Post -ContentType application/json -Body '{"model":"hivemind/speech","input":"Hivemind media jobs are planned as signed contracts.","voice":"alloy","response_format":"mp3","metadata":{"requester":"local-dev"}}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/hivemind/ai/sign-request -Method Post -ContentType application/json -Body '{"schemaVersion":"hivemind.request.v1","requestId":"unsigned-demo","requester":"local-dev","apiSurface":"hivemind_native","packageSelector":{"model":"hivemind/hello-chat"},"inputs":[{"type":"text","content":"sign this AIRequestV1"}],"task":"chat"}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/hivemind/ai/verify-request -Method Post -ContentType application/json -Body '{"schemaVersion":"hivemind.request.v1","requestId":"ai-demo-1","requester":"local-dev","apiSurface":"hivemind_native","packageSelector":{"model":"hivemind/hello-chat"},"inputs":[{"type":"text","content":"verify this AIRequestV1"}],"task":"chat"}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/hivemind/ai/plan -Method Post -ContentType application/json -Body '{"schemaVersion":"hivemind.request.v1","requestId":"ai-plan-demo-1","requester":"local-dev","apiSurface":"hivemind_native","packageSelector":{"model":"hivemind/hello-chat"},"inputs":[{"type":"text","content":"plan this AIRequestV1"}],"task":"chat","metadata":{"policyMode":"balanced","maxMarketplaceResults":3}}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/hivemind/ai -Method Post -ContentType application/json -Body '{"schemaVersion":"hivemind.request.v1","requestId":"ai-demo-1","requester":"local-dev","apiSurface":"hivemind_native","packageSelector":{"model":"hivemind/hello-chat"},"inputs":[{"type":"text","content":"hello through AIRequestV1"}],"task":"chat","metadata":{"policyMode":"balanced","maxMarketplaceResults":3}}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/chat/completions -Method Post -ContentType application/json -Body '{"model":"hivemind/hello-chat","messages":[{"role":"user","content":"hello"}]}'
curl.exe -N http://127.0.0.1:8787/v1/chat/completions -H "Content-Type: application/json" -d '{"model":"hivemind/hello-chat","stream":true,"messages":[{"role":"user","content":"hello as SSE"}]}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/responses -Method Post -ContentType application/json -Body '{"model":"hivemind/hello-chat","input":"explain this package","instructions":"Be concise"}'
curl.exe -N http://127.0.0.1:8787/v1/responses -H "Content-Type: application/json" -d '{"model":"hivemind/hello-chat","stream":true,"input":"explain this package as SSE","instructions":"Be concise"}'
curl.exe -N http://127.0.0.1:8787/v1/swarm-ai/jobs/example-job-id/stream?format=sse
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/swarm-ai/jobs/example-job-id/timeline
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/swarm-ai/jobs/example-job-id/lifecycle
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/swarm-ai/jobs/lifecycle-audit -Method Post -ContentType application/json -Body '{"schemaVersion":"swarm-ai.job-store-audit-request.v1"}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/swarm-ai/jobs/example-job-id/evidence -Method Post -ContentType application/json -Body '{"schemaVersion":"swarm-ai.job-evidence-link-request.v1","jobId":"example-job-id","evidenceKind":"validation-report","evidenceRef":"local://validation/report-id","evidenceId":"report-id","linkedBy":"validator-1"}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/swarm-ai/jobs/example-job-id/cancel -Method Post -ContentType application/json -Body '{"schemaVersion":"swarm-ai.job-cancellation-request.v1","jobId":"example-job-id","cancelledBy":"local-dev","reason":"user requested stop"}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/hivemind/observability/snapshot -Method Get
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/anthropic/messages -Method Post -ContentType application/json -Body '{"model":"hivemind/hello-chat","max_tokens":64,"messages":[{"role":"user","content":"hello from an Anthropic-style client"}]}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/gemini/generateContent -Method Post -ContentType application/json -Body '{"model":"hivemind/hello-chat","contents":[{"role":"user","parts":[{"text":"hello from a Gemini-style client"}]}]}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/gemini/live/sessions -Method Post -ContentType application/json -Body '{"model":"hivemind/realtime","inputModalities":["audio","text"],"responseModalities":["audio","text"],"transport":"websocket","latencyTargetMs":150,"privacyTier":"no_log","metadata":{"requester":"local-dev"}}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/huggingface/inference/hivemind/hello-chat -Method Post -ContentType application/json -Body '{"inputs":"hello from a Hugging Face-style client","task":"text-generation","parameters":{"max_new_tokens":64}}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/huggingface/inference/hivemind/hello-embedding -Method Post -ContentType application/json -Body '{"inputs":["hello","swarm"],"task":"feature-extraction"}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/embeddings -Method Post -ContentType application/json -Body '{"model":"hivemind/hello-embedding","input":["hello","swarm"]}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/moderations -Method Post -ContentType application/json -Body '{"model":"hivemind/moderation","input":["please classify this message"]}'
cargo run -p hivemind-server -- issue-grant bzz://commercial-local-dir-reference --grantee local-dev --output .\.swarm-ai-cache\commercial.grant.json
cargo run -p hivemind-server -- verify-grant .\.swarm-ai-cache\commercial.grant.json
cargo run -p hivemind-server -- identity generate --subject local-dev --output .\.swarm-ai-cache\identity\local-dev.identity.json
cargo run -p hivemind-server -- issue-grant bzz://commercial-local-dir-reference --grantee local-dev --issuer local-dev --identity .\.swarm-ai-cache\identity\local-dev.identity.json --output .\.swarm-ai-cache\commercial.identity.grant.json
cargo run -p hivemind-server -- access-grants
cargo run -p hivemind-server -- get-grant grant-id
cargo run -p hivemind-server -- verify-grant .\.swarm-ai-cache\commercial.identity.grant.json
cargo run -p hivemind-server -- revoke-grant .\.swarm-ai-cache\commercial.grant.json --reason "subscription ended" --output .\.swarm-ai-cache\commercial.revocation.json
cargo run -p hivemind-server -- revoke-grant .\.swarm-ai-cache\commercial.identity.grant.json --revoked-by local-dev --reason "subscription ended" --identity .\.swarm-ai-cache\identity\local-dev.identity.json --output .\.swarm-ai-cache\commercial.identity.revocation.json
cargo run -p hivemind-server -- access-revocations
cargo run -p hivemind-server -- get-revocation revocation-id
cargo run -p hivemind-server -- verify-grant-revocation .\.swarm-ai-cache\commercial.revocation.json --grant .\.swarm-ai-cache\commercial.grant.json
cargo run -p hivemind-server -- revocation-list .\.swarm-ai-cache\commercial.revocation.json > .\.swarm-ai-cache\commercial.revocations.json
cargo run -p hivemind-server -- verify-revocation-list .\.swarm-ai-cache\commercial.revocations.json
cargo run -p hivemind-server -- run-ref bzz://commercial-local-dir-reference --grant .\.swarm-ai-cache\commercial.grant.json --task embedding --text "paid ref"
cargo run -p hivemind-server -- marketplace listings
cargo run -p hivemind-server -- marketplace listings --output-dir .\.swarm-ai-cache\marketplace\listings
cargo run -p hivemind-server -- identity generate --subject local-market --output .\.swarm-ai-cache\identity\market.identity.json
cargo run -p hivemind-server -- marketplace listings --owner local-market --identity .\.swarm-ai-cache\identity\market.identity.json
cargo run -p hivemind-server -- marketplace verify-listing --listing .\.swarm-ai-cache\marketplace\listing.json
cargo run -p hivemind-server -- marketplace sign-listing --listing .\.swarm-ai-cache\marketplace\listing.json --identity .\.swarm-ai-cache\identity\market.identity.json --output .\.swarm-ai-cache\marketplace\listing.identity.json
cargo run -p hivemind-server -- marketplace offers
cargo run -p hivemind-server -- marketplace offers --output-dir .\.swarm-ai-cache\marketplace\offers
cargo run -p hivemind-server -- identity generate --subject local-dev-runner --output .\.swarm-ai-cache\identity\runner.identity.json
cargo run -p hivemind-server -- marketplace offers --identity .\.swarm-ai-cache\identity\runner.identity.json
cargo run -p hivemind-server -- marketplace hardware-offers --operator local-market
cargo run -p hivemind-server -- marketplace hardware-offers --operator local-market --output-dir .\.swarm-ai-cache\marketplace\hardware-offers
cargo run -p hivemind-server -- marketplace verify-hardware-offer --offer .\.swarm-ai-cache\marketplace\hardware-offer.json
cargo run -p hivemind-server -- marketplace sign-hardware-offer --offer .\.swarm-ai-cache\marketplace\hardware-offer.json --identity .\.swarm-ai-cache\identity\market.identity.json --output .\.swarm-ai-cache\marketplace\hardware-offer.identity.json
cargo run -p hivemind-server -- miner profile --offer .\.swarm-ai-cache\marketplace\hardware-offer.json --daemon-version 0.1.0-dev --output .\.swarm-ai-cache\miner\profile.json
cargo run -p hivemind-server -- miner verify-profile --profile .\.swarm-ai-cache\miner\profile.json --offer .\.swarm-ai-cache\marketplace\hardware-offer.json
cargo run -p hivemind-server -- miner heartbeat --profile .\.swarm-ai-cache\miner\profile.json --status busy --queue-depth 1 --active-jobs 1 --current-job-id job-id --load-average 0.42 --output .\.swarm-ai-cache\miner\heartbeat.json
cargo run -p hivemind-server -- miner benchmark --profile .\.swarm-ai-cache\miner\profile.json --offer .\.swarm-ai-cache\marketplace\hardware-offer.json --suite local-miner-smoke --workload chat-throughput --metric tokens_per_second=42:tokens/s --evidence-ref bzz://benchmark-evidence --output .\.swarm-ai-cache\miner\benchmark.json
cargo run -p hivemind-server -- miner verify-benchmark --benchmark .\.swarm-ai-cache\miner\benchmark.json --profile .\.swarm-ai-cache\miner\profile.json --offer .\.swarm-ai-cache\marketplace\hardware-offer.json
cargo run -p hivemind-server -- miner onboarding --profile .\.swarm-ai-cache\miner\profile.json --offer .\.swarm-ai-cache\marketplace\hardware-offer.json --benchmark .\.swarm-ai-cache\miner\benchmark.json
cargo run -p hivemind-server -- miner dashboard --profile .\.swarm-ai-cache\miner\profile.json --heartbeat .\.swarm-ai-cache\miner\heartbeat.json --offer .\.swarm-ai-cache\marketplace\hardware-offer.json --benchmark .\.swarm-ai-cache\miner\benchmark.json --completed-jobs 3 --settled-jobs 2 --earning-amount 1.25
cargo run -p hivemind-server -- miner list
cargo run -p hivemind-server -- miner get miner-record-id
cargo run -p hivemind-server -- marketplace shortlist bzz://commercial-local-dir-reference --package-id hivemind/commercial-embedding --task embedding --text "rank runners" --policy balanced --offers .\.swarm-ai-cache\marketplace\offers
cargo run -p hivemind-server -- marketplace verify-offer --offer .\.swarm-ai-cache\marketplace\offer.json
cargo run -p hivemind-server -- marketplace sign-offer --offer .\.swarm-ai-cache\marketplace\offer.json --identity .\.swarm-ai-cache\identity\runner.identity.json --output .\.swarm-ai-cache\marketplace\offer.identity.json
cargo run -p hivemind-server -- marketplace quote bzz://commercial-local-dir-reference --package-id hivemind/commercial-embedding --task embedding --text "quote me" --offers .\.swarm-ai-cache\marketplace\offers
cargo run -p hivemind-server -- marketplace quote bzz://commercial-local-dir-reference --package-id hivemind/commercial-embedding --task embedding --text "quote me" --offers .\.swarm-ai-cache\marketplace\offers --identity .\.swarm-ai-cache\identity\runner.identity.json
cargo run -p hivemind-server -- marketplace verify-quote --quote .\.swarm-ai-cache\marketplace\quote.json --offer .\.swarm-ai-cache\marketplace\offer.json
cargo run -p hivemind-server -- marketplace sign-quote --quote .\.swarm-ai-cache\marketplace\quote.json --identity .\.swarm-ai-cache\identity\runner.identity.json --output .\.swarm-ai-cache\marketplace\quote.identity.json
cargo run -p hivemind-server -- marketplace authorize-payment --quote .\.swarm-ai-cache\marketplace\quote.json --payer local-dev --payee local-dev-runner --payment-ref local://payment/dev-auth --output .\.swarm-ai-cache\marketplace\payment.json
cargo run -p hivemind-server -- marketplace authorize-payment --quote .\.swarm-ai-cache\marketplace\quote.json --payer local-dev --payee local-dev-runner --payment-ref local://payment/dev-auth --identity .\.swarm-ai-cache\identity\local-dev.identity.json --output .\.swarm-ai-cache\marketplace\payment.identity.json
cargo run -p hivemind-server -- marketplace payments
cargo run -p hivemind-server -- marketplace get-payment authorization-id
cargo run -p hivemind-server -- marketplace sign-payment --authorization .\.swarm-ai-cache\marketplace\payment.json --identity .\.swarm-ai-cache\identity\local-dev.identity.json --output .\.swarm-ai-cache\marketplace\payment.signed.json
cargo run -p hivemind-server -- marketplace verify-payment --authorization .\.swarm-ai-cache\marketplace\payment.json --quote .\.swarm-ai-cache\marketplace\quote.json
cargo run -p hivemind-server -- marketplace settle --receipt .\.swarm-ai-cache\marketplace\commercial.receipt.json --quote .\.swarm-ai-cache\marketplace\commercial.quote.json --payment-authorization .\.swarm-ai-cache\marketplace\payment.json
cargo run -p hivemind-server -- marketplace settle --receipt .\.swarm-ai-cache\marketplace\commercial.receipt.json --quote .\.swarm-ai-cache\marketplace\commercial.quote.json --payment-authorization .\.swarm-ai-cache\marketplace\payment.json --payee local-dev-runner --identity .\.swarm-ai-cache\identity\runner.identity.json
cargo run -p hivemind-server -- marketplace audit
cargo run -p hivemind-server -- marketplace verify-settlement --settlement .\.swarm-ai-cache\marketplace\settlement.json
cargo run -p hivemind-server -- marketplace sign-settlement --settlement .\.swarm-ai-cache\marketplace\settlement.json --identity .\.swarm-ai-cache\identity\runner.identity.json --output .\.swarm-ai-cache\marketplace\settlement.identity.json
cargo run -p hivemind-server -- identity generate --subject local-market --output .\.swarm-ai-cache\identity\resolver.identity.json
cargo run -p hivemind-server -- marketplace dispute-settlement --settlement .\.swarm-ai-cache\marketplace\settlement.json --dispute .\.swarm-ai-cache\disputes\dispute-id.json --resolved-by local-market --identity .\.swarm-ai-cache\identity\resolver.identity.json
cargo run -p hivemind-server -- marketplace refund-settlement --settlement .\.swarm-ai-cache\marketplace\disputed-settlement.json --dispute .\.swarm-ai-cache\disputes\dispute-id.json --resolved-by local-market --identity .\.swarm-ai-cache\identity\resolver.identity.json
cargo run -p hivemind-server -- marketplace reject-dispute --settlement .\.swarm-ai-cache\marketplace\disputed-settlement.json --dispute .\.swarm-ai-cache\disputes\dispute-id.json --resolved-by local-market --identity .\.swarm-ai-cache\identity\resolver.identity.json
cargo run -p hivemind-server -- marketplace get-settlement settlement-id
cargo run -p hivemind-server -- marketplace get-resolution resolution-id
cargo run -p hivemind-server -- marketplace verify-resolution --resolution .\.swarm-ai-cache\marketplace\resolution.json
cargo run -p hivemind-server -- marketplace sign-resolution --resolution .\.swarm-ai-cache\marketplace\resolution.json --identity .\.swarm-ai-cache\identity\resolver.identity.json --output .\.swarm-ai-cache\marketplace\resolution.identity.json
cargo run -p hivemind-server -- validate-run bzz://local-dir-reference --task embedding --text "validator hello"
cargo run -p hivemind-server -- identity generate --subject local-dev-validator --output .\.swarm-ai-cache\identity\validator.identity.json
cargo run -p hivemind-server -- validate-run bzz://local-dir-reference --task embedding --text "validator hello" --validator-id local-dev-validator --identity .\.swarm-ai-cache\identity\validator.identity.json
cargo run -p hivemind-server -- sign-validation .\.swarm-ai-cache\validations\validation-id.json --identity .\.swarm-ai-cache\identity\validator.identity.json --output .\.swarm-ai-cache\validations\validation-id.identity.json
cargo run -p hivemind-server -- benchmark-run bzz://local-dir-reference --benchmark embedding-basic
cargo run -p hivemind-server -- benchmark-run bzz://local-dir-reference --benchmark embedding-basic --validator-id local-dev-validator --identity .\.swarm-ai-cache\identity\validator.identity.json
cargo run -p hivemind-server -- sign-evaluation .\.swarm-ai-cache\evaluations\evaluation-id.json --identity .\.swarm-ai-cache\identity\validator.identity.json --output .\.swarm-ai-cache\evaluations\evaluation-id.identity.json
cargo run -p hivemind-server -- evaluation-results
cargo run -p hivemind-server -- evaluation-leaderboard
cargo run -p hivemind-server -- get-evaluation evaluation-id
cargo run -p hivemind-server -- evaluation-v2-from-v1 .\.swarm-ai-cache\evaluations\evaluation-id.json .\.swarm-ai-cache\evaluations\v2\evaluation-id.v2.json --suite-id suite-embedding-basic --started-at 2026-06-02T00:00:00Z --completed-at 2026-06-02T00:00:01Z --cost-amount 0.01 --cost-currency USD --pricing-ref local://pricing/free-tier --runner-type local --hardware-ref local://hardware/cpu --software-ref bzz://software-lockfile --artifact-ref bzz://evaluation-artifact --random-seed seed-1 --force
cargo run -p hivemind-server -- verify-evaluation-v2 .\.swarm-ai-cache\evaluations\v2\evaluation-id.v2.json
cargo run -p hivemind-server -- sign-evaluation-v2 .\.swarm-ai-cache\evaluations\v2\evaluation-id.v2.json --identity .\.swarm-ai-cache\identity\validator.identity.json --output .\.swarm-ai-cache\evaluations\v2\evaluation-id.identity.v2.json
cargo run -p hivemind-server -- evaluation-results-v2
cargo run -p hivemind-server -- get-evaluation-v2 evaluation-v2-id
cargo run -p hivemind-server -- benchmark-suite-init .\.swarm-ai-cache\evaluations\suites\embedding-basic.suite.json --dataset-ref local://datasets/embedding-basic-v1 --split "public|1.0|false|local://datasets/embedding-basic-v1" --allowed-model-ref package-kind://model --allowed-runtime local --metric quality --metric latency --metric overall --force
cargo run -p hivemind-server -- verify-benchmark-suite .\.swarm-ai-cache\evaluations\suites\embedding-basic.suite.json
cargo run -p hivemind-server -- sign-benchmark-suite .\.swarm-ai-cache\evaluations\suites\embedding-basic.suite.json --identity .\.swarm-ai-cache\identity\validator.identity.json --output .\.swarm-ai-cache\evaluations\suites\embedding-basic.identity.suite.json
cargo run -p hivemind-server -- benchmark-suites
cargo run -p hivemind-server -- get-benchmark-suite benchmark-suite-id
cargo run -p hivemind-server -- challenge-commitment-init .\.swarm-ai-cache\evaluations\challenges\embedding-basic.challenge.json --challenge-set-hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --answer-set-hash bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --salt-hash cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --challenge-count 12 --public-dataset-ref bzz://public-dataset --hidden-ref-commitment dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd --scoring-rule-ref local://scoring/embedding-shape --force
cargo run -p hivemind-server -- verify-challenge-commitment .\.swarm-ai-cache\evaluations\challenges\embedding-basic.challenge.json
cargo run -p hivemind-server -- sign-challenge-commitment .\.swarm-ai-cache\evaluations\challenges\embedding-basic.challenge.json --identity .\.swarm-ai-cache\identity\validator.identity.json --output .\.swarm-ai-cache\evaluations\challenges\embedding-basic.identity.challenge.json
cargo run -p hivemind-server -- challenge-commitments
cargo run -p hivemind-server -- get-challenge-commitment challenge-commitment-id
cargo run -p hivemind-server -- verify-validation .\.swarm-ai-cache\validations\validation-id.json
cargo run -p hivemind-server -- upload-validation .\.swarm-ai-cache\validations\validation-id.json
cargo run -p hivemind-server -- download-validation bzz://local-bytes-validation-report-ref
cargo run -p hivemind-server -- validation-reports
cargo run -p hivemind-server -- get-validation validation-id
cargo run -p hivemind-server -- integrity-evidence-init .\.swarm-ai-cache\validations\integrity\runner-attestation.json --evidence-kind tee-attestation --validator-id local-dev-validator --runner-id confidential-runner --subject-type runner --subject-id confidential-runner --measurement-hash sha256:measured-environment --expected-measurement-hash sha256:measured-environment --evidence-ref bzz://attestation-quote --force
cargo run -p hivemind-server -- verify-integrity-evidence .\.swarm-ai-cache\validations\integrity\runner-attestation.json
cargo run -p hivemind-server -- integrity-evidence-records
cargo run -p hivemind-server -- get-integrity-evidence integrity-evidence-id
cargo run -p hivemind-server -- reputation --subject-type runner local-dev-runner
cargo run -p hivemind-server -- verify-evaluation .\.swarm-ai-cache\evaluations\evaluation-id.json
cargo run -p hivemind-server -- eval init .\.swarm-ai-cache\evals\rag.eval.json --name "RAG answer quality" --owner local-dev-eval-owner --kind rag --dataset-ref bzz://eval-dataset --scoring-rule-ref bzz://scoring-rule --target-ref bzz://rag-package --force
cargo run -p hivemind-server -- eval verify .\.swarm-ai-cache\evals\rag.eval.json
cargo run -p hivemind-server -- eval run-init .\.swarm-ai-cache\evals\rag.run.json --eval-id eval-id --requester local-dev-eval-requester --target-ref bzz://rag-package --input-ref bzz://eval-inputs --sample-count 25 --force
cargo run -p hivemind-server -- eval run-verify .\.swarm-ai-cache\evals\rag.run.json
cargo run -p hivemind-server -- eval plan .\.swarm-ai-cache\evals\rag.eval.json .\.swarm-ai-cache\evals\rag.run.json
cargo run -p hivemind-server -- eval list
cargo run -p hivemind-server -- eval get eval-record-id
cargo run -p hivemind-server -- experiment init .\.swarm-ai-cache\research\embedding-comparison.experiment.json --title "Compare embedding models" --author local-dev-researcher --hypothesis "Model A improves retrieval quality" --package-ref bzz://local-dir-reference --dataset-ref bzz://dataset-reference --benchmark-ref bzz://benchmark-reference --force
cargo run -p hivemind-server -- experiment verify .\.swarm-ai-cache\research\embedding-comparison.experiment.json
cargo run -p hivemind-server -- experiment reproduce .\.swarm-ai-cache\research\embedding-comparison.experiment.json --runner local
cargo run -p hivemind-server -- experiment run-init .\.swarm-ai-cache\research\embedding-comparison.experiment.json .\.swarm-ai-cache\research\embedding-comparison.run.json --requester local-dev-researcher --runner local --receipt-ref receipt://receipt-id --evaluation-result-ref evaluation://evaluation-id --output-ref bzz://experiment-output --force
cargo run -p hivemind-server -- experiment run-verify .\.swarm-ai-cache\research\embedding-comparison.run.json --experiment .\.swarm-ai-cache\research\embedding-comparison.experiment.json
cargo run -p hivemind-server -- experiment run-list
cargo run -p hivemind-server -- experiment run-get experiment-run-id
cargo run -p hivemind-server -- experiment sign .\.swarm-ai-cache\research\embedding-comparison.experiment.json --identity .\.swarm-ai-cache\identity\researcher.identity.json --output .\.swarm-ai-cache\research\embedding-comparison.identity.experiment.json
cargo run -p hivemind-server -- experiment list
cargo run -p hivemind-server -- experiment get experiment-id
cargo run -p hivemind-server -- vector init .\.swarm-ai-cache\vector\company-docs.vector.json --name "Company Docs" --owner local-dev-vector-owner --embedding-model-ref bzz://embedding-model --document-ref bzz://document-collection --storage-ref index=bzz://vector-index --storage-ref chunks=bzz://document-chunks --force
cargo run -p hivemind-server -- vector verify .\.swarm-ai-cache\vector\company-docs.vector.json
cargo run -p hivemind-server -- vector plan .\.swarm-ai-cache\vector\company-docs.vector.json --text "find security policy" --top-k 5
cargo run -p hivemind-server -- vector sign .\.swarm-ai-cache\vector\company-docs.vector.json --identity .\.swarm-ai-cache\identity\vector-owner.identity.json --output .\.swarm-ai-cache\vector\company-docs.identity.vector.json
cargo run -p hivemind-server -- vector list
cargo run -p hivemind-server -- vector get vector-store-id
cargo run -p hivemind-server -- workflow tool-init .\.swarm-ai-cache\workflow\repo-search.tool.json --name "Repository Search" --description "Searches repository content" --publisher local-dev-tool-publisher --permission filesystem-read:"Read indexed repository files" --safety-policy-ref bzz://tool-safety-policy --force
cargo run -p hivemind-server -- workflow tool-verify .\.swarm-ai-cache\workflow\repo-search.tool.json
cargo run -p hivemind-server -- workflow init .\.swarm-ai-cache\workflow\rag-answer.workflow.json --name "RAG Answer" --publisher local-dev-workflow-publisher --tool-ref bzz://repo-search-tool --vector-store-ref bzz://company-docs-vector --package-ref bzz://answer-package --trace-policy full --force
cargo run -p hivemind-server -- workflow verify .\.swarm-ai-cache\workflow\rag-answer.workflow.json
cargo run -p hivemind-server -- workflow plan .\.swarm-ai-cache\workflow\rag-answer.workflow.json
cargo run -p hivemind-server -- workflow list
cargo run -p hivemind-server -- workflow get workflow-or-tool-record-id
cargo run -p hivemind-server -- batch init .\.swarm-ai-cache\batch\embedding.batch.json --requester local-dev-requester --package-ref bzz://embedding-package --package-id hivemind/embedding --package-version 0.1.0 --task embedding --item "first document" --item "second document" --max-concurrency 2 --force
cargo run -p hivemind-server -- batch verify .\.swarm-ai-cache\batch\embedding.batch.json
cargo run -p hivemind-server -- batch plan .\.swarm-ai-cache\batch\embedding.batch.json
cargo run -p hivemind-server -- batch sign .\.swarm-ai-cache\batch\embedding.batch.json --identity .\.swarm-ai-cache\identity\requester.identity.json --output .\.swarm-ai-cache\batch\embedding.identity.batch.json
cargo run -p hivemind-server -- batch list
cargo run -p hivemind-server -- batch get batch-id
cargo run -p hivemind-server -- fine-tune init .\.swarm-ai-cache\fine-tune\adapter.fine-tune.json --requester local-dev-requester --base-model-ref bzz://base-model --training-dataset-ref bzz://training-dataset --validation-dataset-ref bzz://validation-dataset --recipe-ref bzz://fine-tune-recipe --output-ref local://fine-tune/output --max-cost-amount 10 --force
cargo run -p hivemind-server -- fine-tune verify .\.swarm-ai-cache\fine-tune\adapter.fine-tune.json
cargo run -p hivemind-server -- fine-tune plan .\.swarm-ai-cache\fine-tune\adapter.fine-tune.json
cargo run -p hivemind-server -- fine-tune sign .\.swarm-ai-cache\fine-tune\adapter.fine-tune.json --identity .\.swarm-ai-cache\identity\requester.identity.json --output .\.swarm-ai-cache\fine-tune\adapter.identity.fine-tune.json
cargo run -p hivemind-server -- fine-tune list
cargo run -p hivemind-server -- fine-tune get fine-tune-job-id
cargo run -p hivemind-server -- realtime init .\.swarm-ai-cache\realtime\voice.session.json --requester local-dev-requester --package-ref bzz://realtime-session-package --package-id hivemind/realtime-agent --package-version 0.1.0 --modality-in audio --modality-in text --modality-out audio --modality-out text --transport websocket --latency-target-ms 200 --tool-ref bzz://tool --force
cargo run -p hivemind-server -- realtime verify .\.swarm-ai-cache\realtime\voice.session.json
cargo run -p hivemind-server -- realtime plan .\.swarm-ai-cache\realtime\voice.session.json
cargo run -p hivemind-server -- realtime sign .\.swarm-ai-cache\realtime\voice.session.json --identity .\.swarm-ai-cache\identity\requester.identity.json --output .\.swarm-ai-cache\realtime\voice.identity.session.json
cargo run -p hivemind-server -- realtime list
cargo run -p hivemind-server -- realtime get session-id
cargo run -p hivemind-server -- media init .\.swarm-ai-cache\media\image.media.json --requester local-dev-requester --task image-generation --package-id hivemind/image --model-alias hivemind/image --prompt "a Swarm-backed AI package network" --response-format url --output-ref local://media/output/image --size 1024x1024 --force
cargo run -p hivemind-server -- media verify .\.swarm-ai-cache\media\image.media.json
cargo run -p hivemind-server -- media plan .\.swarm-ai-cache\media\image.media.json
cargo run -p hivemind-server -- media sign .\.swarm-ai-cache\media\image.media.json --identity .\.swarm-ai-cache\identity\requester.identity.json --output .\.swarm-ai-cache\media\image.identity.media.json
cargo run -p hivemind-server -- media list
cargo run -p hivemind-server -- media get media-job-id
cargo run -p hivemind-server -- moderation policy-init .\.swarm-ai-cache\moderation\default.policy.json --name "Default Moderation" --publisher local-dev-policy-publisher --model-ref bzz://moderation-model --safety-policy-ref bzz://safety-policy --force
cargo run -p hivemind-server -- moderation policy-verify .\.swarm-ai-cache\moderation\default.policy.json
cargo run -p hivemind-server -- moderation request-init .\.swarm-ai-cache\moderation\classify.request.json --requester local-dev-requester --package-ref bzz://moderation-model --package-id hivemind/moderation --package-version 0.1.0 --policy-ref bzz://moderation-policy --text "please classify this message" --modality text --category harassment --force
cargo run -p hivemind-server -- moderation request-verify .\.swarm-ai-cache\moderation\classify.request.json
cargo run -p hivemind-server -- moderation plan .\.swarm-ai-cache\moderation\classify.request.json --policy .\.swarm-ai-cache\moderation\default.policy.json
cargo run -p hivemind-server -- moderation request-sign .\.swarm-ai-cache\moderation\classify.request.json --identity .\.swarm-ai-cache\identity\requester.identity.json --output .\.swarm-ai-cache\moderation\classify.identity.request.json
cargo run -p hivemind-server -- moderation list
cargo run -p hivemind-server -- moderation get moderation-record-id
cargo run -p hivemind-server -- governance policy-init .\.swarm-ai-cache\governance\phase-1.policy.json --title "Phase 1 Governance" --steward core-maintainers --scope protocol-schemas --scope compatibility-certification --scope security-response --approved-schema-version hivemind.job_order.v1 --compatibility-test-ref local://compat/phase-1 --force
cargo run -p hivemind-server -- governance policy-verify .\.swarm-ai-cache\governance\phase-1.policy.json
cargo run -p hivemind-server -- governance policy-sign .\.swarm-ai-cache\governance\phase-1.policy.json --identity .\.swarm-ai-cache\identity\core-maintainers.identity.json --output .\.swarm-ai-cache\governance\phase-1.identity.policy.json
cargo run -p hivemind-server -- governance schema-release-init .\.swarm-ai-cache\governance\job-order.schema-release.json --object-type JobOrderV1 --released-schema-version hivemind.job_order.v1 --interface-version 0.2.0 --status production-approved --approved-by core-maintainers --compatibility-test-ref local://compat/job-order --force
cargo run -p hivemind-server -- governance schema-release-verify .\.swarm-ai-cache\governance\job-order.schema-release.json
cargo run -p hivemind-server -- governance advisory-init .\.swarm-ai-cache\governance\sandbox.security-advisory.json --title "Sandbox Escape Advisory" --reporter local-security --severity critical --category sandbox-escape --affected-ref local://runner/native --summary "Native runner sandbox isolation requires review" --impact "Affected runner targets should be disabled until fixed" --force
cargo run -p hivemind-server -- governance advisory-verify .\.swarm-ai-cache\governance\sandbox.security-advisory.json
cargo run -p hivemind-server -- governance response-plan .\.swarm-ai-cache\governance\sandbox.security-advisory.json
cargo run -p hivemind-server -- governance readiness-init .\.swarm-ai-cache\governance\router.component-readiness.json --component-name hivemind-router --component-type crate --owner core-maintainers --status local --implementation-ref local://crates/router --schema-ref urn:schema:hivemind.route_planner_request.v1 --api-surface native-route-planning --environment local-dev --evidence-ref local://tests/router --limitation "local development runner contracts only" --force
cargo run -p hivemind-server -- governance readiness-verify .\.swarm-ai-cache\governance\router.component-readiness.json
cargo run -p hivemind-server -- governance readiness-sign .\.swarm-ai-cache\governance\router.component-readiness.json --identity .\.swarm-ai-cache\identity\core-maintainers.identity.json --output .\.swarm-ai-cache\governance\router.identity.component-readiness.json
cargo run -p hivemind-server -- governance list
cargo run -p hivemind-server -- governance get governance-record-id
cargo run -p hivemind-server -- registry get hivemind/hello-embedding
cargo run -p hivemind-server -- registry get hivemind/private-embedding --grant .\.swarm-ai-cache\private.grant.json --requester local-dev --runner-id local-dev-runner
cargo run -p hivemind-server -- registry rebuild
cargo run -p hivemind-server -- registry rebuild --marketplace-listings .\.swarm-ai-cache\marketplace\listings --marketplace-offers .\.swarm-ai-cache\marketplace\offers --marketplace-hardware-offers .\.swarm-ai-cache\marketplace\hardware-offers --governance-dir .\.swarm-ai-cache\governance
cargo run -p hivemind-server -- registry rebuild --include-private --output .\.swarm-ai-cache\private-registry.json
cargo run -p hivemind-server -- registry verify-snapshot
cargo run -p hivemind-server -- registry shards
cargo run -p hivemind-server -- registry verify-shards
cargo run -p hivemind-server -- registry compare-manifest
cargo run -p hivemind-server -- registry verify-manifest
cargo run -p hivemind-server -- registry shards --include-private --input .\.swarm-ai-cache\private-registry.json --output .\.swarm-ai-cache\private-shards
cargo run -p hivemind-server -- registry verify-shards --include-private --input .\.swarm-ai-cache\private-registry.json --shards .\.swarm-ai-cache\private-shards
cargo run -p hivemind-server -- registry compare-manifest --include-private --input .\.swarm-ai-cache\private-registry.json --manifest .\.swarm-ai-cache\private-shards\manifest.json
cargo run -p hivemind-server -- registry verify-manifest --include-private --input .\.swarm-ai-cache\private-registry.json --shards .\.swarm-ai-cache\private-shards
cargo run -p hivemind-server -- compat .\examples\packages\hello-embedding
cargo run -p hivemind-server -- certify .\examples\packages\hello-embedding
cargo run -p hivemind-server -- identity generate --subject local-compat-certifier --output .\.swarm-ai-cache\identity\compat-certifier.identity.json
cargo run -p hivemind-server -- certify .\examples\packages\hello-embedding --identity .\.swarm-ai-cache\identity\compat-certifier.identity.json --implementation-name hivemind-hello-embedding --output .\.swarm-ai-cache\compat\hello-embedding.certification.json
cargo run -p hivemind-server -- certify .\examples\packages\hello-embedding --identity .\.swarm-ai-cache\identity\compat-certifier.identity.json --implementation-name hivemind-hello-embedding --store
cargo run -p hivemind-server -- certifications list
cargo run -p hivemind-server -- certifications get compat-cert-id
cargo run -p hivemind-server -- verify-certification .\.swarm-ai-cache\compat\hello-embedding.certification.json --expected-signer local-compat-certifier
cargo run -p hivemind-server -- schema package-v2
cargo run -p hivemind-server -- schema package-v3
cargo run -p hivemind-server -- schema package-v4
cargo run -p hivemind-server -- schema artifact-group-v2
cargo run -p hivemind-server -- schema universal-capability
cargo run -p hivemind-server -- schema asset-descriptor
cargo run -p hivemind-server -- schema runtime-descriptor-v2
cargo run -p hivemind-server -- schema browser-publish-profile
cargo run -p hivemind-server -- schema ai-request
cargo run -p hivemind-server -- schema ai-workload
cargo run -p hivemind-server -- schema ai-workload-verification
cargo run -p hivemind-server -- schema task-envelope
cargo run -p hivemind-server -- schema task-envelope-verification
cargo run -p hivemind-server -- schema task-envelope-input
cargo run -p hivemind-server -- schema expected-output-descriptor
cargo run -p hivemind-server -- schema ai-request-verification
cargo run -p hivemind-server -- schema ai-response
cargo run -p hivemind-server -- schema ai-response-verification
cargo run -p hivemind-server -- schema ai-execution-plan
cargo run -p hivemind-server -- schema universal-route-plan
cargo run -p hivemind-server -- schema ai-input-part
cargo run -p hivemind-server -- schema ai-output-part
cargo run -p hivemind-server -- schema swarm-ai-error
cargo run -p hivemind-server -- schema standard-error-code
cargo run -p hivemind-server -- schema standard-error-definition
cargo run -p hivemind-server -- schema standard-error-catalog
cargo run -p hivemind-server -- schema access-grant
cargo run -p hivemind-server -- schema access-grant-v2
cargo run -p hivemind-server -- schema access-grant-v3
cargo run -p hivemind-server -- schema access-scope
cargo run -p hivemind-server -- schema access-subject
cargo run -p hivemind-server -- schema access-subject-type
cargo run -p hivemind-server -- schema access-policy
cargo run -p hivemind-server -- schema access-policy-verification
cargo run -p hivemind-server -- schema license-policy-v2
cargo run -p hivemind-server -- schema access-policy-v2
cargo run -p hivemind-server -- schema access-policy-v2-verification
cargo run -p hivemind-server -- schema asset-access-rule
cargo run -p hivemind-server -- schema asset-access-rule-v2
cargo run -p hivemind-server -- schema paid-access-quote
cargo run -p hivemind-server -- schema access-evaluation-result
cargo run -p hivemind-server -- schema job-access-attachment
cargo run -p hivemind-server -- schema package-init-options
cargo run -p hivemind-server -- schema package-init-result
cargo run -p hivemind-server -- schema package-validation-audit-record
cargo run -p hivemind-server -- schema package-validation-audit-store-summary
cargo run -p hivemind-server -- schema access-grant-verification
cargo run -p hivemind-server -- schema access-grant-v2-verification
cargo run -p hivemind-server -- schema access-grant-v3-verification
cargo run -p hivemind-server -- schema access-grant-store-summary
cargo run -p hivemind-server -- schema access-grant-lookup
cargo run -p hivemind-server -- schema access-grant-revocation
cargo run -p hivemind-server -- schema access-grant-revocation-verification
cargo run -p hivemind-server -- schema access-grant-revocation-store-summary
cargo run -p hivemind-server -- schema access-grant-revocation-lookup
cargo run -p hivemind-server -- schema access-revocation-list
cargo run -p hivemind-server -- schema access-revocation-list-verification
cargo run -p hivemind-server -- schema registry-snapshot
cargo run -p hivemind-server -- schema registry-snapshot-source-record
cargo run -p hivemind-server -- schema registry-snapshot-verification
cargo run -p hivemind-server -- schema registry-package-lookup
cargo run -p hivemind-server -- schema registry-package-lookup-request
cargo run -p hivemind-server -- schema registry-search-audit-record
cargo run -p hivemind-server -- schema registry-search-audit-store-summary
cargo run -p hivemind-server -- schema registry-shard
cargo run -p hivemind-server -- schema registry-shard-manifest
cargo run -p hivemind-server -- schema registry-shard-manifest-comparison
cargo run -p hivemind-server -- schema registry-shard-manifest-comparison-request
cargo run -p hivemind-server -- schema registry-shard-manifest-verification
cargo run -p hivemind-server -- schema registry-shard-manifest-verification-request
cargo run -p hivemind-server -- schema registry-shard-verification
cargo run -p hivemind-server -- schema registry-shard-verification-request
cargo run -p hivemind-server -- schema storage-status
cargo run -p hivemind-server -- schema storage-retry-policy
cargo run -p hivemind-server -- schema storage-transfer-metrics
cargo run -p hivemind-server -- schema storage-download
cargo run -p hivemind-server -- schema storage-upload
cargo run -p hivemind-server -- schema storage-local-inspection
cargo run -p hivemind-server -- schema storage-local-cache-summary
cargo run -p hivemind-server -- schema storage-feed-pointer
cargo run -p hivemind-server -- schema storage-feed-update
cargo run -p hivemind-server -- schema storage-feed-resolution
cargo run -p hivemind-server -- schema storage-pin-result
cargo run -p hivemind-server -- schema storage-provider-descriptor-v3
cargo run -p hivemind-server -- schema storage-provider-kind-v3
cargo run -p hivemind-server -- schema storage-provider-capability-v3
cargo run -p hivemind-server -- schema storage-provider-kind-v4
cargo run -p hivemind-server -- schema browser-swarm-storage-provider-v4
cargo run -p hivemind-server -- schema browser-swarm-capability-report
cargo run -p hivemind-server -- schema browser-swarm-provider-conformance
cargo run -p hivemind-server -- schema browser-swarm-provider-catalog-v4
cargo run -p hivemind-server -- schema browser-storage-capability-probe
cargo run -p hivemind-server -- schema browser-storage-purchase-quote
cargo run -p hivemind-server -- schema browser-storage-purchase-authorization
cargo run -p hivemind-server -- schema browser-storage-session-v2
cargo run -p hivemind-server -- schema storage-event-receipt-v2
cargo run -p hivemind-server -- schema browser-storage-state-report
cargo run -p hivemind-server -- schema storage-cost
cargo run -p hivemind-server -- schema browser-storage-consent
cargo run -p hivemind-server -- schema browser-storage-session
cargo run -p hivemind-server -- schema storage-event-receipt
cargo run -p hivemind-server -- schema storage-sponsorship
cargo run -p hivemind-server -- schema browser-service-worker-policy
cargo run -p hivemind-server -- schema browser-storage-security-assessment-request
cargo run -p hivemind-server -- schema browser-storage-security-assessment
cargo run -p hivemind-server -- schema storage-contract-verification
cargo run -p hivemind-server -- schema identity-keypair
cargo run -p hivemind-server -- schema identity-public
cargo run -p hivemind-server -- schema identity-signature
cargo run -p hivemind-server -- schema identity-signature-verification
cargo run -p hivemind-server -- schema trust-policy
cargo run -p hivemind-server -- schema privacy-tier-profile
cargo run -p hivemind-server -- schema privacy-tier-catalog
cargo run -p hivemind-server -- schema privacy-requirement-assessment-request
cargo run -p hivemind-server -- schema privacy-requirement-assessment
cargo run -p hivemind-server -- schema permission-manifest-v2
cargo run -p hivemind-server -- schema policy-inspection
cargo run -p hivemind-server -- schema risk-inspection-report
cargo run -p hivemind-server -- schema consent-record
cargo run -p hivemind-server -- schema tool-permission-grant
cargo run -p hivemind-server -- schema runner-offer-verification
cargo run -p hivemind-server -- schema hardware-resource-offer
cargo run -p hivemind-server -- schema hardware-resource-offer-verification
cargo run -p hivemind-server -- schema miner-profile
cargo run -p hivemind-server -- schema miner-profile-verification
cargo run -p hivemind-server -- schema miner-heartbeat
cargo run -p hivemind-server -- schema miner-heartbeat-verification
cargo run -p hivemind-server -- schema miner-benchmark-result
cargo run -p hivemind-server -- schema miner-benchmark-verification
cargo run -p hivemind-server -- schema miner-onboarding-plan
cargo run -p hivemind-server -- schema miner-dashboard-input
cargo run -p hivemind-server -- schema miner-dashboard-summary
cargo run -p hivemind-server -- schema miner-record-store-summary
cargo run -p hivemind-server -- schema miner-record-lookup
cargo run -p hivemind-server -- schema miner-capacity-input
cargo run -p hivemind-server -- schema miner-capacity-signal
cargo run -p hivemind-server -- schema marketplace-shortlist-request
cargo run -p hivemind-server -- schema marketplace-listing-verification
cargo run -p hivemind-server -- schema marketplace-listing-v2
cargo run -p hivemind-server -- schema marketplace-listing-v2-verification
cargo run -p hivemind-server -- schema runner-offer-score
cargo run -p hivemind-server -- schema marketplace-shortlist
cargo run -p hivemind-server -- schema service-quote
cargo run -p hivemind-server -- schema service-quote-timing
cargo run -p hivemind-server -- schema service-quote-verification
cargo run -p hivemind-server -- schema payment-authorization
cargo run -p hivemind-server -- schema payment-authorization-verification
cargo run -p hivemind-server -- schema payment-authorization-store-summary
cargo run -p hivemind-server -- schema payment-authorization-lookup
cargo run -p hivemind-server -- schema escrow-record
cargo run -p hivemind-server -- schema escrow-record-verification
cargo run -p hivemind-server -- schema escrow-release-request
cargo run -p hivemind-server -- schema escrow-release-result
cargo run -p hivemind-server -- schema escrow-record-store-summary
cargo run -p hivemind-server -- schema escrow-record-lookup
cargo run -p hivemind-server -- schema settlement-verification
cargo run -p hivemind-server -- schema settlement-event-verification
cargo run -p hivemind-server -- schema settlement-build-result
cargo run -p hivemind-server -- schema settlement-resolution
cargo run -p hivemind-server -- schema settlement-resolution-verification
cargo run -p hivemind-server -- schema settlement-resolution-result
cargo run -p hivemind-server -- schema refund-build-request
cargo run -p hivemind-server -- schema refund-record
cargo run -p hivemind-server -- schema refund-record-verification
cargo run -p hivemind-server -- schema refund-build-result
cargo run -p hivemind-server -- schema refund-record-store-summary
cargo run -p hivemind-server -- schema refund-record-lookup
cargo run -p hivemind-server -- schema marketplace-audit-summary
cargo run -p hivemind-server -- schema settlement-event-lookup
cargo run -p hivemind-server -- schema settlement-resolution-lookup
cargo run -p hivemind-server -- schema slashing-build-request
cargo run -p hivemind-server -- schema slashing-record
cargo run -p hivemind-server -- schema slashing-record-verification
cargo run -p hivemind-server -- schema slashing-build-result
cargo run -p hivemind-server -- schema validation-report
cargo run -p hivemind-server -- schema validation-report-v2
cargo run -p hivemind-server -- schema validation-method
cargo run -p hivemind-server -- schema validation-method-descriptor
cargo run -p hivemind-server -- schema validation-method-registry
cargo run -p hivemind-server -- schema validation-report-verification
cargo run -p hivemind-server -- schema validation-report-store-summary
cargo run -p hivemind-server -- schema validation-report-lookup
cargo run -p hivemind-server -- schema validation-report-upload
cargo run -p hivemind-server -- schema validation-report-download
cargo run -p hivemind-server -- schema integrity-evidence
cargo run -p hivemind-server -- schema integrity-evidence-init-options
cargo run -p hivemind-server -- schema integrity-evidence-verification
cargo run -p hivemind-server -- schema integrity-evidence-store-summary
cargo run -p hivemind-server -- schema integrity-evidence-lookup
cargo run -p hivemind-server -- schema reputation-profile-v2
cargo run -p hivemind-server -- schema benchmark-split
cargo run -p hivemind-server -- schema benchmark-privacy-rules
cargo run -p hivemind-server -- schema benchmark-expected-runtime
cargo run -p hivemind-server -- schema benchmark-suite-init-options
cargo run -p hivemind-server -- schema benchmark-suite
cargo run -p hivemind-server -- schema benchmark-suite-verification
cargo run -p hivemind-server -- schema benchmark-pack-context
cargo run -p hivemind-server -- schema benchmark-pack-projection-request
cargo run -p hivemind-server -- schema benchmark-pack
cargo run -p hivemind-server -- schema benchmark-pack-verification
cargo run -p hivemind-server -- schema benchmark-pack-projection
cargo run -p hivemind-server -- schema benchmark-suite-store-summary
cargo run -p hivemind-server -- schema benchmark-suite-lookup
cargo run -p hivemind-server -- schema challenge-commitment-init-options
cargo run -p hivemind-server -- schema challenge-commitment
cargo run -p hivemind-server -- schema challenge-commitment-verification
cargo run -p hivemind-server -- schema challenge-commitment-store-summary
cargo run -p hivemind-server -- schema challenge-commitment-lookup
cargo run -p hivemind-server -- schema evaluation-result
cargo run -p hivemind-server -- schema evaluation-result-verification
cargo run -p hivemind-server -- schema evaluation-result-store-summary
cargo run -p hivemind-server -- schema evaluation-result-lookup
cargo run -p hivemind-server -- schema evaluation-cost-v2
cargo run -p hivemind-server -- schema evaluation-timing-v2
cargo run -p hivemind-server -- schema evaluation-environment-v2
cargo run -p hivemind-server -- schema evaluation-error-v2
cargo run -p hivemind-server -- schema evaluation-result-v2-context
cargo run -p hivemind-server -- schema evaluation-result-v2-projection-request
cargo run -p hivemind-server -- schema evaluation-result-v2
cargo run -p hivemind-server -- schema evaluation-result-v2-verification
cargo run -p hivemind-server -- schema evaluation-result-v2-store-summary
cargo run -p hivemind-server -- schema evaluation-result-v2-lookup
cargo run -p hivemind-server -- schema evaluation-leaderboard-entry
cargo run -p hivemind-server -- schema evaluation-leaderboard
cargo run -p hivemind-server -- schema eval-manifest
cargo run -p hivemind-server -- schema eval-manifest-init-options
cargo run -p hivemind-server -- schema eval-manifest-verification
cargo run -p hivemind-server -- schema eval-run
cargo run -p hivemind-server -- schema eval-run-init-options
cargo run -p hivemind-server -- schema eval-run-verification
cargo run -p hivemind-server -- schema eval-run-planning-request
cargo run -p hivemind-server -- schema eval-run-plan
cargo run -p hivemind-server -- schema eval-record-store-summary
cargo run -p hivemind-server -- schema eval-record-lookup
cargo run -p hivemind-server -- schema research-experiment
cargo run -p hivemind-server -- schema research-experiment-init-options
cargo run -p hivemind-server -- schema research-experiment-verification
cargo run -p hivemind-server -- schema research-experiment-store-summary
cargo run -p hivemind-server -- schema research-experiment-lookup
cargo run -p hivemind-server -- schema research-reproduction-plan
cargo run -p hivemind-server -- schema research-experiment-run
cargo run -p hivemind-server -- schema research-experiment-run-init-options
cargo run -p hivemind-server -- schema research-experiment-run-verification
cargo run -p hivemind-server -- schema research-experiment-run-store-summary
cargo run -p hivemind-server -- schema research-experiment-run-lookup
cargo run -p hivemind-server -- schema research-artifact-ref
cargo run -p hivemind-server -- schema evaluation-run-v2
cargo run -p hivemind-server -- schema evaluation-run-v2-init-options
cargo run -p hivemind-server -- schema evaluation-run-v2-verification
cargo run -p hivemind-server -- schema research-result-record
cargo run -p hivemind-server -- schema research-result-record-init-options
cargo run -p hivemind-server -- schema research-result-record-verification
cargo run -p hivemind-server -- schema reproducibility-bundle
cargo run -p hivemind-server -- schema reproducibility-bundle-init-options
cargo run -p hivemind-server -- schema reproducibility-bundle-verification
cargo run -p hivemind-server -- schema vector-store
cargo run -p hivemind-server -- schema vector-store-init-options
cargo run -p hivemind-server -- schema vector-store-verification
cargo run -p hivemind-server -- schema vector-store-manifest-store-summary
cargo run -p hivemind-server -- schema vector-store-manifest-lookup
cargo run -p hivemind-server -- schema document-collection
cargo run -p hivemind-server -- schema chunk-set
cargo run -p hivemind-server -- schema embedding-set
cargo run -p hivemind-server -- schema vector-index-v2
cargo run -p hivemind-server -- schema retrieval-query
cargo run -p hivemind-server -- schema retrieval-planning-request
cargo run -p hivemind-server -- schema retrieval-plan
cargo run -p hivemind-server -- schema rag-pipeline-v2
cargo run -p hivemind-server -- schema citation-trace
cargo run -p hivemind-server -- schema knowledge-asset-verification
cargo run -p hivemind-server -- schema vector-search-request
cargo run -p hivemind-server -- schema vector-search-planning-request
cargo run -p hivemind-server -- schema vector-search-plan
cargo run -p hivemind-server -- schema tool-manifest
cargo run -p hivemind-server -- schema tool-manifest-init-options
cargo run -p hivemind-server -- schema tool-manifest-verification
cargo run -p hivemind-server -- schema workflow-manifest
cargo run -p hivemind-server -- schema workflow-manifest-init-options
cargo run -p hivemind-server -- schema workflow-manifest-verification
cargo run -p hivemind-server -- schema workflow-plan-request
cargo run -p hivemind-server -- schema workflow-plan
cargo run -p hivemind-server -- schema workflow-record-store-summary
cargo run -p hivemind-server -- schema workflow-record-lookup
cargo run -p hivemind-server -- schema batch-job
cargo run -p hivemind-server -- schema batch-job-init-options
cargo run -p hivemind-server -- schema batch-job-verification
cargo run -p hivemind-server -- schema batch-execution-plan
cargo run -p hivemind-server -- schema batch-job-store-summary
cargo run -p hivemind-server -- schema batch-job-lookup
cargo run -p hivemind-server -- schema fine-tune-job
cargo run -p hivemind-server -- schema fine-tune-job-init-options
cargo run -p hivemind-server -- schema fine-tune-job-verification
cargo run -p hivemind-server -- schema fine-tune-execution-plan
cargo run -p hivemind-server -- schema fine-tune-job-store-summary
cargo run -p hivemind-server -- schema fine-tune-job-lookup
cargo run -p hivemind-server -- schema realtime-session
cargo run -p hivemind-server -- schema realtime-session-init-options
cargo run -p hivemind-server -- schema realtime-session-verification
cargo run -p hivemind-server -- schema realtime-connection-plan
cargo run -p hivemind-server -- schema realtime-session-store-summary
cargo run -p hivemind-server -- schema realtime-session-lookup
cargo run -p hivemind-server -- schema moderation-policy
cargo run -p hivemind-server -- schema moderation-policy-init-options
cargo run -p hivemind-server -- schema moderation-policy-verification
cargo run -p hivemind-server -- schema moderation-request
cargo run -p hivemind-server -- schema moderation-request-init-options
cargo run -p hivemind-server -- schema moderation-request-verification
cargo run -p hivemind-server -- schema moderation-plan-request
cargo run -p hivemind-server -- schema moderation-plan
cargo run -p hivemind-server -- schema moderation-record-store-summary
cargo run -p hivemind-server -- schema moderation-record-lookup
cargo run -p hivemind-server -- schema governance-policy
cargo run -p hivemind-server -- schema governance-policy-init-options
cargo run -p hivemind-server -- schema governance-policy-verification
cargo run -p hivemind-server -- schema schema-release
cargo run -p hivemind-server -- schema schema-release-init-options
cargo run -p hivemind-server -- schema schema-release-verification
cargo run -p hivemind-server -- schema security-advisory
cargo run -p hivemind-server -- schema security-advisory-init-options
cargo run -p hivemind-server -- schema security-advisory-verification
cargo run -p hivemind-server -- schema security-response-plan
cargo run -p hivemind-server -- schema component-readiness
cargo run -p hivemind-server -- schema component-readiness-init-options
cargo run -p hivemind-server -- schema component-readiness-verification
cargo run -p hivemind-server -- schema governance-store-summary
cargo run -p hivemind-server -- schema governance-record-lookup
cargo run -p hivemind-server -- schema compatibility-report
cargo run -p hivemind-server -- schema compatibility-certification
cargo run -p hivemind-server -- schema compatibility-certification-index-entry
cargo run -p hivemind-server -- schema compatibility-certification-store-summary
cargo run -p hivemind-server -- schema compatibility-certification-lookup
cargo run -p hivemind-server -- schema compatibility-certification-write-result
cargo run -p hivemind-server -- schema receipt-verification
cargo run -p hivemind-server -- schema receipt-lookup
cargo run -p hivemind-server -- schema receipt-audit-summary
cargo run -p hivemind-server -- schema receipt-upload
cargo run -p hivemind-server -- schema receipt-download
cargo run -p hivemind-server -- schema receipt-redaction-policy
cargo run -p hivemind-server -- schema receipt-redaction
cargo run -p hivemind-server -- schema receipt-redaction-verification
cargo run -p hivemind-server -- schema execution-receipt-v2
cargo run -p hivemind-server -- schema execution-receipt-v2-verification-request
cargo run -p hivemind-server -- schema execution-receipt-v2-verification
cargo run -p hivemind-server -- schema receipt-v2
cargo run -p hivemind-server -- schema receipt-v2-verification-request
cargo run -p hivemind-server -- schema receipt-v2-verification
cargo run -p hivemind-server -- schema receipt-correctness-assessment-request
cargo run -p hivemind-server -- schema receipt-correctness-assessment
cargo run -p hivemind-server -- schema batch-receipt
cargo run -p hivemind-server -- schema batch-receipt-verification
cargo run -p hivemind-server -- schema batch-receipt-store-summary
cargo run -p hivemind-server -- schema batch-receipt-audit-summary
cargo run -p hivemind-server -- schema batch-receipt-lookup
cargo run -p hivemind-server -- schema partial-receipt
cargo run -p hivemind-server -- schema partial-receipt-verification
cargo run -p hivemind-server -- schema partial-receipt-stream-summary
cargo run -p hivemind-server -- schema receipt-dispute-evidence
cargo run -p hivemind-server -- schema receipt-dispute-verification
cargo run -p hivemind-server -- schema receipt-dispute-store-summary
cargo run -p hivemind-server -- schema receipt-dispute-lookup
cargo run -p hivemind-server -- schema browser-capabilities
cargo run -p hivemind-server -- schema browser-assessment
cargo run -p hivemind-server -- schema browser-swarm-status
cargo run -p hivemind-server -- schema browser-swarm-compatibility
cargo run -p hivemind-server -- schema remote-health
cargo run -p hivemind-server -- schema local-runner-cache
cargo run -p hivemind-server -- schema local-runner-cache-clear
cargo run -p hivemind-server -- schema local-runner-sensitive-cache-marker
cargo run -p hivemind-server -- schema runner-capability
cargo run -p hivemind-server -- schema runner-capability-v2
cargo run -p hivemind-server -- schema job-order
cargo run -p hivemind-server -- schema job-record
cargo run -p hivemind-server -- schema job-store-summary
cargo run -p hivemind-server -- schema job-lookup
cargo run -p hivemind-server -- schema job-cancellation-request
cargo run -p hivemind-server -- schema job-cancellation-result
cargo run -p hivemind-server -- schema job-expiration-sweep-request
cargo run -p hivemind-server -- schema job-expiration-sweep-result
cargo run -p hivemind-server -- schema job-store-audit-request
cargo run -p hivemind-server -- schema job-store-audit-summary
cargo run -p hivemind-server -- schema job-evidence-link-request
cargo run -p hivemind-server -- schema job-evidence-link-result
cargo run -p hivemind-server -- schema job-lifecycle-event
cargo run -p hivemind-server -- schema job-lifecycle-timeline
cargo run -p hivemind-server -- schema job-production-lifecycle
cargo run -p hivemind-server -- schema job-production-lifecycle-store-summary
cargo run -p hivemind-server -- schema job-quote
cargo run -p hivemind-server -- schema execution-lease-request
cargo run -p hivemind-server -- schema execution-lease
cargo run -p hivemind-server -- schema streaming-event
cargo run -p hivemind-server -- schema stream-event-store
cargo run -p hivemind-server -- schema runner-reputation-summary
cargo run -p hivemind-server -- schema route-planner-request
cargo run -p hivemind-server -- schema route-planner-report
cargo run -p hivemind-server -- schema route-planner-timing
cargo run -p hivemind-server -- schema route-execution-trace
cargo run -p hivemind-server -- schema route-trace-store-summary
cargo run -p hivemind-server -- schema route-decision-record
cargo run -p hivemind-server -- schema route-decision-proof-verification
cargo run -p hivemind-server -- schema operational-snapshot-request
cargo run -p hivemind-server -- schema operational-snapshot
cargo run -p hivemind-server -- schema operational-snapshot-verification
cargo run -p hivemind-server -- schema operational-snapshot-store-summary
cargo run -p hivemind-server -- schema openai-chat-completion-request
cargo run -p hivemind-server -- schema openai-chat-completion-response
cargo run -p hivemind-server -- schema openai-chat-completion-stream-event
cargo run -p hivemind-server -- schema openai-responses-request
cargo run -p hivemind-server -- schema openai-responses-response
cargo run -p hivemind-server -- schema openai-responses-stream-event
cargo run -p hivemind-server -- schema anthropic-message-request
cargo run -p hivemind-server -- schema anthropic-message-response
cargo run -p hivemind-server -- schema gemini-generate-content-request
cargo run -p hivemind-server -- schema gemini-generate-content-response
cargo run -p hivemind-server -- schema gemini-live-session-create-request
cargo run -p hivemind-server -- schema gemini-live-session
cargo run -p hivemind-server -- schema huggingface-inference-request
cargo run -p hivemind-server -- schema huggingface-inference-response
cargo run -p hivemind-server -- schema openai-file-create-request
cargo run -p hivemind-server -- schema openai-file
cargo run -p hivemind-server -- schema openai-vector-store-create-request
cargo run -p hivemind-server -- schema openai-vector-store
cargo run -p hivemind-server -- schema openai-vector-store-search-request
cargo run -p hivemind-server -- schema openai-vector-store-search-response
cargo run -p hivemind-server -- schema openai-batch-create-request
cargo run -p hivemind-server -- schema openai-batch
cargo run -p hivemind-server -- schema openai-fine-tuning-create-request
cargo run -p hivemind-server -- schema openai-fine-tuning-job
cargo run -p hivemind-server -- schema openai-realtime-session-create-request
cargo run -p hivemind-server -- schema openai-realtime-session
cargo run -p hivemind-server -- schema openai-eval-create-request
cargo run -p hivemind-server -- schema openai-eval
cargo run -p hivemind-server -- schema openai-eval-run-create-request
cargo run -p hivemind-server -- schema openai-eval-run
cargo run -p hivemind-server -- schema media-job
cargo run -p hivemind-server -- schema media-job-init-options
cargo run -p hivemind-server -- schema media-job-verification
cargo run -p hivemind-server -- schema media-execution-plan
cargo run -p hivemind-server -- schema media-job-store-summary
cargo run -p hivemind-server -- schema media-job-lookup
cargo run -p hivemind-server -- schema openai-image-generation-request
cargo run -p hivemind-server -- schema openai-image-edit-request
cargo run -p hivemind-server -- schema openai-image-generation-response
cargo run -p hivemind-server -- schema openai-audio-transcription-request
cargo run -p hivemind-server -- schema openai-audio-transcription-response
cargo run -p hivemind-server -- schema openai-audio-speech-request
cargo run -p hivemind-server -- schema openai-audio-speech-response
cargo run -p hivemind-server -- schema openai-model
cargo run -p hivemind-server -- schema openai-model-list
cargo run -p hivemind-server -- schema openai-embedding-response
cargo run -p hivemind-server -- schema openai-moderation-request
cargo run -p hivemind-server -- schema openai-moderation-response
cargo run -p hivemind-server -- schema publication-record
cargo run -p hivemind-server -- schema publication-record-store-summary
cargo run -p hivemind-server -- schema publication-record-lookup
cargo run -p hivemind-server -- schema publication-verification
cargo run -p hivemind-server -- schema feed-pointer-store-summary
cargo run -p hivemind-server -- schema feed-pointer-lookup
cargo run -p hivemind-server -- schema feed-verification
cargo run -p hivemind-server -- schema feed-resolution
wasm-pack build .\crates\web --target web --out-dir static\pkg --dev
cargo run -p hivemind-server -- serve --port 8787
```

The server exposes:

- `GET /health`
- `POST /v1/packages/validate`
- `POST /v1/packages/project-v2`
- `POST /v1/packages/project-v3`
- `POST /v1/packages/project-v4`
- `POST /v1/ai/workload`
- `POST /v1/ai/task-envelope`
- `POST /v1/access/verify-grant`
- `POST /v1/access/sign-grant-v2`
- `POST /v1/access/verify-grant-v2`
- `POST /v1/access/sign-grant-v3`
- `POST /v1/access/verify-grant-v3`
- `POST /v1/access/policy/project`
- `POST /v1/access/policy/verify`
- `POST /v1/access/policy/project-v2`
- `POST /v1/access/policy/verify-v2`
- `POST /v1/access/request-paid-access`
- `POST /v1/access/attach-grant-to-job`
- `GET /v1/access/grants`
- `GET /v1/access/grants/{grantId}`
- `POST /v1/access/revoke-grant`
- `GET /v1/access/revocations`
- `GET /v1/access/revocations/{revocationId}`
- `POST /v1/access/verify-revocation`
- `POST /v1/access/verify-revocation-list`
- `POST /v1/registry/search`
- `POST /v1/registry/package`
- `GET /v1/registry/packages/{packageId}`
- `GET /v1/registry/snapshot`
- `GET /v1/registry/snapshot/verification`
- `POST /v1/registry/snapshot/verify`
- `GET /v1/registry/shards`
- `GET /v1/registry/shards/manifest`
- `POST /v1/registry/shards/manifest/compare`
- `POST /v1/registry/shards/verify`
- `POST /v1/registry/shards/manifest/verify`
- `GET /v1/storage/status`
- `GET /v1/storage/providers/v3`
- `GET /v1/storage/providers/v4`
- `GET /v1/storage/cache`
- `POST /v1/storage/inspect`
- `POST /v1/storage/pin`
- `POST /v1/storage/unpin`
- `POST /v1/storage/feed/create`
- `POST /v1/storage/feed/update`
- `POST /v1/storage/feed/resolve`
- `GET /v1/browser-storage/providers`
- `GET /v1/browser-storage/providers/v4`
- `POST /v1/browser-storage/consent/verify`
- `POST /v1/browser-storage/session/verify`
- `POST /v1/browser-storage/receipt/verify`
- `POST /v1/browser-storage/sponsorship/verify`
- `POST /v1/browser-storage/security/assess`
- `POST /v1/browser-storage/security/verify`
- `GET /v1/policy/catalog`
- `POST /v1/policy/inspect`
- `POST /v1/policy/inspect-v2`
- `GET /v1/policy/privacy/tiers`
- `POST /v1/policy/privacy/assess`
- `GET /v1/receipts`
- `GET /v1/receipts/audit`
- `GET /v1/receipts/batches`
- `GET /v1/receipts/batches/audit`
- `GET /v1/receipts/batches/{batchReceiptId}`
- `GET /v1/receipts/{receiptId}/v2`
- `GET /v1/receipts/{receiptId}`
- `GET /v1/receipts/{receiptId}/redacted`
- `POST /v1/receipts/verify`
- `POST /v1/receipts/verify-v2`
- `POST /v1/receipts/assess-correctness`
- `POST /v1/receipts/verify-batch`
- `POST /v1/receipts/verify-partial`
- `POST /v1/receipts/verify-redaction`
- `GET /v1/receipts/partials/{streamKey}`
- `POST /v1/receipts/upload`
- `POST /v1/receipts/download`
- `GET /v1/receipts/disputes`
- `GET /v1/receipts/disputes/{disputeId}`
- `POST /v1/receipts/dispute`
- `POST /v1/receipts/verify-dispute`
- `GET /v1/publisher/publications`
- `GET /v1/publisher/publications/{publicationId}`
- `POST /v1/publisher/verify`
- `GET /v1/publisher/feeds`
- `GET /v1/publisher/feeds/{packageId}/{channel}`
- `POST /v1/publisher/feed/update`
- `POST /v1/publisher/feed/resolve`
- `GET /v1/validator/methods`
- `GET /v1/validator/reports`
- `GET /v1/validator/integrity-evidence`
- `POST /v1/validator/integrity-evidence`
- `GET /v1/validator/integrity-evidence/{evidenceId}`
- `GET /v1/validator/reports/{reportId}`
- `GET /v1/validator/reports/{reportId}/v2`
- `POST /v1/validator/reputation`
- `POST /v1/validator/reputation/v2`
- `POST /v1/validator/verify-report`
- `POST /v1/validator/verify-integrity-evidence`
- `POST /v1/validator/upload-report`
- `POST /v1/validator/download-report`
- `GET /v1/benchmarks/evaluations`
- `GET /v1/benchmarks/evaluations-v2`
- `POST /v1/benchmarks/evaluations-v2/from-v1`
- `GET /v1/benchmarks/evaluations-v2/{evaluationId}`
- `GET /v1/benchmarks/evaluations/{evaluationId}/v2`
- `POST /v1/benchmarks/verify-evaluation-v2`
- `GET /v1/benchmarks/leaderboard`
- `GET /v1/research/leaderboard`
- `GET /v1/research/evaluations-v2`
- `POST /v1/research/evaluations-v2/from-v1`
- `GET /v1/research/evaluations-v2/{evaluationId}`
- `POST /v1/research/verify-evaluation-v2`
- `GET /v1/benchmarks/suites`
- `POST /v1/benchmarks/suites`
- `GET /v1/benchmarks/suites/{suiteId}`
- `POST /v1/benchmarks/verify-suite`
- `POST /v1/benchmarks/packs/from-suite`
- `POST /v1/benchmarks/verify-pack`
- `GET /v1/research/benchmark-suites`
- `POST /v1/research/benchmark-suites`
- `GET /v1/research/benchmark-suites/{suiteId}`
- `POST /v1/research/verify-benchmark-suite`
- `POST /v1/research/benchmark-packs/from-suite`
- `POST /v1/research/verify-benchmark-pack`
- `GET /v1/benchmarks/challenge-commitments`
- `POST /v1/benchmarks/challenge-commitments`
- `GET /v1/benchmarks/challenge-commitments/{commitmentId}`
- `POST /v1/benchmarks/verify-challenge-commitment`
- `GET /v1/research/challenge-commitments`
- `POST /v1/research/challenge-commitments`
- `GET /v1/research/challenge-commitments/{commitmentId}`
- `POST /v1/research/verify-challenge-commitment`
- `GET /v1/benchmarks/evaluations/{evaluationId}`
- `POST /v1/benchmarks/verify-evaluation`
- `POST /v1/evals/verify-manifest`
- `POST /v1/evals/verify-run`
- `POST /v1/evals/plan`
- `GET /v1/evals/records`
- `GET /v1/evals/records/{recordId}`
- `POST /v1/research/verify-experiment`
- `POST /v1/research/reproduce`
- `POST /v1/research/runs`
- `POST /v1/research/verify-run`
- `GET /v1/research/runs`
- `GET /v1/research/runs/{runId}`
- `POST /v1/research/verify-evaluation-run-v2`
- `POST /v1/research/verify-result-record`
- `POST /v1/research/reproducibility-bundles/from-experiment`
- `POST /v1/research/verify-reproducibility-bundle`
- `GET /v1/research/experiments`
- `GET /v1/research/experiments/{experimentId}`
- `POST /v1/vector/verify-store`
- `POST /v1/vector/verify-document-collection`
- `POST /v1/vector/verify-chunk-set`
- `POST /v1/vector/verify-embedding-set`
- `POST /v1/vector/verify-index-v2`
- `POST /v1/vector/retrieval-plan`
- `POST /v1/vector/verify-rag-pipeline-v2`
- `POST /v1/vector/verify-citation-trace`
- `POST /v1/vector/search-plan`
- `GET /v1/vector/stores`
- `GET /v1/vector/stores/{vectorStoreId}`
- `POST /v1/workflows/verify-tool`
- `POST /v1/workflows/verify-workflow`
- `POST /v1/workflows/plan`
- `GET /v1/workflows/records`
- `GET /v1/workflows/records/{recordId}`
- `POST /v1/batch/verify-job`
- `POST /v1/batch/plan`
- `GET /v1/batch/jobs`
- `GET /v1/batch/jobs/{batchId}`
- `POST /v1/fine-tune/verify-job`
- `POST /v1/fine-tune/plan`
- `GET /v1/fine-tune/jobs`
- `GET /v1/fine-tune/jobs/{fineTuneJobId}`
- `POST /v1/realtime/verify-session`
- `POST /v1/realtime/plan`
- `GET /v1/realtime/native-sessions`
- `GET /v1/realtime/native-sessions/{sessionId}`
- `POST /v1/media/verify-job`
- `POST /v1/media/plan`
- `GET /v1/media/jobs`
- `GET /v1/media/jobs/{mediaJobId}`
- `POST /v1/moderation/verify-policy`
- `POST /v1/moderation/verify-request`
- `POST /v1/moderation/plan`
- `GET /v1/moderation/records`
- `GET /v1/moderation/records/{recordId}`
- `POST /v1/governance/verify-policy`
- `POST /v1/governance/verify-schema-release`
- `POST /v1/governance/verify-advisory`
- `POST /v1/governance/verify-readiness`
- `POST /v1/governance/security-response-plan`
- `GET /v1/governance/records`
- `GET /v1/governance/records/{recordId}`
- `GET /v1/browser/capabilities`
- `POST /v1/browser/assess`
- `POST /v1/browser/execute`
- `GET /v1/remote/capabilities`
- `GET /v1/remote/health`
- `POST /v1/remote/prepare`
- `POST /v1/remote/execute`
- `POST /v1/remote/cancel`
- `GET /v1/browser-swarm/descriptor`
- `GET /v1/browser-swarm/status`
- `GET /v1/browser-swarm/compatibility`
- `POST /v1/browser-swarm/manifest`
- `POST /v1/browser-swarm/file`
- `GET /v1/compatibility/supported-schemas`
- `POST /v1/compatibility/certify-package`
- `POST /v1/compatibility/verify-certification`
- `GET /v1/compatibility/certifications`
- `GET /v1/compatibility/certifications/{certificationId}`
- `GET /v1/errors/catalog`
- `GET /v1/swarm-ai/capabilities`
- `GET /v1/swarm-ai/errors/catalog`
- `GET /v1/swarm-ai/compatibility/supported-schemas`
- `POST /v1/swarm-ai/compatibility/certify-package`
- `POST /v1/swarm-ai/compatibility/verify-certification`
- `GET /v1/swarm-ai/compatibility/certifications`
- `GET /v1/swarm-ai/compatibility/certifications/{certificationId}`
- `POST /v1/swarm-ai/route`
- `POST /v1/swarm-ai/route-report`
- `POST /v1/swarm-ai/execute`
- `POST /v1/swarm-ai/ai/plan`
- `POST /v1/swarm-ai/ai/workload`
- `POST /v1/swarm-ai/ai/task-envelope`
- `GET /v1/swarm-ai/storage/providers/v3`
- `GET /v1/swarm-ai/storage/providers/v4`
- `GET /v1/swarm-ai/browser-storage/providers`
- `GET /v1/swarm-ai/browser-storage/providers/v4`
- `POST /v1/swarm-ai/browser-storage/consent/verify`
- `POST /v1/swarm-ai/browser-storage/session/verify`
- `POST /v1/swarm-ai/browser-storage/receipt/verify`
- `POST /v1/swarm-ai/browser-storage/sponsorship/verify`
- `POST /v1/swarm-ai/access/sign-grant-v2`
- `POST /v1/swarm-ai/access/verify-grant-v2`
- `POST /v1/swarm-ai/ai/verify-request`
- `POST /v1/swarm-ai/ai/sign-request`
- `POST /v1/swarm-ai/ai/verify-response`
- `POST /v1/swarm-ai/ai/sign-response`
- `POST /v1/swarm-ai/ai`
- `GET /v1/swarm-ai/jobs`
- `GET /v1/swarm-ai/jobs/{jobId}`
- `GET /v1/swarm-ai/jobs/{jobId}/timeline`
- `GET /v1/swarm-ai/jobs/{jobId}/lifecycle`
- `POST /v1/swarm-ai/jobs/{jobId}/evidence`
- `POST /v1/swarm-ai/jobs/audit`
- `POST /v1/swarm-ai/jobs/lifecycle-audit`
- `POST /v1/swarm-ai/jobs/expire`
- `POST /v1/swarm-ai/jobs/quote`
- `POST /v1/swarm-ai/jobs/lease`
- `POST /v1/swarm-ai/jobs/{jobId}/cancel`
- `GET /v1/swarm-ai/jobs/{jobId}/stream` (`?format=sse` returns native `StreamingEventV1` SSE)
- `GET /v1/swarm-ai/jobs/{jobId}/partial-receipts`
- `GET /v1/swarm-ai/receipts`
- `GET /v1/swarm-ai/receipts/audit`
- `POST /v1/swarm-ai/receipts/verify-v2`
- `POST /v1/swarm-ai/receipts/assess-correctness`
- `GET /v1/swarm-ai/receipts/batches`
- `GET /v1/swarm-ai/receipts/batches/audit`
- `GET /v1/swarm-ai/receipts/batches/{batchReceiptId}`
- `GET /v1/swarm-ai/receipts/partials/{streamKey}`
- `GET /v1/swarm-ai/receipt/{receiptId}/v2`
- `GET /v1/swarm-ai/receipt/{receiptId}/redacted`
- `GET /v1/swarm-ai/receipt/{receiptId}`
- `GET /v1/swarm-ai/cache`
- `DELETE /v1/swarm-ai/cache/{packageRef}`
- `POST /v1/chat/completions`
- `POST /v1/responses`
- `POST /v1/anthropic/messages`
- `POST /v1/gemini/generateContent`
- `POST /v1/gemini/generateContent/{modelId}`
- `POST /v1/gemini/live/sessions`
- `GET /v1/gemini/live/sessions/{sessionId}`
- `POST /v1/huggingface/inference`
- `POST /v1/huggingface/inference/{modelId}`
- `POST /v1/files`
- `GET /v1/files/{fileId}`
- `POST /v1/batches`
- `GET /v1/batches/{batchId}`
- `POST /v1/fine_tuning/jobs`
- `GET /v1/fine_tuning/jobs/{fineTuneJobId}`
- `POST /v1/realtime/sessions`
- `GET /v1/realtime/sessions/{sessionId}`
- `POST /v1/evals`
- `GET /v1/evals/{evalId}`
- `POST /v1/evals/{evalId}/runs`
- `GET /v1/evals/{evalId}/runs/{evalRunId}`
- `POST /v1/images/generations`
- `POST /v1/images/edits`
- `POST /v1/audio/transcriptions`
- `POST /v1/audio/speech`
- `POST /v1/vector_stores`
- `GET /v1/vector_stores/{vectorStoreId}`
- `POST /v1/vector_stores/{vectorStoreId}/search`
- `GET /v1/models`
- `GET /v1/models/{modelId}`
- `POST /v1/embeddings`
- `POST /v1/moderations`
- `GET /v1/hivemind/packages`
- `POST /v1/hivemind/resolve`
- `GET /v1/hivemind/errors/catalog`
- `GET /v1/hivemind/compatibility/supported-schemas`
- `POST /v1/hivemind/compatibility/certify-package`
- `POST /v1/hivemind/compatibility/verify-certification`
- `GET /v1/hivemind/compatibility/certifications`
- `GET /v1/hivemind/compatibility/certifications/{certificationId}`
- `POST /v1/hivemind/ai/plan`
- `POST /v1/hivemind/ai/workload`
- `POST /v1/hivemind/ai/task-envelope`
- `GET /v1/hivemind/storage/providers/v3`
- `GET /v1/hivemind/storage/providers/v4`
- `GET /v1/hivemind/browser-storage/providers`
- `GET /v1/hivemind/browser-storage/providers/v4`
- `POST /v1/hivemind/browser-storage/consent/verify`
- `POST /v1/hivemind/browser-storage/session/verify`
- `POST /v1/hivemind/browser-storage/receipt/verify`
- `POST /v1/hivemind/browser-storage/sponsorship/verify`
- `POST /v1/hivemind/access/sign-grant-v2`
- `POST /v1/hivemind/access/verify-grant-v2`
- `POST /v1/hivemind/ai/verify-request`
- `POST /v1/hivemind/ai/sign-request`
- `POST /v1/hivemind/ai/verify-response`
- `POST /v1/hivemind/ai/sign-response`
- `POST /v1/hivemind/ai`
- `POST /v1/hivemind/policy/evaluate`
- `GET /v1/hivemind/runners`
- `GET /v1/hivemind/runners/v2`
- `GET /v1/hivemind/jobs`
- `POST /v1/hivemind/jobs`
- `GET /v1/hivemind/jobs/{jobId}`
- `GET /v1/hivemind/jobs/{jobId}/timeline`
- `GET /v1/hivemind/jobs/{jobId}/lifecycle`
- `POST /v1/hivemind/jobs/{jobId}/evidence`
- `POST /v1/hivemind/jobs/audit`
- `POST /v1/hivemind/jobs/lifecycle-audit`
- `POST /v1/hivemind/jobs/expire`
- `POST /v1/hivemind/jobs/{jobId}/quotes`
- `POST /v1/hivemind/leases`
- `POST /v1/hivemind/jobs/{jobId}/cancel`
- `GET /v1/hivemind/jobs/{jobId}/stream` (`?format=sse` returns native `StreamingEventV1` SSE)
- `GET /v1/hivemind/jobs/{jobId}/partial-receipts`
- `GET /v1/hivemind/receipts`
- `GET /v1/hivemind/receipts/audit`
- `GET /v1/hivemind/receipts/batches`
- `GET /v1/hivemind/receipts/batches/audit`
- `GET /v1/hivemind/receipts/batches/{batchReceiptId}`
- `GET /v1/hivemind/receipts/partials/{streamKey}`
- `GET /v1/hivemind/receipts/{receiptId}/v2`
- `GET /v1/hivemind/receipts/{receiptId}/redacted`
- `GET /v1/hivemind/receipts/{receiptId}`
- `POST /v1/hivemind/receipts/verify-v2`
- `POST /v1/hivemind/receipts/assess-correctness`
- `GET /v1/observability/snapshot`
- `GET /v1/hivemind/observability/snapshot`
- `GET /v1/hivemind/validations/{reportId}`
- `GET /v1/hivemind/validator/methods`
- `GET /v1/hivemind/validations/{reportId}/v2`
- `GET /v1/hivemind/integrity-evidence`
- `POST /v1/hivemind/integrity-evidence`
- `GET /v1/hivemind/integrity-evidence/{evidenceId}`
- `POST /v1/hivemind/verify-integrity-evidence`
- `GET /v1/hivemind/marketplace/listings`
- `GET /v1/hivemind/marketplace/listings/v2`
- `GET /v1/marketplace/listings`
- `GET /v1/marketplace/listings/v2`
- `POST /v1/marketplace/listing/project-v2`
- `POST /v1/marketplace/verify-listing`
- `POST /v1/marketplace/verify-listing-v2`
- `GET /v1/marketplace/offers`
- `GET /v1/marketplace/hardware-offers`
- `POST /v1/marketplace/shortlist`
- `POST /v1/marketplace/verify-offer`
- `POST /v1/marketplace/verify-hardware-offer`
- `POST /v1/miner/verify-profile`
- `POST /v1/miner/verify-heartbeat`
- `POST /v1/miner/verify-benchmark`
- `POST /v1/miner/onboarding-plan`
- `POST /v1/miner/dashboard`
- `GET /v1/miner/records`
- `GET /v1/miner/records/{recordId}`
- `POST /v1/marketplace/quote`
- `POST /v1/marketplace/verify-quote`
- `POST /v1/marketplace/authorize-payment`
- `POST /v1/marketplace/verify-payment`
- `GET /v1/marketplace/payments`
- `GET /v1/marketplace/payments/{authorizationId}`
- `POST /v1/marketplace/create-escrow`
- `POST /v1/marketplace/verify-escrow`
- `POST /v1/marketplace/release-escrow`
- `GET /v1/marketplace/escrows`
- `GET /v1/marketplace/escrows/{escrowId}`
- `GET /v1/marketplace/audit`
- `GET /v1/marketplace/settlements/{settlementId}`
- `GET /v1/marketplace/resolutions/{resolutionId}`
- `POST /v1/marketplace/settle`
- `POST /v1/marketplace/verify-settlement`
- `POST /v1/marketplace/dispute-settlement`
- `POST /v1/marketplace/refund-settlement`
- `POST /v1/marketplace/reject-dispute`
- `POST /v1/marketplace/refund-record`
- `POST /v1/marketplace/verify-refund-record`
- `GET /v1/marketplace/refunds`
- `GET /v1/marketplace/refunds/{refundId}`
- `POST /v1/marketplace/slash`
- `POST /v1/marketplace/verify-slashing`
- `POST /v1/marketplace/verify-resolution`

## Local Publish Flow

`swarm-ai init` creates valid embedding or chat package scaffolds with `swarm-ai.json`, mock artifact files, computed artifact-group hashes, and an immediate validation report. `swarm-ai validate`, `swarm-ai validate-ref`, and `/v1/packages/validate` write compact package validation audit records under `.swarm-ai-cache/package-audit` with manifest hashes, source kind, validity, issue counts, parse timing when available, validation timing, and total elapsed time, so operational snapshots can cover manifest parse time without changing the shared `ValidationReport` response shape.

Publication and feed audit records are indexed for `publication-records`, `get-publication`, `feed-pointers`, `get-feed`, `/v1/publisher/publications`, `/v1/publisher/feeds`, and the Rust/WASM dashboard.

`swarm-ai publish` validates a package, uploads the package directory into `.swarm-ai-cache/storage`, writes a signed `PublicationRecordV1` into `.swarm-ai-cache/publications`, updates channel feed pointers under `.swarm-ai-cache/feeds`, and returns a local `bzz://local-dir-...` reference. The smaller `sign`, `verify-publication`, `update-feed`, `resolve-feed`, identity, cache, storage inspection, and Bee-backed storage commands expose the same publication lifecycle in independently testable pieces.

Registry search, package detail lookup, public snapshots, shard manifests, marketplace listings, marketplace shortlists, quotes, and public runner offers default to public output. Grant-aware search and package resolution can reveal private entries only when the signed grant, requester, requested use, runner scope, and optional revocation list authorize discovery. CLI and API registry searches write compact audit records under `.swarm-ai-cache/registry-audit` with query hashes, filter names, retrieval mode, result counts, and elapsed time, so operational snapshots can report registry search latency without storing raw queries or access grants. Local registry rebuilds combine packages, signed publication records, feed pointers, validation reports, marketplace listings, runner offers, hardware-resource offers, valid schema releases, valid component readiness records, policy summaries, and verified benchmark evidence into `examples/registry/index.json`, then split the catalog into mirrorable shard files. Package entries expose compact `runnerOfferRefs` and `hardwareResourceOfferRefs`, while snapshot-level `schemaReleases` and `componentReadiness` expose verified interface compatibility and implementation readiness for registry clients. Public snapshots remove private package records and scrub private package refs from stored offer evidence before exposure.

Execution flows are available as local-first contracts: `run-ref`, browser runs, remote runner simulations, route planning, OpenAI-compatible endpoints, provider-shaped compatibility endpoints, trust-policy presets, access grants, marketplace quote/payment/settlement/dispute records, job lifecycle records, stream events, receipt stores, redacted receipt views, batch/partial receipts, validation reports, integrity evidence, storage transfer audit records, reputation summaries, operational metric snapshots, miner profiles, miner heartbeats, and hardware-resource offers. These flows are designed for integration testing and protocol hardening; they are not yet live decentralized compute, production payment, or production sandbox infrastructure.

Benchmark and R&D flows include public validation challenges, the mini embedding benchmark, a task-specific validation method registry, signed `BenchmarkSuiteV1` suite definitions, signed `BenchmarkPackV1` projections, signed `EvaluationResultV1` records, production-oriented `EvaluationResultV2` projections, local evaluation stores, evidence-backed leaderboards, `EvalManifestV1` and `EvalRunV1` planning records, research experiment/run records, and vector/workflow/batch/fine-tune/realtime/media/moderation/governance planning contracts. The vector/RAG layer now exposes review-4 `DocumentCollectionManifestV1`, `ChunkSetManifestV1`, `EmbeddingSetManifestV1`, `VectorIndexManifestV2`, `RetrievalPlanV1`, `RagPipelineManifestV2`, and `CitationTraceV1` contracts so file-search and knowledge-base teams can verify exact document, chunk, embedding, index, retrieval, and citation refs without treating Swarm as a live vector database. `/v1/validator/methods` exposes the supported method menu with strength, task classes, subject types, evidence requirements, hidden-challenge compatibility, subjective-method disclosure, and privacy/integrity tier metadata. `BenchmarkSuiteV1` captures modalities, dataset refs, scoring refs, split definitions, allowed model/runtime selectors, privacy rules, expected runtime, and metric names for separate benchmark and R&D teams; `/v1/benchmarks/packs/from-suite` projects that suite into a `BenchmarkPackV1` with hidden challenge commitment refs, validation method refs, scoring function ref, allowed runtimes, privacy rules, and the expected validation-report schema. `EvaluationResultV2` preserves the source benchmark result while adding suite id, package ref, runner, validator, aggregate score, metrics, lifecycle timing, optional cost, environment metadata, artifact refs, result refs, random seeds, structured errors, timestamps, and local-dev or Ed25519 signatures; it can be created with `evaluation-v2-from-v1`, inspected through `evaluation-results-v2`, and served through `/v1/benchmarks/evaluations-v2` or `/v1/research/evaluations-v2`. `ChallengeCommitmentV1` adds a signed hidden-benchmark commitment object: validators can publish hashes of private challenge sets, answer sets, salts, and hidden dataset refs without leaking the private material, then expose those records through `challenge-commitments`, `/v1/benchmarks/challenge-commitments`, and `/v1/research/challenge-commitments`.

Review-4 research reproducibility contracts now include `EvaluationRunV2`, `ResearchResultRecordV1`, and `ReproducibilityBundleV1`. `EvaluationRunV2` links an experiment, eval, or benchmark to the target package, datasets, scoring refs, privacy/integrity tiers, evidence refs, seeds, artifacts, and signatures. `ResearchResultRecordV1` records signed positive, negative, inconclusive, benchmark, safety, regression, or reproduction outcomes with metrics and evidence refs. `ReproducibilityBundleV1` ties an experiment, embedded or referenced runs, evaluation runs, result records, receipts, validation reports, immutable refs, reproduction steps, privacy/integrity tiers, and licensed artifact refs into one auditable bundle; exact-reproduction bundles reject unresolved mutable refs and dataset/model/code artifacts without license refs.

`swarm-ai certify` runs the SDK compatibility suite against a package folder, including manifest validation, forward-compatible unknown fields, execution request/response round trips, receipt verification, mock storage loading, and artifact selection.

The same package certification path is exposed through `/v1/compatibility/certify-package`, `/v1/swarm-ai/compatibility/certify-package`, and `/v1/hivemind/compatibility/certify-package` for packages already indexed by the local registry. Supplying an identity object signs the resulting `CompatibilityCertificationV1`; adding `store: true` persists the signed evidence under `.swarm-ai-cache/compat`, returns a stable `local://compat/{certificationId}` reference, and makes the record available through `swarm-ai certifications list/get` and the `/v1/compatibility/certifications` API aliases. `/v1/compatibility/verify-certification` and its `swarm-ai`/`hivemind` aliases verify posted certification artifacts against an optional expected signer.

`PackageManifestV2`, `PackageManifestV3`, and `PackageManifestV4` are exposed as deterministic projections over stored `PackageManifestV1` manifests. `/v1/packages/project-v2` lets package and registry tooling inspect the v02 package shape without migrating the on-disk `swarm-ai.json` format yet. `/v1/packages/project-v3` adds the v0.3 generic-AI projection with `UniversalCapabilityV1`, `AssetDescriptorV1`, and optional `BrowserPublishProfileV1`. `/v1/packages/project-v4` adds the review-4 package contract with `hivemind.package_manifest.v4`, `packageKind`, v4 asset fields, `RuntimeDescriptorV2`, named input/output schemas, storage policy, safety policy, and provenance records so independent package, registry, browser-publishing, and runner teams can inspect a generic AI package without downloading large artifacts or changing the v1 disk format.

`AIRequestV1`, `TaskEnvelopeV1`, `AIWorkloadV1`, `AiInputPartV1`, `AiExecutionPlanV1`, `UniversalRoutePlanV1`, `AIResponseV1`, and `AiOutputPartV1` provide the general interface-object layer for separate compatibility and R&D teams. Core helpers now produce canonical request/response/workload/task-envelope ids, deterministic local-dev signatures, and verification reports for these objects; `/v1/swarm-ai/ai/verify-request`, `/v1/swarm-ai/ai/sign-request`, `/v1/swarm-ai/ai/verify-response`, `/v1/swarm-ai/ai/sign-response`, and the matching `/v1/hivemind/ai/*` aliases expose that preflight path to API clients. `/v1/ai/task-envelope`, `/v1/swarm-ai/ai/task-envelope`, and `/v1/hivemind/ai/task-envelope` project an `AIRequestV1` into the review-4 portable job object with requested API, universal capability summary, package reference, asset-or-inline inputs, expected outputs, job policy, privacy requirement, verification requirement, budget, runtime preferences, streaming contract, requester, and verification report. `/v1/ai/workload`, `/v1/swarm-ai/ai/workload`, and `/v1/hivemind/ai/workload` keep projecting the same request into the internal workload object used by current planning. The OpenAI and provider compatibility crates also project chat, Responses, embeddings, moderation, Anthropic Messages, Gemini Generate Content, Gemini Live, and Hugging Face-style requests into `AIRequestV1`, so adapters can preflight, sign, project to task envelope or workload, plan, or hand off the same native interface object before execution. `/v1/swarm-ai/ai/plan` and `/v1/hivemind/ai/plan` resolve an `AIRequestV1.packageSelector` and return the mapped execution request, job order, route candidates, quotes, miner-capacity signals, stored runner-offer shortlist evidence, readiness counters, and a `universalRoutePlan` that explains input upload/encryption, output publication, allowed and fallback storage providers, route-specific input/output delivery strategies, privacy and verification decisions, settlement requirements, fallback route chain, and user consent requirements without running the job. `/v1/swarm-ai/ai` and `/v1/hivemind/ai` map the same request into the trust-aware execution path used by native and OpenAI-compatible calls, then return `AIResponseV1` with outputs, usage, receipt refs, route trace refs, and underlying execution metadata.

`SwarmAiErrorV1` now carries a compatibility-preserving legacy `code` plus a v0.2 `standardCode` for the production failure taxonomy. `StandardErrorCatalogV1`, exposed through `schema standard-error-catalog`, `/v1/errors/catalog`, `/v1/swarm-ai/errors/catalog`, and `/v1/hivemind/errors/catalog`, gives independent runner, router, marketplace, storage, and API teams a shared machine-readable list of retryable, terminal, HTTP-mapped error conditions.

`ExecutionReceiptV2` is exposed as a richer projection over the existing stored `ExecutionReceiptV1` evidence. `/v1/receipts/{receiptId}/v2`, `/v1/swarm-ai/receipt/{receiptId}/v2`, and `/v1/hivemind/receipts/{receiptId}/v2` preserve the v1 receipt id and signature while adding job, lease, API surface, modality, timing, usage, cost, privacy, verification, route, policy, access, and error fields when that context is available from the local job store. `receipts verify-v2`, `/v1/receipts/verify-v2`, and `/v1/hivemind/receipts/verify-v2` structure-check the v2 projection and, when supplied with the source `ExecutionReceiptV1`, verify that the preserved signature and projected audit fields match the original receipt evidence. `ReceiptCorrectnessAssessmentV1`, exposed through `/v1/receipts/assess-correctness` and namespace aliases, checks whether a structurally valid receipt has enough linked validator evidence for its declared integrity tier, such as hidden challenges, redundant execution, deterministic replay, TEE attestation checks, or ZK proof checks, while keeping receipt-only audit explicitly separate from proof of output correctness. Receipt list responses from `/v1/receipts`, `/v1/swarm-ai/receipts`, and `/v1/hivemind/receipts` now enrich each index entry with job id, requester, lease id, quote id, settlement reference, settlement status, queue/load/compute/total timing, token counts, and output throughput when those values exist; receipt store summaries aggregate queue time, package load time, completion latency, and output tokens per second for operational snapshots. `swarm-ai receipts audit`, `/v1/receipts/audit`, and `/v1/hivemind/receipts/audit` project the same index into `ReceiptAuditSummaryV1` with verification health, privacy counts, settlement follow-ups, cost totals, and grouping by job, runner, requester, package ref, privacy mode, and settlement status. `BatchReceiptV1` records item-level batch outcomes with per-item status, input/output hashes, optional item receipt refs, aggregate metrics, privacy tier, verification mode, and local-dev or Ed25519 runner signatures; it can be checked with `receipts verify-batch` or `/v1/receipts/verify-batch`, and local batch receipt stores can be inspected with `receipts list-batches`, `receipts get-batch`, `/v1/receipts/batches`, and `/v1/hivemind/receipts/batches/{batchReceiptId}`. `receipts audit-batches`, `/v1/receipts/batches/audit`, and `/v1/hivemind/receipts/batches/audit` summarize batch receipt stores by runner, requester, package ref, privacy mode, item status totals, failed or cancelled batches, and mixed-outcome partial-settlement candidates. Streaming responses that have captured a final receipt now insert a `partial_receipt` event whose payload includes a signed `PartialReceiptV1`, so stream consumers can verify receipt availability without embedding raw prompts or outputs; `swarm-ai jobs partial-receipts`, `/v1/receipts/partials/{streamKey}`, `/v1/swarm-ai/jobs/{jobId}/partial-receipts`, and `/v1/hivemind/jobs/{jobId}/partial-receipts` summarize those persisted stream events into verified `PartialReceiptStreamSummaryV1` audit views. `swarm-ai receipts redact`, `/v1/receipts/{receiptId}/redacted`, and `/v1/hivemind/receipts/{receiptId}/redacted` produce signed `RedactedReceiptV1` views using `public-audit`, `settlement-audit`, or `internal-audit` policies; the redacted object records retained and withheld field paths, keeps input/output evidence hash-only, and can be checked with `receipts verify-redaction` or `/v1/receipts/verify-redaction`. When a stored job has an execution lease, the optional `leaseContext` block preserves the quote id, authorized input refs and hashes, authorized package refs, maximum cost, start window, deadline, and settlement reference used to issue the receipt.

`RunnerCapabilityV2` is exposed as a production-facing projection over `RunnerCapabilityV1`. `/v1/hivemind/runners/v2` preserves supported APIs, modalities, package kinds, engines, hardware, memory, streaming modes, privacy tiers, verification tiers, price tables, and cache claims while adding identity, public-key placeholder, tool-execution policy, latency hints, uptime, validator-score, terms, expiration, and signature fields for independent runner, router, marketplace, and miner teams.

`AccessPolicyV1` and `AccessPolicyV2` are exposed as canonical policy objects derived from `LicensePolicyV1`, with `LicensePolicyV2` available for manifest-derived asset rules. `/v1/access/policy/project` and `/v1/access/policy/project-v2` turn existing package license rules into package/service refs, license type, rights, payment requirements, privacy requirements, verification requirements, grant scope, revocation refs, expiration metadata, and optional local-dev signatures; `/v1/access/policy/verify` and `/v1/access/policy/verify-v2` check canonical policy ids and development signatures. `AssetAccessRuleV2` is now the review-5 target rule object, projected from existing asset rules with allowed grant scopes, policy/license/payment/revocation refs, encryption metadata, and explicit privacy and verification requirements. `PaidAccessQuoteV1` plus `AccessEvaluationResultV1` provide auditable quote/evaluation records for paid or denied access without pretending the local implementation is already a live payment rail. `/v1/access/request-paid-access` accepts a valid `MarketplaceListingV2`, derives or reads its access policy, and returns a canonical `PaidAccessQuoteV1` bound to the listing. `AccessGrantV2` adds asset-scoped permissions for generic AI workflows, and `AccessGrantV3` extends that grant with asset-rule snapshots, payment evidence refs, revocation hints, privacy tier, and settlement refs for payment-bound package, asset, dataset, tool, and service access. `/v1/access/sign-grant-v2`, `/v1/access/verify-grant-v2`, `/v1/access/sign-grant-v3`, and `/v1/access/verify-grant-v3`, with matching `swarm-ai` and `hivemind` aliases, check canonical ids, compatible scope/subject pairs, expiry, references, asset-rule consistency, and deterministic local-dev signatures. `/v1/access/attach-grant-to-job` returns `JobAccessAttachmentV1`, an auditable projection that verifies a grant is job-relevant, attaches its ref to `JobOrderV1`, carries payment and settlement refs, and re-canonicalizes the updated job order before routing or execution.

`swarm-ai policy trust local-only` and `swarm-ai policy trust open-marketplace` generate canonical `TrustPolicyV1` presets for route planning, native execution, dashboard-style local-only runs, and compatibility-endpoint metadata; `swarm-ai policy trust sign` adds a local-dev signature, `swarm-ai policy trust verify` checks a policy file's schema, canonical id, routing constraints, and signature status before use, and `swarm-ai policy trust list/get` expose the local trust-policy audit store. `/v1/policy/trust/local-only`, `/v1/policy/trust/open-marketplace`, `/v1/policy/trust/sign`, `/v1/policy/trust/verify`, `/v1/policy/trust`, and `/v1/policy/trust/{policyId}` expose the same trust-policy loop to API clients; generated or signed valid policies are persisted under `.swarm-ai-cache/trust` by default.

Review-4 security policy inspection is exposed through `PermissionManifestV2`, `RiskInspectionReportV1`, `ConsentRecordV1`, and `ToolPermissionGrantV1`. `swarm-ai policy inspect-v2`, `swarm-ai policy inspect-ref-v2`, and `/v1/policy/inspect-v2` project a package manifest into declared permissions, consent-required permissions, default-denied permissions, sandbox requirements, stable audit ids, and warnings for cases such as wallet access, local shell execution, or network permissions without an allowlist. This remains a local preflight and audit contract; production enforcement still belongs to browser, local, remote, and miner runners that can prove the required sandbox controls.

Review-4 privacy tier precision is exposed through `PrivacyTierCatalogV1` and `PrivacyRequirementAssessmentV1`. The shared `PrivacyTier` enum now accepts public, standard remote, no-log remote, local-only, browser-only, encrypted-storage, TEE-confidential, split-trust redundant, FHE encrypted inference, zk verified inference, and legacy compatibility names. `/v1/policy/privacy/tiers` returns the catalog with each tier's allowed execution locations, data-movement rule, evidence requirements, receipt guidance, and limitations; `/v1/policy/privacy/assess` checks whether an offered runner/storage/proof setup satisfies a requested tier before data movement or routing. No-log is explicitly marked as an operational promise rather than cryptographic privacy, and local-only/browser-only policies reject remote plaintext transfer.

Routing also consumes request-scoped stored runner offers from `.swarm-ai-cache/marketplace/offers`, standalone hardware-resource offers from `.swarm-ai-cache/marketplace/hardware-offers`, miner daemon capacity inputs, and summarized runner reputation evidence derived from valid validation reports. The router only sees compact `RunnerReputationSummaryV1` records, while `/v1/swarm-ai/route`, `/v1/swarm-ai/route-report`, `/v1/swarm-ai/execute`, `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, and `/v1/moderations` attach available route, marketplace, miner, and reputation summaries to response metadata.

Execution-backed JSON and SSE compatibility responses also expose audit context through `X-Hivemind-Request-Id`, `X-Hivemind-Job-Id`, `X-Hivemind-Receipt-Ref`, `X-Hivemind-Runner-Id`, `X-Hivemind-Route-Decision-Ref`, `X-Hivemind-Privacy-Mode`, and `X-Hivemind-Verification-Mode` headers when those values exist.

Server-backed native and compatibility executions persist `JobRecordV1` audit records under `.swarm-ai-cache/jobs` by default and expose the capture result as `jobStore` metadata. Job creation, quotes, leases, evidence links, audit summaries, expiration sweeps, cancellations, and completed routed executions update or inspect the same local job record, so `swarm-ai jobs list/get/timeline/lifecycle/lifecycle-audit/link-evidence/audit/expire/stream/partial-receipts/cancel`, `/v1/swarm-ai/jobs`, `/v1/swarm-ai/jobs/{jobId}`, `/v1/hivemind/jobs`, and `/v1/hivemind/jobs/{jobId}` can inspect lifecycle status, route, runner, receipt, and stream references from the same store. `/v1/swarm-ai/jobs/{jobId}/timeline`, `/v1/hivemind/jobs/{jobId}/timeline`, and `swarm-ai jobs timeline` project the record into `JobLifecycleTimelineV1`, an ordered view of created, quoted, leased, running, streamed, receipt-captured, validation-linked, dispute-opened, settled, succeeded, failed, partial, and cancelled phases with evidence refs and warnings for missing audit links. `/v1/swarm-ai/jobs/{jobId}/lifecycle`, `/v1/hivemind/jobs/{jobId}/lifecycle`, and `swarm-ai jobs lifecycle` project the same record into `JobProductionLifecycleV1`, a stage-coverage view of the production execution path from request intake through package resolution, policy, discovery, quotes, payment, lease, execution, streaming, receipt, validation, settlement, reputation, and stored evidence. `/v1/swarm-ai/jobs/lifecycle-audit`, `/v1/hivemind/jobs/lifecycle-audit`, and `swarm-ai jobs lifecycle-audit` aggregate those per-job lifecycle projections into `JobProductionLifecycleStoreSummaryV1` with stage-status counts, ready-for-settlement counts, operator-action counts, blocked jobs, and compact per-job blocked/pending stage lists. `JobStoreAuditRequestV1` and `JobStoreAuditSummaryV1` provide a read-only operator summary of status counts, receipt/stream/validation/dispute/settlement coverage, timeline warnings, and stale quote or lease candidates. `JobEvidenceLinkRequestV1` and `JobEvidenceLinkResultV1` let CLI and API callers attach validation reports, dispute evidence, settlement events, settlement resolutions, receipts, stream-event stores, and other external audit refs so those lifecycle phases become inspectable from the job timeline and production lifecycle view. `JobExpirationSweepRequestV1` and `JobExpirationSweepResultV1` add an explicit sweep that marks stale quoted or leased jobs as failed with `DeadlineExceeded` errors and quote or lease evidence. `JobCancellationRequestV1` and `JobCancellationResultV1` add an idempotent local cancellation transition for non-terminal jobs; successful API or CLI cancellation persists a native `cancelled` stream event keyed by job ID and request ID. Server-backed native and compatibility executions also persist embedded signed receipts under `.swarm-ai-cache/receipts` by default and expose the capture result as `receiptStore` metadata, so receipt lookup, settlement, dispute, and validation flows can inspect the same audit evidence produced by the runner. Successful executions requested with `stream: true` attach normalized native `StreamingEventV1` records under response metadata as `streamEvents`, with a compact `streamEventSummary` for request, job, event count, and event id boundaries; after receipt capture, the native stream is enriched with a `partial_receipt` event before `completed` so stream consumers can see receipt availability without polling the receipt store first. Those stream events are also persisted under `.swarm-ai-cache/streams` by default, keyed by job ID and request ID, expose the persistence result as `StreamEventStoreSummaryV1` metadata, can be read through `swarm-ai jobs stream`, summarized into verified partial receipt indexes with `swarm-ai jobs partial-receipts`, and projected into `StreamEventAuditSummaryV1` for time-to-first-output operational metrics.

`ExecutionLeaseV1` issuance now validates that the selected `JobQuoteV1` still matches the `JobOrderV1`: schema versions must be supported, job IDs and quote IDs must match canonical signed content, quote and job IDs must match, requester and settlement references must be present, quote expiration, optional `startAfter`, and lease deadlines must be ordered RFC3339 timestamps, quoted cost must respect any job `maxPrice`, and quoted privacy or verification modes must satisfy the job requirements before the lease is stored. Generated leases expose both local `allowedInputHashes` and interface-facing `allowedInputRefs` (`sha256://...`) alongside `allowedPackageRefs`, optional `startAfter`, deadline, cancellation rules, and settlement reference.

Hardware resource offers make the v0.2 AI miner marketplace explicit without turning Swarm/Bee into a compute layer. `RunnerOfferV1` now emits `hivemind.runner_offer.v1` records that preserve the legacy package, capability, pricing, service-level, and reputation fields while adding signed runner identity, public-key placeholder, supported APIs, modalities, package kinds, model formats, engines, hardware, memory, context, batch, streaming, price-table, cache-claim, privacy-tier, verification-tier, reputation-ref, terms-ref, and expiration fields for routing and quote comparison. `HardwareResourceOfferV1` emits `hivemind.hardware_resource_offer.v1` records for expiring GPU/CPU capacity, supported execution modes, APIs, modalities, price tables, cache claims, privacy tiers, verification tiers, trust tier, stake claim, benchmark refs, terms ref, and signatures; `marketplace offers --output-dir`, `marketplace shortlist --offers`, `marketplace quote --offers`, `route --marketplace-offers`, `route --marketplace-hardware-offers`, `marketplace hardware-offers --output-dir`, `registry rebuild`, `/v1/marketplace/offers`, `/v1/marketplace/hardware-offers`, `/v1/swarm-ai/route`, `/v1/swarm-ai/route-report`, `/v1/swarm-ai/execute`, and the verification commands expose the local development flow while still accepting legacy local `swarm-ai.runner-offer.v1` and `swarm-ai.hardware-resource-offer.v1` records. `hivemind-miner` adds the daemon/operator side of that flow: signed `MinerProfileV1` records derived from hardware offers, signed `MinerHeartbeatV1` load/status and available RAM/VRAM updates, signed `MinerBenchmarkResultV1` evidence, `MinerOnboardingPlanV1` eligibility checks for public versus sensitive jobs, and `MinerDashboardSummaryV1` records for local operator dashboards. Miner record summaries derive current memory and VRAM usage ratios from each miner's latest valid heartbeat and signed profile capacity for operational snapshots. `MinerCapacityInputV1` and `MinerCapacitySignalV1` let the router consume standalone hardware offers or miner records as route candidates with queue, trust, privacy, benchmark, RAM, VRAM, and rejection diagnostics; `swarm-ai miner`, `swarm-ai route --marketplace-offers`, `swarm-ai route --marketplace-hardware-offers`, `swarm-ai route --miner`, and `/v1/miner/*` expose those contracts before a live miner network exists.

Marketplace payment records now emit the v0.2 interface names used by the production execution writeups: `MarketplaceListingV1` uses `hivemind.marketplace_listing.v1` with concrete listing types such as `package_license`, `hosted_ai_service`, `gpu_capacity`, `dataset_license`, `benchmark_bounty`, and `research_grant`, plus signed evidence, validation-report, reputation, and compact detail refs. `MarketplaceListingV2` adds the review-4 separated listing contract for `package_license`, `package_subscription`, `hosted_inference`, `gpu_capacity`, `batch_capacity`, `confidential_runner`, `validator_service`, `dataset_license`, `vector_store_service`, `benchmark_bounty`, and `research_grant`; each v2 listing carries a typed subject, price model, access policy, service level, privacy tiers, verification tiers, settlement terms, dispute terms, evidence refs, expiration, source listing id, and local-dev or Ed25519 signature. `/v1/marketplace/listings/v2`, `/v1/hivemind/marketplace/listings/v2`, `/v1/marketplace/listing/project-v2`, and `/v1/marketplace/verify-listing-v2` expose the projection and verification path while v1 remains accepted. `MarketplaceShortlistRequestV1` now uses `hivemind.marketplace_shortlist_request.v1` with optional API surface, modality, required privacy tier, and required verification tier filters; `RunnerOfferScoreV1` uses `hivemind.runner_offer_score.v1` and reports selected privacy/verification modes, cache-hit claims, and a policy-fit score before route selection. `ServiceQuoteV1` uses `hivemind.quote.v1` with signed job, listing, price, price model, privacy, verification, latency, cache-claim, validation-support, expiration, and terms fields while still carrying legacy cost/token compatibility fields; generated quotes include `quoteTiming.elapsedMs`, and marketplace audit summaries aggregate quote response latency, quote cache-hit claims, and linked quote-to-settlement latency for operational snapshots. Quote generation and verification now reject unsupported privacy, verification, or cache-hit claims when the matching runner offer is supplied. `PaymentAuthorizationV1` uses `hivemind.payment_authorization.v1`, includes signed max amount, asset, method, optional job/escrow refs, payment ref, expiration, and cancellation rules. `EscrowRecordV1` uses `hivemind.escrow_record.v1` to record a local locked-funds state linked to a payment authorization and optional quote; `/v1/marketplace/create-escrow`, `/v1/marketplace/verify-escrow`, `/v1/marketplace/release-escrow`, and `/v1/marketplace/escrows` expose local escrow creation, verification, settlement-matched release, and lookup without claiming live on-chain custody. `SettlementEventV1` uses `hivemind.settlement_event.v1` with signed job, quote, receipt, payment-authorization, payer/payee, amount, asset, status, reason, evidence refs, and timestamp fields. `RefundRecordV1`, built through `/v1/marketplace/refund-record`, turns a valid refunded settlement plus a signed refund settlement resolution into a separate audit object with source settlement, refunded settlement, dispute, receipt, payment, refund ref, amount, currency, and local-dev or Ed25519 signature. `SlashingRecordV1`, built through `/v1/marketplace/slash`, is an evidence-gated local-dev record: it requires a disputed settlement, verified dispute evidence, valid receipt verification, and failed validator/proof evidence from `ReceiptCorrectnessAssessmentV1`; missing correctness evidence alone cannot slash a runner or miner. Listing, quote, payment, escrow, settlement, refund, and legacy shortlist request handling remain backward-compatible with existing local `swarm-ai.marketplace.listing.v1`, `swarm-ai.service-quote.v1`, `swarm-ai.payment-authorization.v1`, and `swarm-ai.settlement-event.v1` records; rejected disputes now expose `dispute_rejected` as a first-class settlement state.

The first production job-flow contracts are now explicit Rust/JSON schemas: `RunnerCapabilityV1`, `JobOrderV1`, `JobQuoteV1`, `ExecutionLeaseRequestV1`, `ExecutionLeaseV1`, `JobLifecycleEventV1`, `JobLifecycleTimelineV1`, `JobProductionLifecycleV1`, `JobProductionLifecycleStoreSummaryV1`, `JobStoreAuditRequestV1`, `JobStoreAuditSummaryV1`, `JobEvidenceLinkRequestV1`, `JobEvidenceLinkResultV1`, `JobExpirationSweepRequestV1`, `JobExpirationSweepResultV1`, `JobCancellationRequestV1`, `JobCancellationResultV1`, `StreamingEventV1`, `StreamEventStoreSummaryV1`, `TrustPolicyV1`, `RoutePlannerRequestV1`, `HardwareResourceOfferV1`, `MinerCapacityInputV1`, `MinerCapacitySignalV1`, and the miner profile/heartbeat/benchmark/onboarding/dashboard objects. Route planner reports include an unsigned `JobOrderV1` with typed privacy and verification requirements plus the applied trust policy when one is supplied, local and remote capability endpoints return `RunnerCapabilityV1` with typed `privacyTiers` and `verificationTiers`, quote generation rejects runners that cannot satisfy the job metadata, miner-capacity signals reject stale or impossible GPU routes before selection, and the native `/v1/hivemind`, `/v1/swarm-ai/jobs/*`, and `/v1/miner/*` endpoints now expose the job, quote, lease, lifecycle timeline, production lifecycle coverage, audit, evidence, expiration, cancellation, stream, and miner daemon contracts for the next execution-marketplace milestone.

`swarm-ai registry verify-snapshot`, `/v1/registry/snapshot/verification`, and `/v1/registry/snapshot/verify` check a registry snapshot's canonical `snapshotId`, deterministic `sourceRecords`, content hash, and local-dev signature. `swarm-ai registry compare-manifest`, `swarm-ai registry verify-manifest`, `/v1/registry/shards/manifest`, `/v1/registry/shards/manifest/compare`, `/v1/registry/shards/manifest/verify`, and the Rust/WASM dashboard manifest actions check shard catalogs before a mirror trusts them, including the manifest's own deterministic `manifestHash`, snapshot hashes, counts, portable paths, expected shard hashes, and actual shard files. Manifest comparison is the lightweight catalog preflight; manifest verification additionally checks supplied shard bodies or files.

Evaluation suite contracts are now exposed separately from completed benchmark reports. `/v1/evals/verify-manifest`, `/v1/evals/verify-run`, and `/v1/evals/plan` validate signed `EvalManifestV1` and `EvalRunV1` objects, while OpenAI-style `/v1/evals` and `/v1/evals/{evalId}/runs` create stored, signed planning records for model, RAG, safety, regression, human-review, and model-graded evaluation workflows before live evaluation workers are enabled.

Local packages that have not yet been backed by a PublicationRecordV1 use a deterministic `publishedAt` fallback, and registry snapshot hashes ignore verification observation timestamps such as `verifiedAt`, so independent mirrors can rebuild matching public registry snapshot and shard manifest hashes; signed publication/feed records still preserve their real `publishedAt` values.

Bee-backed storage is available behind the same trait:

```powershell
$env:SWARM_POSTAGE_BATCH_ID="your-64-hex-batch-id"
cargo run -p hivemind-server -- publish .\examples\packages\hello-embedding --provider bee --bee-url http://127.0.0.1:1633
cargo run -p hivemind-server -- validate-ref bzz://bee-reference --provider bee --bee-url http://127.0.0.1:1633
cargo run -p hivemind-server -- inspect bzz://bee-reference --provider bee --bee-url http://127.0.0.1:1633 --path swarm-ai.json
cargo run -p hivemind-server -- cache pin bzz://bee-reference --provider bee --bee-url http://127.0.0.1:1633
cargo run -p hivemind-server -- cache unpin bzz://bee-reference --provider bee --bee-url http://127.0.0.1:1633
cargo run -p hivemind-server -- install bzz://bee-reference --provider bee --bee-url http://127.0.0.1:1633
cargo run -p hivemind-server -- run-ref bzz://bee-reference --provider bee --bee-url http://127.0.0.1:1633 --task embedding --text "hello bee"
```

The Bee provider uses `/bytes` for raw bytes and `/bzz` with an `application/x-tar` body plus `swarm-collection: true` for directory uploads, retries transient 408/429/502/503/504 responses twice with short backoff, and records header/total transfer timing plus `retryCount` in the same `metrics` shape as the local providers.

Browser-native storage is modeled as auditable interface objects instead of a hard dependency on one JavaScript wallet or gateway implementation. `StorageProviderDescriptorV3` remains available for current local dev, Bee HTTP, bee-js gateway, Weeb-3 npm, and hosted upload relay flows. The review-4 `BrowserSwarmStorageProviderV4` catalog adds provider kind names, method sets, capability reports, fallback provider ids, and conformance reports for Weeb-3 browser, bee-js browser, verified gateway fallback, local development, and hosted relay paths. The review-5 browser storage contracts add `BrowserStorageCapabilityProbeV1`, `BrowserStoragePurchaseQuoteV1`, `BrowserStoragePurchaseAuthorizationV1`, `BrowserStorageSessionV2`, `StorageEventReceiptV2`, and `BrowserStorageStateReportV1` so separate browser, wallet, storage, and product teams can agree on explicit capability, payment, session, receipt, and sensitive-state boundaries before a real browser runtime spends funds or uploads user data. `BrowserStorageSecurityAssessmentV1` makes the browser risk controls explicit: provider conformance, origin isolation, sandboxed Swarm-loaded content, service-worker scope and update policy, IndexedDB origin scoping and visibility, clear-state controls, key separation, consent, private-upload encryption, and penetration-test evidence. `/v1/storage/providers/v4`, `/v1/browser-storage/providers/v4`, `/v1/browser-storage/security/assess`, `/v1/browser-storage/security/verify`, the schema CLI, and the `swarm-ai`/`hivemind` aliases expose the provider catalog, security assessment surface, and interface object schemas while keeping Swarm/Bee as storage, publication, access, and audit infrastructure rather than a GPU compute layer.

Governance records can now mark implementation surfaces with explicit readiness labels: `mock`, `local`, `gateway`, `testnet`, or `production`. `ComponentReadinessV1` captures the component name, type, owner, implementation ref, schema refs, API surfaces, supported environments, compatibility certification refs, evidence refs, blockers, limitations, timestamp, and signature. Production readiness verification requires compatibility certification evidence, operational or test evidence, and no blockers; lower readiness levels can still be recorded with warnings so registry and operator views can distinguish local simulations, gateway integrations, testnet services, and production-approved components.

## Current MVP Boundary

Production wallet binding, runner/operator signatures beyond publication, access, receipt, validation, benchmark, and marketplace listing/offer/quote/payment/settlement records, real model inference, and decentralized feed publication are represented by stable interfaces and local development implementations. That keeps the first pass runnable while preserving the component boundaries described in the R&D briefs.
