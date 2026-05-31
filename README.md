# Hivemind

Rust-first implementation scaffold for the SwarmAI architecture writeups.

## What It Can Do Today

Hivemind is a Rust-first local development stack for Swarm-backed AI packages, runners, registries, marketplace flows, validation, receipts, and audit trails. It can scaffold and validate packages, publish them to local or Bee-style storage, rebuild searchable registries, route execution across browser/local/remote runner contracts, produce signed receipts and reports, and expose the whole flow through a CLI, JSON API, OpenAI-compatible endpoints, and a Rust/WASM dashboard.

The current implementation is a working MVP and compatibility harness, not a production decentralized AI network yet. It is useful now for local prototyping, integration tests, protocol demos, package publishing flows, runner and marketplace simulations, and contract validation.

## Ways People Can Use It

- Package authors can create, validate, certify, sign, publish, and feed-update `swarm-ai.json` packages.
- App developers can search the registry, inspect package details, route requests, execute locally, or use `/v1/chat/completions` and `/v1/embeddings`.
- Runner operators can model browser, local, or remote capacity, publish offers, quote work, and emit receipts.
- Registry and mirror operators can rebuild public indexes, emit shards, verify manifests, and compare mirrors.
- Validators can run compatibility checks, benchmark packages, sign reports, and contribute reputation data.
- Marketplace participants can list packages, shortlist runners, authorize payment records, settle receipts, and resolve disputes.
- Protocol implementers can use the schemas, SDK facade, CLI, tests, and crate boundaries as executable contract examples.

The repository is a single Cargo workspace with separate crates for the major R&D components:

- `hivemind-core`: shared SwarmAI contract types, canonical JSON hashing, and common validators.
- `hivemind-identity`: Ed25519 identity keypairs, public identity documents, canonical JSON signature envelopes, and verification reports.
- `hivemind-package`: PackageManifestV1 scaffolding, folder loading, and path validation.
- `hivemind-publisher`: publisher dry-run, deterministic local-dev signing, Ed25519 publication signatures, PublicationRecordV1 verification, local publication/feed audit indexing, and local feed updates/resolution.
- `hivemind-registry`: local registry indexing, grant-aware paginated search, signed publication/feed trust evidence, package detail lookup, public snapshot filtering, and mirrorable shard output/verification.
- `hivemind-storage`: StorageProvider trait, in-memory provider, local directory storage, Bee HTTP storage, transfer timing metrics, cache inspection, feed pointer operations, and pin/unpin support.
- `hivemind-weeb3-adapter`: browser Swarm/weeb-3 provider contract, fallback retrieval, cache status, and compatibility/security reports.
- `hivemind-browser-runner`: browser capability detection, artifact selection, prepare plans, deterministic browser execution, and receipt metadata.
- `hivemind-local-runner`: deterministic Rust development runner with installable artifact cache and sensitive-cache markers for protected packages.
- `hivemind-remote-runner`: remote GPU runner API contract, health/load/pricing status, prepare records, deterministic remote execution, cancellation, and receipts.
- `hivemind-router`: multi-runner route planning, marketplace offer-backed route candidates, cost quotes, policy scoring, and fallback route ordering.
- `hivemind-openai-compat`: OpenAI-style chat completion and embedding request/response adapters backed by SwarmAI execution.
- `hivemind-marketplace`: local-dev and Ed25519 signed package listings, runner offers, service quotes, settlement events, and dispute/refund/reject resolutions, marketplace shortlists/ranking, offer/quote/payment verification, local-dev and Ed25519 payment authorizations, verified settlement results, and local payment/settlement/resolution audit stores.
- `hivemind-access`: license policy, access request, local-dev and Ed25519 signed grants, grant/revocation audit indexing, grant revocation, verification, and access evaluation.
- `hivemind-validator`: compatibility reports, validation challenges, local-dev and Ed25519 signed scoring reports, local report audit indexing, storage upload/download, verification, and reputation profiles.
- `hivemind-receipts`: local-dev and Ed25519 signed receipt handling, embedded policy evidence, storage upload/download, dispute evidence, verification, capture, and local audit trail storage.
- `hivemind-policy`: permission manifests, policy decisions, sandbox requirements, and risk inspection.
- `hivemind-benchmarks`: benchmark packages, dataset entries, scoring rules, local-dev and Ed25519 signed evaluation results, local result audit indexing, and verification.
- `hivemind-sdk`: SDK facade, mock storage/runner, verification helpers, and compatibility certification reports.
- `hivemind-server`: `swarm-ai` CLI plus Axum API/UI composition layer.
- `hivemind-web`: Yew/WASM dashboard built in Rust.

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
cargo run -p hivemind-server -- install bzz://local-dir-reference
cargo run -p hivemind-server -- runner-cache list
cargo run -p hivemind-server -- runner-cache clean bzz://local-dir-reference
cargo run -p hivemind-server -- run-ref bzz://local-dir-reference --task embedding --text "hello ref" --receipts-dir .\.swarm-ai-cache\receipts
cargo run -p hivemind-server -- receipts list
cargo run -p hivemind-server -- receipts get receipt-id
cargo run -p hivemind-server -- receipts verify .\.swarm-ai-cache\receipts\receipt-id.json
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
cargo run -p hivemind-server -- route .\examples\packages\hello-embedding --task embedding --text "route me" --policy balanced
cargo run -p hivemind-server -- serve
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/chat/completions -Method Post -ContentType application/json -Body '{"model":"hivemind/hello-chat","messages":[{"role":"user","content":"hello"}]}'
Invoke-RestMethod -Uri http://127.0.0.1:8787/v1/embeddings -Method Post -ContentType application/json -Body '{"model":"hivemind/hello-embedding","input":["hello","swarm"]}'
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
cargo run -p hivemind-server -- identity generate --subject local-market --output .\.swarm-ai-cache\identity\market.identity.json
cargo run -p hivemind-server -- marketplace listings --owner local-market --identity .\.swarm-ai-cache\identity\market.identity.json
cargo run -p hivemind-server -- marketplace verify-listing --listing .\.swarm-ai-cache\marketplace\listing.json
cargo run -p hivemind-server -- marketplace sign-listing --listing .\.swarm-ai-cache\marketplace\listing.json --identity .\.swarm-ai-cache\identity\market.identity.json --output .\.swarm-ai-cache\marketplace\listing.identity.json
cargo run -p hivemind-server -- marketplace offers
cargo run -p hivemind-server -- identity generate --subject local-dev-runner --output .\.swarm-ai-cache\identity\runner.identity.json
cargo run -p hivemind-server -- marketplace offers --identity .\.swarm-ai-cache\identity\runner.identity.json
cargo run -p hivemind-server -- marketplace shortlist bzz://commercial-local-dir-reference --package-id hivemind/commercial-embedding --task embedding --text "rank runners" --policy balanced
cargo run -p hivemind-server -- marketplace verify-offer --offer .\.swarm-ai-cache\marketplace\offer.json
cargo run -p hivemind-server -- marketplace sign-offer --offer .\.swarm-ai-cache\marketplace\offer.json --identity .\.swarm-ai-cache\identity\runner.identity.json --output .\.swarm-ai-cache\marketplace\offer.identity.json
cargo run -p hivemind-server -- marketplace quote bzz://commercial-local-dir-reference --package-id hivemind/commercial-embedding --task embedding --text "quote me"
cargo run -p hivemind-server -- marketplace quote bzz://commercial-local-dir-reference --package-id hivemind/commercial-embedding --task embedding --text "quote me" --identity .\.swarm-ai-cache\identity\runner.identity.json
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
cargo run -p hivemind-server -- get-evaluation evaluation-id
cargo run -p hivemind-server -- verify-validation .\.swarm-ai-cache\validations\validation-id.json
cargo run -p hivemind-server -- upload-validation .\.swarm-ai-cache\validations\validation-id.json
cargo run -p hivemind-server -- download-validation bzz://local-bytes-validation-report-ref
cargo run -p hivemind-server -- validation-reports
cargo run -p hivemind-server -- get-validation validation-id
cargo run -p hivemind-server -- reputation --subject-type runner local-dev-runner
cargo run -p hivemind-server -- verify-evaluation .\.swarm-ai-cache\evaluations\evaluation-id.json
cargo run -p hivemind-server -- registry get hivemind/hello-embedding
cargo run -p hivemind-server -- registry get hivemind/private-embedding --grant .\.swarm-ai-cache\private.grant.json --requester local-dev --runner-id local-dev-runner
cargo run -p hivemind-server -- registry rebuild
cargo run -p hivemind-server -- registry rebuild --include-private --output .\.swarm-ai-cache\private-registry.json
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
cargo run -p hivemind-server -- schema access-grant
cargo run -p hivemind-server -- schema package-init-options
cargo run -p hivemind-server -- schema package-init-result
cargo run -p hivemind-server -- schema access-grant-verification
cargo run -p hivemind-server -- schema access-grant-store-summary
cargo run -p hivemind-server -- schema access-grant-lookup
cargo run -p hivemind-server -- schema access-grant-revocation
cargo run -p hivemind-server -- schema access-grant-revocation-verification
cargo run -p hivemind-server -- schema access-grant-revocation-store-summary
cargo run -p hivemind-server -- schema access-grant-revocation-lookup
cargo run -p hivemind-server -- schema access-revocation-list
cargo run -p hivemind-server -- schema access-revocation-list-verification
cargo run -p hivemind-server -- schema registry-snapshot
cargo run -p hivemind-server -- schema registry-package-lookup
cargo run -p hivemind-server -- schema registry-package-lookup-request
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
cargo run -p hivemind-server -- schema identity-keypair
cargo run -p hivemind-server -- schema identity-public
cargo run -p hivemind-server -- schema identity-signature
cargo run -p hivemind-server -- schema identity-signature-verification
cargo run -p hivemind-server -- schema policy-inspection
cargo run -p hivemind-server -- schema runner-offer-verification
cargo run -p hivemind-server -- schema marketplace-shortlist-request
cargo run -p hivemind-server -- schema marketplace-listing-verification
cargo run -p hivemind-server -- schema runner-offer-score
cargo run -p hivemind-server -- schema marketplace-shortlist
cargo run -p hivemind-server -- schema service-quote
cargo run -p hivemind-server -- schema service-quote-verification
cargo run -p hivemind-server -- schema payment-authorization
cargo run -p hivemind-server -- schema payment-authorization-verification
cargo run -p hivemind-server -- schema payment-authorization-store-summary
cargo run -p hivemind-server -- schema payment-authorization-lookup
cargo run -p hivemind-server -- schema settlement-verification
cargo run -p hivemind-server -- schema settlement-event-verification
cargo run -p hivemind-server -- schema settlement-build-result
cargo run -p hivemind-server -- schema settlement-resolution
cargo run -p hivemind-server -- schema settlement-resolution-verification
cargo run -p hivemind-server -- schema settlement-resolution-result
cargo run -p hivemind-server -- schema marketplace-audit-summary
cargo run -p hivemind-server -- schema settlement-event-lookup
cargo run -p hivemind-server -- schema settlement-resolution-lookup
cargo run -p hivemind-server -- schema validation-report
cargo run -p hivemind-server -- schema validation-report-verification
cargo run -p hivemind-server -- schema validation-report-store-summary
cargo run -p hivemind-server -- schema validation-report-lookup
cargo run -p hivemind-server -- schema validation-report-upload
cargo run -p hivemind-server -- schema validation-report-download
cargo run -p hivemind-server -- schema evaluation-result
cargo run -p hivemind-server -- schema evaluation-result-verification
cargo run -p hivemind-server -- schema evaluation-result-store-summary
cargo run -p hivemind-server -- schema evaluation-result-lookup
cargo run -p hivemind-server -- schema compatibility-report
cargo run -p hivemind-server -- schema receipt-verification
cargo run -p hivemind-server -- schema receipt-lookup
cargo run -p hivemind-server -- schema receipt-upload
cargo run -p hivemind-server -- schema receipt-download
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
cargo run -p hivemind-server -- schema route-planner-report
cargo run -p hivemind-server -- schema route-execution-trace
cargo run -p hivemind-server -- schema openai-chat-completion-request
cargo run -p hivemind-server -- schema openai-embedding-response
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
- `POST /v1/access/verify-grant`
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
- `GET /v1/registry/shards`
- `GET /v1/registry/shards/manifest`
- `POST /v1/registry/shards/manifest/compare`
- `POST /v1/registry/shards/verify`
- `POST /v1/registry/shards/manifest/verify`
- `GET /v1/storage/status`
- `GET /v1/storage/cache`
- `POST /v1/storage/inspect`
- `POST /v1/storage/pin`
- `POST /v1/storage/unpin`
- `POST /v1/storage/feed/create`
- `POST /v1/storage/feed/update`
- `POST /v1/storage/feed/resolve`
- `GET /v1/policy/catalog`
- `POST /v1/policy/inspect`
- `GET /v1/receipts`
- `GET /v1/receipts/{receiptId}`
- `POST /v1/receipts/verify`
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
- `GET /v1/validator/reports`
- `GET /v1/validator/reports/{reportId}`
- `POST /v1/validator/reputation`
- `POST /v1/validator/verify-report`
- `POST /v1/validator/upload-report`
- `POST /v1/validator/download-report`
- `GET /v1/benchmarks/evaluations`
- `GET /v1/benchmarks/evaluations/{evaluationId}`
- `POST /v1/benchmarks/verify-evaluation`
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
- `GET /v1/swarm-ai/capabilities`
- `POST /v1/swarm-ai/route`
- `POST /v1/swarm-ai/route-report`
- `POST /v1/swarm-ai/execute`
- `GET /v1/swarm-ai/receipt/{receiptId}`
- `GET /v1/swarm-ai/cache`
- `DELETE /v1/swarm-ai/cache/{packageRef}`
- `POST /v1/chat/completions`
- `POST /v1/embeddings`
- `GET /v1/marketplace/listings`
- `POST /v1/marketplace/verify-listing`
- `GET /v1/marketplace/offers`
- `POST /v1/marketplace/shortlist`
- `POST /v1/marketplace/verify-offer`
- `POST /v1/marketplace/quote`
- `POST /v1/marketplace/verify-quote`
- `POST /v1/marketplace/authorize-payment`
- `POST /v1/marketplace/verify-payment`
- `GET /v1/marketplace/payments`
- `GET /v1/marketplace/payments/{authorizationId}`
- `GET /v1/marketplace/audit`
- `GET /v1/marketplace/settlements/{settlementId}`
- `GET /v1/marketplace/resolutions/{resolutionId}`
- `POST /v1/marketplace/settle`
- `POST /v1/marketplace/verify-settlement`
- `POST /v1/marketplace/dispute-settlement`
- `POST /v1/marketplace/refund-settlement`
- `POST /v1/marketplace/reject-dispute`
- `POST /v1/marketplace/verify-resolution`

## Local Publish Flow

`swarm-ai init` creates valid embedding or chat package scaffolds with `swarm-ai.json`, mock artifact files, computed artifact-group hashes, and an immediate validation report.

Publication and feed audit records are indexed for `publication-records`, `get-publication`, `feed-pointers`, `get-feed`, `/v1/publisher/publications`, `/v1/publisher/feeds`, and the Rust/WASM dashboard.

`swarm-ai publish` validates a package, uploads the package directory into `.swarm-ai-cache/storage`, writes a signed PublicationRecordV1 into `.swarm-ai-cache/publications`, updates channel feed pointers under `.swarm-ai-cache/feeds`, and returns a local `bzz://local-dir-...` reference. `swarm-ai sign`, `swarm-ai verify-publication`, `swarm-ai update-feed`, and `swarm-ai resolve-feed` expose the same local-dev signing and feed lifecycle as smaller steps; `swarm-ai identity generate/public/sign-publication` adds Ed25519 keypair-backed publication signatures without breaking existing local-dev records. `swarm-ai cache status`, `cache list`, `cache pin`, `cache unpin`, `cache create-feed`, `cache update-feed`, and `cache resolve-feed` exercise the StorageProvider contract directly; download/upload responses now include transfer timing metrics and retry counts, `storage/status` exposes Bee HTTP's bounded retry policy for transient 408/429/502/503/504 responses, local cache inspection is exposed through `/v1/storage/cache` and `/v1/storage/inspect`, local storage persists feed pointers and pin markers, and Bee HTTP supports timed transfer responses plus pin/unpin through Bee pin endpoints. `swarm-ai validate-ref` checks the manifest and referenced artifact paths directly from storage. Registry search, package detail lookup, public snapshots, shards, marketplace listings, marketplace shortlists, quotes, and public runner offers hide private packages by default; `swarm-ai search --grant ... --requester ... --runner-id ...` and `/v1/registry/search` can reveal matching private entries only when the signed grant, requester, requested use, runner scope, and optional revocation list authorize discovery. `swarm-ai registry get`, `/v1/registry/package`, `/v1/registry/packages/{packageId}`, and the Rust/WASM dashboard package detail action return the selected entry with its manifest, publication/feed evidence, validation reports, and benchmark evaluations; private detail lookup requires the same grant/revocation inputs as private search unless `--include-private` is used for intentional local/private CLI exports. `swarm-ai registry rebuild`, `swarm-ai registry shards`, `swarm-ai registry verify-shards`, `/v1/registry/shards`, `/v1/registry/shards/verify`, and `swarm-ai marketplace listings/offers/shortlist` also default to public output, with `--include-private` reserved for intentional local/private exports; `swarm-ai registry shards` writes a portable `manifest.json` with a snapshot hash, relative shard paths, entry/shard counts, and deterministic `shardHash` values for mirror comparison, and shard verification compares mirror files or submitted shard sets against snapshot-derived facet shards while ignoring the intentionally variable `generatedAt` timestamp. `swarm-ai browser-swarm` exposes the browser-side weeb-3 provider contract, checks cache/fallback status, reports browser compatibility/security boundaries, and retrieves package manifests/files through the same local fallback storage used by the server. `swarm-ai policy inspect` explains permissions, risk level, default policy decision, and sandbox requirements before execution. `swarm-ai install` resolves that reference, verifies any signed access grant and optional access revocation list before artifact download, caches the compatible artifact files under `.swarm-ai-cache/runner`, writes an `install.json` record, and marks protected/private installs with a `.swarm-ai-sensitive-cache.json` sidecar. `swarm-ai runner-cache` and `/v1/swarm-ai/cache` list and clear installed artifact groups by package reference. `swarm-ai run-ref` executes a package directly from a storage reference through the local Rust runner and can persist its signed embedded receipt with `--receipts-dir`; local-runner receipts include signed policy decision evidence, and `swarm-ai receipts` verifies, captures, lists, looks up by id, uploads/downloads storage-backed receipt objects, upgrades receipts with `receipts sign --identity`, and creates, stores, lists, and looks up local-dev or Ed25519 signed dispute evidence for those audit records. `swarm-ai browser` assesses browser-compatible artifact groups, creates browser prepare records, and runs the deterministic browser execution path used by the Rust/WASM dashboard's `Run Browser` command. `swarm-ai remote` exposes the remote GPU runner API contract, health/load/pricing metadata, prepare records, simulated streaming output, and signed receipt-producing execution. `swarm-ai route` compares browser, local, remote, and marketplace offer-backed routes with privacy, speed, cost, quality, or balanced policy scoring and emits fallback route IDs; route planning evaluates access per candidate runner so runner-scoped grants only authorize matching routes. `/v1/swarm-ai/execute` records the selected route, attempted fallback routes, and marketplace shortlist in response metadata, while `/v1/swarm-ai/receipt/{receiptId}` exposes the remote-runner receipt lookup contract from the local audit store. `/v1/chat/completions` and `/v1/embeddings` provide OpenAI-style local compatibility endpoints over the same router, runners, and receipt-producing execution path. Commercial, private, token-gated, subscription, and custom licenses require an `AccessGrantV1`; `swarm-ai issue-grant` and `swarm-ai revoke-grant` still create local-dev signed records by default, persist grant/revocation audit records under `.swarm-ai-cache/access`, expose them through `access-grants`, `get-grant`, `access-revocations`, `get-revocation`, `/v1/access/grants`, `/v1/access/revocations`, and the Rust/WASM dashboard, and `--identity` upgrades those grants/revocations to Ed25519 envelopes checked by the same `verify-grant`, `verify-grant-revocation`, and `verify-revocation-list` commands. `swarm-ai marketplace` builds local-dev or Ed25519 signed static package listings, local-dev or Ed25519 signed runner offers, ranked runner shortlists, local-dev or Ed25519 signed service quotes, verifies listing, offer, and quote consistency, authorizes local-dev or Ed25519 payer identity payment proofs, persists payment authorization records under `.swarm-ai-cache/marketplace/payments`, creates verified receipt-linked settlement events, creates local-dev or Ed25519 signed dispute/refund/reject resolution records, and persists settlement/resolution audit records under `.swarm-ai-cache/marketplace/audit` for CLI, API, and dashboard lookup; the Rust/WASM dashboard can now drive the same quote, authorization, payment audit, settlement, dispute evidence, dispute, refund, rejection, resolution verification, dispute audit, and marketplace audit-summary path. `swarm-ai validate-run` executes a public validation challenge and writes a signed ValidationReportV1 under `.swarm-ai-cache/validations`; `--identity` or `swarm-ai sign-validation` upgrades validation reports to Ed25519 validator envelopes, `swarm-ai verify-validation` checks their canonical id and signature, `swarm-ai validation-reports` / `swarm-ai get-validation` expose the local validator report audit store, `swarm-ai reputation` builds local reputation profiles from valid reports, and `swarm-ai upload-validation` / `swarm-ai download-validation` store or retrieve verified reports through the local or Bee storage provider. `swarm-ai benchmark-run` executes the mini embedding benchmark from `examples/benchmarks/embedding-basic-v1`, writes a signed EvaluationResultV1 under `.swarm-ai-cache/evaluations`, supports Ed25519 validator signatures through `--identity` or `swarm-ai sign-evaluation`, exposes the local evaluation audit store with `swarm-ai evaluation-results` / `swarm-ai get-evaluation`, and `swarm-ai verify-evaluation` checks result integrity. `swarm-ai registry rebuild` combines local packages, signed publication records, feed pointers, verified validation reports, policy summaries, and verified benchmark evaluation results into `examples/registry/index.json`; `swarm-ai registry shards` splits that snapshot into mirrorable facet shards. `swarm-ai certify` runs the SDK compatibility suite against a package folder, including manifest validation, forward-compatible unknown fields, execution request/response round trips, receipt verification, mock storage loading, and artifact selection.

`swarm-ai registry compare-manifest`, `swarm-ai registry verify-manifest`, `/v1/registry/shards/manifest`, `/v1/registry/shards/manifest/compare`, `/v1/registry/shards/manifest/verify`, and the Rust/WASM dashboard manifest actions check shard catalogs before a mirror trusts them, including the manifest's own deterministic `manifestHash`, snapshot hashes, counts, portable paths, expected shard hashes, and actual shard files. Manifest comparison is the lightweight catalog preflight; manifest verification additionally checks supplied shard bodies or files.

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

## Current MVP Boundary

Production wallet binding, runner/operator signatures beyond publication, access, receipt, validation, benchmark, and marketplace listing/offer/quote/payment/settlement records, real model inference, and decentralized feed publication are represented by stable interfaces and local development implementations. That keeps the first pass runnable while preserving the component boundaries described in the R&D briefs.
