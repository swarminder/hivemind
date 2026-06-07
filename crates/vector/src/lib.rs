use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    ApiSurface, IntegrityTier, PrivacyTier, ValidationIssue, canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const DOCUMENT_COLLECTION_SCHEMA_VERSION: &str = "hivemind.document_collection.v1";
pub const CHUNK_SET_SCHEMA_VERSION: &str = "hivemind.chunk_set.v1";
pub const EMBEDDING_SET_SCHEMA_VERSION: &str = "hivemind.embedding_set.v1";
pub const VECTOR_INDEX_V2_SCHEMA_VERSION: &str = "hivemind.vector_index.v2";
pub const RETRIEVAL_QUERY_SCHEMA_VERSION: &str = "hivemind.retrieval_query.v1";
pub const RETRIEVAL_PLAN_SCHEMA_VERSION: &str = "hivemind.retrieval_plan.v1";
pub const RETRIEVAL_PLANNING_REQUEST_SCHEMA_VERSION: &str =
    "hivemind.retrieval_planning_request.v1";
pub const RAG_PIPELINE_V2_SCHEMA_VERSION: &str = "hivemind.rag_pipeline.v2";
pub const CITATION_TRACE_SCHEMA_VERSION: &str = "hivemind.citation_trace.v1";
pub const KNOWLEDGE_ASSET_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.knowledge_asset_verification.v1";
pub const RAG_INGEST_REQUEST_SCHEMA_VERSION: &str = "hivemind.rag_ingest_request.v1";
pub const RAG_CHUNK_RECORD_SCHEMA_VERSION: &str = "hivemind.rag_chunk_record.v1";
pub const RAG_EMBEDDING_RECORD_SCHEMA_VERSION: &str = "hivemind.rag_embedding_record.v1";
pub const RAG_INDEX_SNAPSHOT_SCHEMA_VERSION: &str = "hivemind.rag_index_snapshot.v1";
pub const RAG_INGEST_RESULT_SCHEMA_VERSION: &str = "hivemind.rag_ingest_result.v1";
pub const RAG_SEARCH_REQUEST_SCHEMA_VERSION: &str = "hivemind.rag_search_request.v1";
pub const RAG_SEARCH_RESULT_SCHEMA_VERSION: &str = "hivemind.rag_search_result.v1";
pub const RAG_ASK_REQUEST_SCHEMA_VERSION: &str = "hivemind.rag_ask_request.v1";
pub const RAG_ANSWER_RECEIPT_SCHEMA_VERSION: &str = "hivemind.rag_answer_receipt.v1";
pub const RAG_ANSWER_RESULT_SCHEMA_VERSION: &str = "hivemind.rag_answer_result.v1";

const DEV_VECTOR_STORE_SIGNATURE_PREFIX: &str = "dev-vector-store-signature-v1";
const DEV_KNOWLEDGE_SIGNATURE_PREFIX: &str = "dev-knowledge-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VectorMetric {
    Cosine,
    DotProduct,
    Euclidean,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum VectorAccessVisibility {
    Public,
    Private,
    Organization,
    TokenGated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum VectorStorageRole {
    Index,
    Metadata,
    Chunks,
    Documents,
    EmbeddingCache,
    Manifest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorAccessPolicyV1 {
    pub visibility: VectorAccessVisibility,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "accessGrantRequired", default)]
    pub access_grant_required: bool,
    #[serde(
        rename = "licenseRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub license_ref: Option<String>,
    #[serde(
        rename = "redactionPolicyRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub redaction_policy_ref: Option<String>,
}

impl Default for VectorAccessPolicyV1 {
    fn default() -> Self {
        Self {
            visibility: VectorAccessVisibility::Public,
            privacy_tier: PrivacyTier::Standard,
            access_grant_required: false,
            license_ref: None,
            redaction_policy_ref: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorStorageRefV1 {
    pub role: VectorStorageRole,
    pub reference: String,
    #[serde(
        rename = "contentType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(rename = "sizeBytes", default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeRefRoleV1 {
    Manifest,
    Document,
    ChunkSet,
    EmbeddingSet,
    VectorIndex,
    Metadata,
    Source,
    Citation,
    Receipt,
    Feed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct KnowledgeAssetRefV1 {
    pub role: KnowledgeRefRoleV1,
    pub reference: String,
    #[serde(
        rename = "contentType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(rename = "sizeBytes", default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DocumentSensitivityV1 {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DocumentCollectionUpdateModeV1 {
    ImmutableSnapshot,
    FeedBacked,
    AppendOnly,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DocumentAssetV1 {
    #[serde(rename = "documentId")]
    pub document_id: String,
    pub title: String,
    #[serde(rename = "sourceRef")]
    pub source_ref: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(rename = "sizeBytes", default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    pub sensitivity: DocumentSensitivityV1,
    #[serde(
        rename = "licenseRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub license_ref: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DocumentCollectionManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "collectionId")]
    pub collection_id: String,
    pub name: String,
    pub owner: String,
    pub summary: String,
    #[serde(rename = "updateMode")]
    pub update_mode: DocumentCollectionUpdateModeV1,
    pub documents: Vec<DocumentAssetV1>,
    #[serde(rename = "metadataSchema", default)]
    pub metadata_schema: Value,
    #[serde(rename = "accessPolicy")]
    pub access_policy: VectorAccessPolicyV1,
    #[serde(rename = "storageRefs", default)]
    pub storage_refs: Vec<KnowledgeAssetRefV1>,
    #[serde(rename = "feedRef", default, skip_serializing_if = "Option::is_none")]
    pub feed_ref: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ChunkingStrategyKindV1 {
    FixedTokens,
    Sentence,
    MarkdownSection,
    Semantic,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChunkingStrategyV1 {
    #[serde(rename = "strategyKind")]
    pub strategy_kind: ChunkingStrategyKindV1,
    #[serde(rename = "targetTokens")]
    pub target_tokens: u32,
    #[serde(rename = "overlapTokens")]
    pub overlap_tokens: u32,
    #[serde(default)]
    pub separators: Vec<String>,
    #[serde(
        rename = "tokenizerRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tokenizer_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChunkSetManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "chunkSetId")]
    pub chunk_set_id: String,
    #[serde(rename = "collectionRef")]
    pub collection_ref: String,
    #[serde(
        rename = "collectionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub collection_id: Option<String>,
    #[serde(rename = "chunkingStrategy")]
    pub chunking_strategy: ChunkingStrategyV1,
    #[serde(rename = "chunkCount")]
    pub chunk_count: u64,
    #[serde(rename = "chunkRefs")]
    pub chunk_refs: Vec<KnowledgeAssetRefV1>,
    #[serde(
        rename = "metadataRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub metadata_ref: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EmbeddingVectorPrecisionV1 {
    Float32,
    Float16,
    Int8Quantized,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EmbeddingSetManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "embeddingSetId")]
    pub embedding_set_id: String,
    #[serde(rename = "chunkSetRef")]
    pub chunk_set_ref: String,
    #[serde(rename = "embeddingModelRef")]
    pub embedding_model_ref: String,
    pub dimensions: u32,
    pub metric: VectorMetric,
    pub precision: EmbeddingVectorPrecisionV1,
    #[serde(rename = "vectorCount")]
    pub vector_count: u64,
    #[serde(rename = "embeddingRefs")]
    pub embedding_refs: Vec<KnowledgeAssetRefV1>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum VectorIndexBackendV2 {
    SwarmStatic,
    BrowserMemory,
    LocalService,
    RemoteService,
    MinerHosted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorIndexRefreshPolicyV2 {
    #[serde(rename = "updateMode")]
    pub update_mode: DocumentCollectionUpdateModeV1,
    #[serde(
        rename = "sourceFeedRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_feed_ref: Option<String>,
    #[serde(rename = "incrementalUpdates", default)]
    pub incremental_updates: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorIndexManifestV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "vectorIndexId")]
    pub vector_index_id: String,
    pub name: String,
    pub owner: String,
    #[serde(rename = "embeddingSetRef")]
    pub embedding_set_ref: String,
    #[serde(rename = "documentCollectionRefs")]
    pub document_collection_refs: Vec<String>,
    #[serde(rename = "chunkSetRefs")]
    pub chunk_set_refs: Vec<String>,
    #[serde(rename = "embeddingModelRef")]
    pub embedding_model_ref: String,
    #[serde(rename = "indexFormat")]
    pub index_format: String,
    pub backend: VectorIndexBackendV2,
    pub dimensions: u32,
    pub metric: VectorMetric,
    #[serde(rename = "accessPolicy")]
    pub access_policy: VectorAccessPolicyV1,
    #[serde(rename = "storageRefs")]
    pub storage_refs: Vec<KnowledgeAssetRefV1>,
    #[serde(rename = "refreshPolicy")]
    pub refresh_policy: VectorIndexRefreshPolicyV2,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RetrievalExecutionModeV1 {
    BrowserLocal,
    LocalService,
    RemoteService,
    MinerHosted,
    StaticIndexReplay,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RetrievalQueryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "queryId")]
    pub query_id: String,
    pub requester: String,
    pub query: Value,
    #[serde(rename = "topK")]
    pub top_k: u32,
    #[serde(default)]
    pub filters: Value,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(
        rename = "embeddingModelRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub embedding_model_ref: Option<String>,
    #[serde(rename = "traceRequired", default)]
    pub trace_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RetrievalPlanningRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub query: RetrievalQueryV1,
    #[serde(rename = "vectorIndex")]
    pub vector_index: VectorIndexManifestV2,
    #[serde(
        rename = "ragPipeline",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub rag_pipeline: Option<RagPipelineManifestV2>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RetrievalPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "planId")]
    pub plan_id: String,
    #[serde(rename = "queryId")]
    pub query_id: String,
    #[serde(
        rename = "pipelineId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pipeline_id: Option<String>,
    #[serde(rename = "vectorIndexRefs")]
    pub vector_index_refs: Vec<String>,
    #[serde(rename = "documentCollectionRefs")]
    pub document_collection_refs: Vec<String>,
    #[serde(rename = "embeddingModelRefs")]
    pub embedding_model_refs: Vec<String>,
    #[serde(rename = "immutableRefs")]
    pub immutable_refs: Vec<String>,
    #[serde(rename = "mutableRefs")]
    pub mutable_refs: Vec<String>,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    #[serde(rename = "topK")]
    pub top_k: u32,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "accessGrantRequired")]
    pub access_grant_required: bool,
    #[serde(rename = "executionMode")]
    pub execution_mode: RetrievalExecutionModeV1,
    #[serde(rename = "citationTraceRequired")]
    pub citation_trace_required: bool,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RagPipelineStageKindV2 {
    Retrieve,
    Rerank,
    AssembleContext,
    GenerateAnswer,
    CiteSources,
    ValidateAnswer,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagPipelineStageV2 {
    #[serde(rename = "stageId")]
    pub stage_id: String,
    #[serde(rename = "stageKind")]
    pub stage_kind: RagPipelineStageKindV2,
    #[serde(rename = "inputRefs", default)]
    pub input_refs: Vec<String>,
    #[serde(rename = "outputRef", default, skip_serializing_if = "Option::is_none")]
    pub output_ref: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CitationPolicyV1 {
    Required,
    BestEffort,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagPipelineManifestV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "pipelineId")]
    pub pipeline_id: String,
    pub name: String,
    pub owner: String,
    #[serde(rename = "documentCollectionRefs")]
    pub document_collection_refs: Vec<String>,
    #[serde(rename = "vectorIndexRefs")]
    pub vector_index_refs: Vec<String>,
    #[serde(rename = "retrieverRef")]
    pub retriever_ref: String,
    #[serde(rename = "generatorPackageRef")]
    pub generator_package_ref: String,
    #[serde(rename = "citationPolicy")]
    pub citation_policy: CitationPolicyV1,
    #[serde(rename = "answerOutputSchema", default)]
    pub answer_output_schema: Value,
    #[serde(rename = "accessPolicy")]
    pub access_policy: VectorAccessPolicyV1,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "verificationTiers")]
    pub verification_tiers: Vec<IntegrityTier>,
    pub stages: Vec<RagPipelineStageV2>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CitationVisibilityV1 {
    Public,
    AuthorizedOnly,
    Redacted,
    HashOnly,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CitationSpanV1 {
    #[serde(rename = "outputStart")]
    pub output_start: u32,
    #[serde(rename = "outputEnd")]
    pub output_end: u32,
    #[serde(rename = "sourceRef")]
    pub source_ref: String,
    #[serde(
        rename = "documentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub document_id: Option<String>,
    #[serde(rename = "chunkId", default, skip_serializing_if = "Option::is_none")]
    pub chunk_id: Option<String>,
    #[serde(rename = "quoteHash", default, skip_serializing_if = "Option::is_none")]
    pub quote_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    pub visibility: CitationVisibilityV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CitationTraceV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "traceId")]
    pub trace_id: String,
    #[serde(rename = "queryId")]
    pub query_id: String,
    #[serde(rename = "answerRef")]
    pub answer_ref: String,
    #[serde(
        rename = "retrievalPlanRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub retrieval_plan_ref: Option<String>,
    #[serde(
        rename = "pipelineRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pipeline_ref: Option<String>,
    pub citations: Vec<CitationSpanV1>,
    #[serde(rename = "policyWarnings", default)]
    pub policy_warnings: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct KnowledgeAssetVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorStoreManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "vectorStoreId")]
    pub vector_store_id: String,
    pub name: String,
    pub owner: String,
    #[serde(rename = "embeddingModelRef")]
    pub embedding_model_ref: String,
    #[serde(rename = "documentCollectionRefs")]
    pub document_collection_refs: Vec<String>,
    #[serde(rename = "indexFormat")]
    pub index_format: String,
    pub dimensions: u32,
    pub metric: VectorMetric,
    #[serde(rename = "metadataSchema", default)]
    pub metadata_schema: Value,
    #[serde(rename = "chunkingStrategyRef")]
    pub chunking_strategy_ref: String,
    #[serde(rename = "accessPolicy")]
    pub access_policy: VectorAccessPolicyV1,
    #[serde(rename = "storageRefs")]
    pub storage_refs: Vec<VectorStorageRefV1>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorStoreInitOptionsV1 {
    pub name: String,
    pub owner: String,
    #[serde(rename = "embeddingModelRef")]
    pub embedding_model_ref: String,
    #[serde(rename = "documentCollectionRefs", default)]
    pub document_collection_refs: Vec<String>,
    #[serde(rename = "indexFormat", default)]
    pub index_format: Option<String>,
    pub dimensions: u32,
    #[serde(default)]
    pub metric: Option<VectorMetric>,
    #[serde(rename = "chunkingStrategyRef", default)]
    pub chunking_strategy_ref: Option<String>,
    #[serde(rename = "storageRefs", default)]
    pub storage_refs: Vec<VectorStorageRefV1>,
    #[serde(rename = "accessPolicy", default)]
    pub access_policy: Option<VectorAccessPolicyV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorStoreVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "vectorStoreId")]
    pub vector_store_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorSearchRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub requester: String,
    #[serde(rename = "vectorStoreRef")]
    pub vector_store_ref: String,
    #[serde(rename = "vectorStoreId")]
    pub vector_store_id: String,
    pub query: Value,
    #[serde(rename = "topK")]
    pub top_k: u32,
    #[serde(default)]
    pub filters: Value,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "traceRequired", default)]
    pub trace_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorSearchPlanningRequestV1 {
    pub manifest: VectorStoreManifestV1,
    pub request: VectorSearchRequestV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorSearchPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "vectorStoreId")]
    pub vector_store_id: String,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    #[serde(rename = "embeddingModelRef")]
    pub embedding_model_ref: String,
    #[serde(rename = "indexFormat")]
    pub index_format: String,
    pub dimensions: u32,
    pub metric: VectorMetric,
    #[serde(rename = "topK")]
    pub top_k: u32,
    #[serde(rename = "immutableRefs")]
    pub immutable_refs: Vec<String>,
    #[serde(rename = "mutableRefs")]
    pub mutable_refs: Vec<String>,
    #[serde(rename = "accessGrantRequired")]
    pub access_grant_required: bool,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "traceRequired")]
    pub trace_required: bool,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorStoreIndexEntryV1 {
    #[serde(rename = "vectorStoreId")]
    pub vector_store_id: String,
    pub name: String,
    pub owner: String,
    pub visibility: VectorAccessVisibility,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "accessGrantRequired")]
    pub access_grant_required: bool,
    #[serde(rename = "embeddingModelRef")]
    pub embedding_model_ref: String,
    #[serde(rename = "indexFormat")]
    pub index_format: String,
    pub dimensions: u32,
    pub metric: VectorMetric,
    #[serde(rename = "documentCollectionCount")]
    pub document_collection_count: usize,
    #[serde(rename = "storageRefCount")]
    pub storage_ref_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub valid: bool,
    #[serde(rename = "signaturePresent")]
    pub signature_present: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "manifestPath")]
    pub manifest_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorStoreManifestStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "vectorStoreCount")]
    pub vector_store_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "privateCount")]
    pub private_count: usize,
    #[serde(rename = "accessGrantRequiredCount")]
    pub access_grant_required_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    #[serde(rename = "vectorStores")]
    pub vector_stores: Vec<VectorStoreIndexEntryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VectorStoreManifestLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "vectorStoreId")]
    pub vector_store_id: String,
    #[serde(rename = "manifestPath")]
    pub manifest_path: String,
    pub manifest: VectorStoreManifestV1,
    pub verification: VectorStoreVerificationV1,
    #[serde(rename = "auditSearchPlan")]
    pub audit_search_plan: VectorSearchPlanV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagIngestRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub collection: String,
    pub owner: String,
    pub title: String,
    #[serde(rename = "documentText")]
    pub document_text: String,
    #[serde(rename = "sourceRef", default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    #[serde(rename = "contentType", default = "default_text_content_type")]
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default = "default_document_sensitivity")]
    pub sensitivity: DocumentSensitivityV1,
    #[serde(rename = "accessPolicy", default)]
    pub access_policy: VectorAccessPolicyV1,
    #[serde(rename = "chunkingStrategy", default = "default_rag_chunking_strategy")]
    pub chunking_strategy: ChunkingStrategyV1,
    #[serde(
        rename = "embeddingModelRef",
        default = "default_rag_embedding_model_ref"
    )]
    pub embedding_model_ref: String,
    #[serde(default = "default_rag_dimensions")]
    pub dimensions: u32,
    #[serde(default = "default_rag_metric")]
    pub metric: VectorMetric,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagChunkRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "chunkId")]
    pub chunk_id: String,
    #[serde(rename = "documentId")]
    pub document_id: String,
    #[serde(rename = "chunkSetId")]
    pub chunk_set_id: String,
    pub ordinal: u64,
    pub text: String,
    #[serde(rename = "textSha256")]
    pub text_sha256: String,
    #[serde(rename = "sourceRef")]
    pub source_ref: String,
    #[serde(rename = "startChar")]
    pub start_char: u64,
    #[serde(rename = "endChar")]
    pub end_char: u64,
    #[serde(rename = "tokenCount")]
    pub token_count: u32,
    #[serde(rename = "accessPolicy")]
    pub access_policy: VectorAccessPolicyV1,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagEmbeddingRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "embeddingId")]
    pub embedding_id: String,
    #[serde(rename = "chunkId")]
    pub chunk_id: String,
    #[serde(rename = "embeddingSetId")]
    pub embedding_set_id: String,
    #[serde(rename = "embeddingModelRef")]
    pub embedding_model_ref: String,
    pub dimensions: u32,
    pub vector: Vec<f32>,
    #[serde(rename = "vectorSha256")]
    pub vector_sha256: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagIndexSnapshotV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "snapshotId")]
    pub snapshot_id: String,
    pub collection: DocumentCollectionManifestV1,
    #[serde(rename = "chunkSet")]
    pub chunk_set: ChunkSetManifestV1,
    #[serde(rename = "embeddingSet")]
    pub embedding_set: EmbeddingSetManifestV1,
    #[serde(rename = "vectorIndex")]
    pub vector_index: VectorIndexManifestV2,
    #[serde(rename = "ragPipeline")]
    pub rag_pipeline: RagPipelineManifestV2,
    pub chunks: Vec<RagChunkRecordV1>,
    pub embeddings: Vec<RagEmbeddingRecordV1>,
    #[serde(rename = "sourceStorageRefs", default)]
    pub source_storage_refs: Vec<KnowledgeAssetRefV1>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagIngestResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "snapshot")]
    pub snapshot: RagIndexSnapshotV1,
    pub verifications: Vec<KnowledgeAssetVerificationV1>,
    pub warnings: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagSearchRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub collection: String,
    pub requester: String,
    pub query: String,
    #[serde(rename = "topK", default = "default_top_k")]
    pub top_k: u32,
    #[serde(rename = "privacyTier", default = "default_privacy_tier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "accessGrantRefs", default)]
    pub access_grant_refs: Vec<String>,
    #[serde(rename = "includeText", default)]
    pub include_text: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagSearchHitV1 {
    #[serde(rename = "chunkId")]
    pub chunk_id: String,
    #[serde(rename = "documentId")]
    pub document_id: String,
    pub title: String,
    pub score: f64,
    #[serde(rename = "sourceRef")]
    pub source_ref: String,
    #[serde(rename = "quoteHash")]
    pub quote_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagSearchResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub request: RagSearchRequestV1,
    #[serde(rename = "retrievalPlan")]
    pub retrieval_plan: RetrievalPlanV1,
    pub hits: Vec<RagSearchHitV1>,
    #[serde(rename = "accessGranted")]
    pub access_granted: bool,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagAskRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub collection: String,
    pub requester: String,
    pub query: String,
    #[serde(rename = "topK", default = "default_top_k")]
    pub top_k: u32,
    #[serde(rename = "privacyTier", default = "default_privacy_tier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "accessGrantRefs", default)]
    pub access_grant_refs: Vec<String>,
    #[serde(rename = "receiptRequired", default)]
    pub receipt_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagAnswerReceiptV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "queryId")]
    pub query_id: String,
    #[serde(rename = "collectionId")]
    pub collection_id: String,
    #[serde(rename = "answerSha256")]
    pub answer_sha256: String,
    #[serde(rename = "documentRefs")]
    pub document_refs: Vec<String>,
    #[serde(rename = "chunkRefs")]
    pub chunk_refs: Vec<String>,
    #[serde(rename = "retrievalPlanRef")]
    pub retrieval_plan_ref: String,
    #[serde(rename = "citationTraceRef")]
    pub citation_trace_ref: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RagAnswerResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub request: RagAskRequestV1,
    pub answer: String,
    #[serde(rename = "searchResult")]
    pub search_result: RagSearchResultV1,
    #[serde(rename = "citationTrace")]
    pub citation_trace: CitationTraceV1,
    #[serde(
        rename = "answerReceipt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub answer_receipt: Option<RagAnswerReceiptV1>,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
}

pub fn create_vector_store_manifest(options: VectorStoreInitOptionsV1) -> VectorStoreManifestV1 {
    let mut document_collection_refs = options.document_collection_refs;
    document_collection_refs.sort();
    document_collection_refs.dedup();
    let mut storage_refs = options.storage_refs;
    storage_refs.sort_by(|left, right| {
        serde_json::to_string(left)
            .unwrap_or_default()
            .cmp(&serde_json::to_string(right).unwrap_or_default())
    });

    let mut manifest = VectorStoreManifestV1 {
        schema_version: "swarm-ai.vector-store.v1".to_string(),
        vector_store_id: String::new(),
        name: options.name,
        owner: options.owner,
        embedding_model_ref: options.embedding_model_ref,
        document_collection_refs,
        index_format: options.index_format.unwrap_or_else(|| "hnsw".to_string()),
        dimensions: options.dimensions,
        metric: options.metric.unwrap_or(VectorMetric::Cosine),
        metadata_schema: json!({ "type": "object" }),
        chunking_strategy_ref: options
            .chunking_strategy_ref
            .unwrap_or_else(|| "local://chunking/default".to_string()),
        access_policy: options.access_policy.unwrap_or_default(),
        storage_refs,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_vector_store_manifest(&mut manifest);
    manifest
}

pub fn sign_vector_store_manifest(manifest: &mut VectorStoreManifestV1) {
    manifest.signature = Some(expected_vector_store_signature(manifest));
    manifest.vector_store_id = canonical_vector_store_id(manifest);
}

pub fn sign_vector_store_with_identity(
    manifest: &mut VectorStoreManifestV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != manifest.owner {
        anyhow::bail!(
            "identity subject {} does not match vector store owner {}",
            identity.subject,
            manifest.owner
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "vector-store",
        &vector_store_signing_value(manifest),
    )?;
    manifest.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    manifest.vector_store_id = canonical_vector_store_id(manifest);
    Ok(envelope)
}

pub fn expected_vector_store_signature(manifest: &VectorStoreManifestV1) -> String {
    format!(
        "{DEV_VECTOR_STORE_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&vector_store_signing_value(manifest)))
    )
}

pub fn canonical_vector_store_id(manifest: &VectorStoreManifestV1) -> String {
    stable_id("vector-store", &vector_store_signing_value(manifest))
}

pub fn verify_vector_store_manifest(manifest: &VectorStoreManifestV1) -> VectorStoreVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_vector_store_signature(manifest));
    let signature = manifest
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if manifest.schema_version != "swarm-ai.vector-store.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.vector-store.v1",
        ));
    }
    require_non_empty(&mut issues, "$.vectorStoreId", &manifest.vector_store_id);
    if !manifest.vector_store_id.is_empty()
        && manifest.vector_store_id != canonical_vector_store_id(manifest)
    {
        issues.push(issue(
            "$.vectorStoreId",
            "Vector store id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.name", &manifest.name);
    require_non_empty(&mut issues, "$.owner", &manifest.owner);
    require_non_empty(
        &mut issues,
        "$.embeddingModelRef",
        &manifest.embedding_model_ref,
    );
    require_non_empty(&mut issues, "$.indexFormat", &manifest.index_format);
    require_non_empty(
        &mut issues,
        "$.chunkingStrategyRef",
        &manifest.chunking_strategy_ref,
    );
    if manifest.dimensions == 0 {
        issues.push(issue(
            "$.dimensions",
            "Vector dimensions must be greater than zero",
        ));
    }
    if manifest.document_collection_refs.is_empty() {
        issues.push(issue(
            "$.documentCollectionRefs",
            "Vector store must reference at least one document collection",
        ));
    }
    if manifest.storage_refs.is_empty() {
        issues.push(issue(
            "$.storageRefs",
            "Vector store must include storage references for index, chunks, or metadata",
        ));
    }
    if !manifest.metadata_schema.is_object() {
        warnings.push(issue(
            "$.metadataSchema",
            "Metadata schema should be a JSON Schema object",
        ));
    }
    for (path, reference) in manifest_refs(manifest) {
        if reference.trim().is_empty() {
            issues.push(issue(path, "Reference must not be empty"));
        } else if !looks_like_ref(&reference) {
            warnings.push(issue(
                path,
                "Reference is not a recognized bzz://, local://, ipfs://, sha256://, or https:// reference",
            ));
        } else if looks_mutable_ref(&reference) {
            warnings.push(issue(
                path,
                "Mutable reference should be resolved to immutable content before exact retrieval replay",
            ));
        }
    }
    match chrono::DateTime::parse_from_rfc3339(&manifest.created_at) {
        Ok(_) => {}
        Err(_) => issues.push(issue(
            "$.createdAt",
            "createdAt must be an RFC3339 timestamp",
        )),
    }

    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "vector-store",
                &vector_store_signing_value(manifest),
                Some(&manifest.owner),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(issue(
                "$.signature",
                "Vector store signature does not match canonical dev signature or Ed25519 owner identity envelope",
            ));
        }
    } else {
        warnings.push(issue(
            "$.signature",
            "Vector store is unsigned; verify owner and vectorStoreId through a trusted source",
        ));
    }

    VectorStoreVerificationV1 {
        schema_version: "swarm-ai.vector-store-verification.v1".to_string(),
        vector_store_id: manifest.vector_store_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn vector_search_plan(
    manifest: &VectorStoreManifestV1,
    request: &VectorSearchRequestV1,
) -> VectorSearchPlanV1 {
    let verification = verify_vector_store_manifest(manifest);
    let mut issues = verification.issues;
    let mut warnings = verification.warnings;
    if request.schema_version != "swarm-ai.vector-search-request.v1" {
        issues.push(issue(
            "$.request.schemaVersion",
            "Expected schemaVersion to be swarm-ai.vector-search-request.v1",
        ));
    }
    require_non_empty(&mut issues, "$.request.requestId", &request.request_id);
    require_non_empty(&mut issues, "$.request.requester", &request.requester);
    require_non_empty(
        &mut issues,
        "$.request.vectorStoreRef",
        &request.vector_store_ref,
    );
    if request.vector_store_id != manifest.vector_store_id {
        issues.push(issue(
            "$.request.vectorStoreId",
            "Search request vectorStoreId must match manifest vectorStoreId",
        ));
    }
    if request.top_k == 0 {
        issues.push(issue("$.request.topK", "topK must be greater than zero"));
    }
    if request.query.is_null() {
        issues.push(issue("$.request.query", "query must not be null"));
    }
    if request.privacy_tier != manifest.access_policy.privacy_tier {
        warnings.push(issue(
            "$.request.privacyTier",
            "Search request privacy tier differs from vector store access policy",
        ));
    }

    let mut immutable_refs = Vec::new();
    let mut mutable_refs = Vec::new();
    for (_path, reference) in manifest_refs(manifest) {
        if looks_mutable_ref(&reference) {
            mutable_refs.push(reference);
        } else {
            immutable_refs.push(reference);
        }
    }
    immutable_refs.sort();
    immutable_refs.dedup();
    mutable_refs.sort();
    mutable_refs.dedup();

    VectorSearchPlanV1 {
        schema_version: "swarm-ai.vector-search-plan.v1".to_string(),
        request_id: request.request_id.clone(),
        vector_store_id: manifest.vector_store_id.clone(),
        api_surface: ApiSurface::VectorSearch,
        embedding_model_ref: manifest.embedding_model_ref.clone(),
        index_format: manifest.index_format.clone(),
        dimensions: manifest.dimensions,
        metric: manifest.metric.clone(),
        top_k: request.top_k,
        immutable_refs,
        mutable_refs,
        access_grant_required: manifest.access_policy.access_grant_required,
        privacy_tier: request.privacy_tier.clone(),
        trace_required: request.trace_required,
        valid: issues.is_empty(),
        issues,
        warnings,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn vector_search_request(
    vector_store_ref: impl Into<String>,
    vector_store_id: impl Into<String>,
    requester: impl Into<String>,
    query: Value,
) -> VectorSearchRequestV1 {
    VectorSearchRequestV1 {
        schema_version: "swarm-ai.vector-search-request.v1".to_string(),
        request_id: stable_id("vector-search", &query),
        requester: requester.into(),
        vector_store_ref: vector_store_ref.into(),
        vector_store_id: vector_store_id.into(),
        query,
        top_k: 5,
        filters: json!({}),
        privacy_tier: PrivacyTier::Standard,
        trace_required: true,
    }
}

pub fn list_vector_store_manifests(
    vector_dir: &Path,
) -> anyhow::Result<VectorStoreManifestStoreSummaryV1> {
    let mut files = Vec::new();
    collect_vector_store_files(vector_dir, &mut files)?;
    files.sort();

    let mut vector_stores = Vec::new();
    let mut valid_count = 0;
    let mut private_count = 0;
    let mut access_grant_required_count = 0;
    let mut mutable_ref_count = 0;
    let mut warning_count = 0;

    for path in files {
        let Some(manifest) = read_vector_store_file(&path)? else {
            continue;
        };
        let verification = verify_vector_store_manifest(&manifest);
        let plan = audit_vector_search_plan(&manifest);
        if verification.valid {
            valid_count += 1;
        }
        if !matches!(
            manifest.access_policy.visibility,
            VectorAccessVisibility::Public
        ) {
            private_count += 1;
        }
        if manifest.access_policy.access_grant_required {
            access_grant_required_count += 1;
        }
        mutable_ref_count += plan.mutable_refs.len();
        warning_count += verification.warnings.len() + plan.warnings.len();
        vector_stores.push(vector_store_index_entry(
            &manifest,
            &verification,
            &plan,
            path.display().to_string(),
        ));
    }
    vector_stores.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.vector_store_id.cmp(&right.vector_store_id))
            .then(left.manifest_path.cmp(&right.manifest_path))
    });

    Ok(VectorStoreManifestStoreSummaryV1 {
        schema_version: "swarm-ai.vector-store-manifest-store-summary.v1".to_string(),
        root: vector_dir.display().to_string(),
        vector_store_count: vector_stores.len(),
        valid_count,
        invalid_count: vector_stores.len().saturating_sub(valid_count),
        private_count,
        access_grant_required_count,
        mutable_ref_count,
        warning_count,
        vector_stores,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn get_vector_store_manifest(
    vector_dir: &Path,
    vector_store_id: &str,
) -> anyhow::Result<Option<VectorStoreManifestLookupV1>> {
    let vector_store_id = vector_store_id.trim();
    if vector_store_id.is_empty() {
        anyhow::bail!("vectorStoreId is required");
    }
    let mut files = Vec::new();
    collect_vector_store_files(vector_dir, &mut files)?;
    files.sort();

    for path in files {
        let Some(manifest) = read_vector_store_file(&path)? else {
            continue;
        };
        if manifest.vector_store_id == vector_store_id {
            let verification = verify_vector_store_manifest(&manifest);
            let audit_search_plan = audit_vector_search_plan(&manifest);
            return Ok(Some(VectorStoreManifestLookupV1 {
                schema_version: "swarm-ai.vector-store-manifest-lookup.v1".to_string(),
                vector_store_id: manifest.vector_store_id.clone(),
                manifest_path: path.display().to_string(),
                manifest,
                verification,
                audit_search_plan,
            }));
        }
    }

    Ok(None)
}

pub fn rag_ingest_plain_text(request: RagIngestRequestV1) -> anyhow::Result<RagIngestResultV1> {
    let mut issues = Vec::new();
    if request.schema_version != RAG_INGEST_REQUEST_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {RAG_INGEST_REQUEST_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.collection", &request.collection);
    require_non_empty(&mut issues, "$.owner", &request.owner);
    require_non_empty(&mut issues, "$.title", &request.title);
    require_non_empty(
        &mut issues,
        "$.embeddingModelRef",
        &request.embedding_model_ref,
    );
    if request.document_text.trim().is_empty() {
        issues.push(issue("$.documentText", "documentText must not be empty"));
    }
    if request.dimensions == 0 {
        issues.push(issue(
            "$.dimensions",
            "dimensions must be greater than zero",
        ));
    }
    if request.chunking_strategy.target_tokens == 0 {
        issues.push(issue(
            "$.chunkingStrategy.targetTokens",
            "targetTokens must be greater than zero",
        ));
    }
    if request.chunking_strategy.overlap_tokens >= request.chunking_strategy.target_tokens {
        issues.push(issue(
            "$.chunkingStrategy.overlapTokens",
            "overlapTokens must be smaller than targetTokens",
        ));
    }
    if !rag_supports_text_content_type(&request.content_type) {
        issues.push(issue(
            "$.contentType",
            "Swarm RAG One currently supports plain text and Markdown content types",
        ));
    }
    if !issues.is_empty() {
        anyhow::bail!("RAG ingest request is invalid: {}", issue_summary(&issues));
    }

    let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let document_bytes = request.document_text.as_bytes();
    let document_sha256 = sha256_hex_bytes(document_bytes);
    let source_ref = request
        .source_ref
        .clone()
        .unwrap_or_else(|| format!("sha256://{document_sha256}"));
    let source_storage_ref = KnowledgeAssetRefV1 {
        role: KnowledgeRefRoleV1::Document,
        reference: source_ref.clone(),
        content_type: Some(request.content_type.clone()),
        sha256: Some(document_sha256.clone()),
        size_bytes: Some(document_bytes.len().try_into().unwrap_or(u64::MAX)),
    };
    let document_seed = json!({
        "collection": &request.collection,
        "owner": &request.owner,
        "title": &request.title,
        "sourceRef": &source_ref,
        "sha256": &document_sha256,
    });
    let document_id = stable_id("document", &document_seed);
    let document = DocumentAssetV1 {
        document_id: document_id.clone(),
        title: request.title.clone(),
        source_ref: source_ref.clone(),
        content_type: request.content_type.clone(),
        sha256: Some(document_sha256),
        size_bytes: Some(document_bytes.len().try_into().unwrap_or(u64::MAX)),
        language: request.language.clone(),
        metadata: request.metadata.clone(),
        sensitivity: request.sensitivity.clone(),
        license_ref: request.access_policy.license_ref.clone(),
        created_at: created_at.clone(),
    };

    let mut collection = DocumentCollectionManifestV1 {
        schema_version: DOCUMENT_COLLECTION_SCHEMA_VERSION.to_string(),
        object_kind: "document_collection".to_string(),
        collection_id: String::new(),
        name: request.collection.clone(),
        owner: request.owner.clone(),
        summary: format!("Swarm RAG One collection for {}", request.title),
        update_mode: DocumentCollectionUpdateModeV1::ImmutableSnapshot,
        documents: vec![document],
        metadata_schema: json!({ "type": "object" }),
        access_policy: request.access_policy.clone(),
        storage_refs: vec![source_storage_ref.clone()],
        feed_ref: None,
        created_at: created_at.clone(),
        signature: None,
    };
    sign_document_collection_manifest(&mut collection);

    let raw_chunks = chunk_document_text(
        &request.document_text,
        request.chunking_strategy.target_tokens,
        request.chunking_strategy.overlap_tokens,
    );
    if raw_chunks.is_empty() {
        anyhow::bail!("RAG ingest produced no chunks");
    }

    let mut chunks = raw_chunks
        .into_iter()
        .map(|raw| {
            let text_sha256 = sha256_hex_bytes(raw.text.as_bytes());
            let chunk_id = stable_id(
                "chunk",
                &json!({
                    "documentId": &document_id,
                    "ordinal": raw.ordinal,
                    "textSha256": &text_sha256,
                }),
            );
            RagChunkRecordV1 {
                schema_version: RAG_CHUNK_RECORD_SCHEMA_VERSION.to_string(),
                chunk_id,
                document_id: document_id.clone(),
                chunk_set_id: String::new(),
                ordinal: raw.ordinal,
                text: raw.text,
                text_sha256,
                source_ref: source_ref.clone(),
                start_char: raw.start_char,
                end_char: raw.end_char,
                token_count: raw.token_count,
                access_policy: request.access_policy.clone(),
                created_at: created_at.clone(),
            }
        })
        .collect::<Vec<_>>();
    let chunk_refs = chunks
        .iter()
        .map(|chunk| KnowledgeAssetRefV1 {
            role: KnowledgeRefRoleV1::ChunkSet,
            reference: format!("sha256://{}", chunk.text_sha256),
            content_type: Some("text/plain".to_string()),
            sha256: Some(chunk.text_sha256.clone()),
            size_bytes: Some(chunk.text.len().try_into().unwrap_or(u64::MAX)),
        })
        .collect::<Vec<_>>();
    let mut chunk_set = ChunkSetManifestV1 {
        schema_version: CHUNK_SET_SCHEMA_VERSION.to_string(),
        object_kind: "chunk_set".to_string(),
        chunk_set_id: String::new(),
        collection_ref: format!("local://document-collections/{}", collection.collection_id),
        collection_id: Some(collection.collection_id.clone()),
        chunking_strategy: request.chunking_strategy.clone(),
        chunk_count: chunks.len().try_into().unwrap_or(u64::MAX),
        chunk_refs,
        metadata_ref: Some(format!(
            "local://rag/{}/chunks",
            sanitize_path_id(&request.collection)
        )),
        created_at: created_at.clone(),
        signature: None,
    };
    sign_chunk_set_manifest(&mut chunk_set);
    for chunk in &mut chunks {
        chunk.chunk_set_id = chunk_set.chunk_set_id.clone();
    }

    let mut embeddings = chunks
        .iter()
        .map(|chunk| {
            let vector = deterministic_embedding_vector(
                &chunk.text,
                &request.embedding_model_ref,
                request.dimensions,
            );
            let vector_sha256 = sha256_hex_bytes(&serde_json::to_vec(&vector).unwrap_or_default());
            let embedding_id = stable_id(
                "embedding",
                &json!({
                    "chunkId": &chunk.chunk_id,
                    "embeddingModelRef": &request.embedding_model_ref,
                    "vectorSha256": &vector_sha256,
                }),
            );
            RagEmbeddingRecordV1 {
                schema_version: RAG_EMBEDDING_RECORD_SCHEMA_VERSION.to_string(),
                embedding_id,
                chunk_id: chunk.chunk_id.clone(),
                embedding_set_id: String::new(),
                embedding_model_ref: request.embedding_model_ref.clone(),
                dimensions: request.dimensions,
                vector,
                vector_sha256,
                created_at: created_at.clone(),
            }
        })
        .collect::<Vec<_>>();
    let embedding_refs = embeddings
        .iter()
        .map(|embedding| KnowledgeAssetRefV1 {
            role: KnowledgeRefRoleV1::EmbeddingSet,
            reference: format!("sha256://{}", embedding.vector_sha256),
            content_type: Some("application/json".to_string()),
            sha256: Some(embedding.vector_sha256.clone()),
            size_bytes: Some(
                serde_json::to_vec(&embedding.vector)
                    .unwrap_or_default()
                    .len()
                    .try_into()
                    .unwrap_or(u64::MAX),
            ),
        })
        .collect::<Vec<_>>();
    let mut embedding_set = EmbeddingSetManifestV1 {
        schema_version: EMBEDDING_SET_SCHEMA_VERSION.to_string(),
        object_kind: "embedding_set".to_string(),
        embedding_set_id: String::new(),
        chunk_set_ref: format!("local://chunk-sets/{}", chunk_set.chunk_set_id),
        embedding_model_ref: request.embedding_model_ref.clone(),
        dimensions: request.dimensions,
        metric: request.metric.clone(),
        precision: EmbeddingVectorPrecisionV1::Float32,
        vector_count: embeddings.len().try_into().unwrap_or(u64::MAX),
        embedding_refs,
        created_at: created_at.clone(),
        signature: None,
    };
    sign_embedding_set_manifest(&mut embedding_set);
    for embedding in &mut embeddings {
        embedding.embedding_set_id = embedding_set.embedding_set_id.clone();
    }

    let mut vector_index = VectorIndexManifestV2 {
        schema_version: VECTOR_INDEX_V2_SCHEMA_VERSION.to_string(),
        object_kind: "vector_index".to_string(),
        vector_index_id: String::new(),
        name: format!("{} index", request.collection),
        owner: request.owner.clone(),
        embedding_set_ref: format!("local://embedding-sets/{}", embedding_set.embedding_set_id),
        document_collection_refs: vec![format!(
            "local://document-collections/{}",
            collection.collection_id
        )],
        chunk_set_refs: vec![format!("local://chunk-sets/{}", chunk_set.chunk_set_id)],
        embedding_model_ref: request.embedding_model_ref.clone(),
        index_format: "swarm-rag-one-static-json".to_string(),
        backend: VectorIndexBackendV2::SwarmStatic,
        dimensions: request.dimensions,
        metric: request.metric.clone(),
        access_policy: request.access_policy.clone(),
        storage_refs: vec![
            source_storage_ref.clone(),
            KnowledgeAssetRefV1 {
                role: KnowledgeRefRoleV1::ChunkSet,
                reference: format!("local://chunk-sets/{}", chunk_set.chunk_set_id),
                content_type: Some("application/json".to_string()),
                sha256: Some(sha256_json(&chunks)),
                size_bytes: Some(serde_json_len(&chunks)),
            },
            KnowledgeAssetRefV1 {
                role: KnowledgeRefRoleV1::EmbeddingSet,
                reference: format!("local://embedding-sets/{}", embedding_set.embedding_set_id),
                content_type: Some("application/json".to_string()),
                sha256: Some(sha256_json(&embeddings)),
                size_bytes: Some(serde_json_len(&embeddings)),
            },
        ],
        refresh_policy: VectorIndexRefreshPolicyV2 {
            update_mode: DocumentCollectionUpdateModeV1::ImmutableSnapshot,
            source_feed_ref: None,
            incremental_updates: false,
        },
        created_at: created_at.clone(),
        signature: None,
    };
    sign_vector_index_manifest_v2(&mut vector_index);

    let mut rag_pipeline = RagPipelineManifestV2 {
        schema_version: RAG_PIPELINE_V2_SCHEMA_VERSION.to_string(),
        object_kind: "rag_pipeline".to_string(),
        pipeline_id: String::new(),
        name: format!("{} RAG pipeline", request.collection),
        owner: request.owner.clone(),
        document_collection_refs: vec![format!(
            "local://document-collections/{}",
            collection.collection_id
        )],
        vector_index_refs: vec![vector_index.vector_index_id.clone()],
        retriever_ref: "local://retrievers/swarm-rag-one-static-cosine".to_string(),
        generator_package_ref: "local://generators/swarm-rag-one-extractive".to_string(),
        citation_policy: CitationPolicyV1::Required,
        answer_output_schema: json!({
            "type": "object",
            "required": ["answer", "citations"]
        }),
        access_policy: request.access_policy.clone(),
        privacy_tier: request.access_policy.privacy_tier.clone(),
        verification_tiers: vec![IntegrityTier::ReceiptOnly],
        stages: vec![
            RagPipelineStageV2 {
                stage_id: "retrieve".to_string(),
                stage_kind: RagPipelineStageKindV2::Retrieve,
                input_refs: vec![vector_index.vector_index_id.clone()],
                output_ref: Some("local://rag/search-hits".to_string()),
                required: true,
            },
            RagPipelineStageV2 {
                stage_id: "assemble-context".to_string(),
                stage_kind: RagPipelineStageKindV2::AssembleContext,
                input_refs: vec!["local://rag/search-hits".to_string()],
                output_ref: Some("local://rag/context".to_string()),
                required: true,
            },
            RagPipelineStageV2 {
                stage_id: "generate-answer".to_string(),
                stage_kind: RagPipelineStageKindV2::GenerateAnswer,
                input_refs: vec!["local://rag/context".to_string()],
                output_ref: Some("local://rag/answer".to_string()),
                required: true,
            },
            RagPipelineStageV2 {
                stage_id: "cite-sources".to_string(),
                stage_kind: RagPipelineStageKindV2::CiteSources,
                input_refs: vec!["local://rag/answer".to_string()],
                output_ref: Some("local://rag/citation-trace".to_string()),
                required: true,
            },
        ],
        created_at: created_at.clone(),
        signature: None,
    };
    sign_rag_pipeline_manifest_v2(&mut rag_pipeline);

    let snapshot_id = stable_id(
        "rag-snapshot",
        &json!({
            "collectionId": collection.collection_id,
            "chunkSetId": chunk_set.chunk_set_id,
            "embeddingSetId": embedding_set.embedding_set_id,
            "vectorIndexId": vector_index.vector_index_id,
            "pipelineId": rag_pipeline.pipeline_id,
        }),
    );
    let snapshot = RagIndexSnapshotV1 {
        schema_version: RAG_INDEX_SNAPSHOT_SCHEMA_VERSION.to_string(),
        snapshot_id,
        collection,
        chunk_set,
        embedding_set,
        vector_index,
        rag_pipeline,
        chunks,
        embeddings,
        source_storage_refs: vec![source_storage_ref],
        created_at,
    };
    let verifications = vec![
        verify_document_collection_manifest(&snapshot.collection),
        verify_chunk_set_manifest(&snapshot.chunk_set),
        verify_embedding_set_manifest(&snapshot.embedding_set),
        verify_vector_index_manifest_v2(&snapshot.vector_index),
        verify_rag_pipeline_manifest_v2(&snapshot.rag_pipeline),
    ];
    let warnings = verifications
        .iter()
        .flat_map(|verification| verification.warnings.clone())
        .collect();

    Ok(RagIngestResultV1 {
        schema_version: RAG_INGEST_RESULT_SCHEMA_VERSION.to_string(),
        snapshot,
        verifications,
        warnings,
    })
}

pub fn rag_search(snapshot: &RagIndexSnapshotV1, request: RagSearchRequestV1) -> RagSearchResultV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if request.schema_version != RAG_SEARCH_REQUEST_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {RAG_SEARCH_REQUEST_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.requestId", &request.request_id);
    require_non_empty(&mut issues, "$.collection", &request.collection);
    require_non_empty(&mut issues, "$.requester", &request.requester);
    require_non_empty(&mut issues, "$.query", &request.query);
    if request.top_k == 0 {
        issues.push(issue("$.topK", "topK must be greater than zero"));
    }
    if request.collection != snapshot.collection.name
        && request.collection != snapshot.collection.collection_id
    {
        issues.push(issue(
            "$.collection",
            "Search request collection must match the RAG snapshot collection name or id",
        ));
    }
    if snapshot.schema_version != RAG_INDEX_SNAPSHOT_SCHEMA_VERSION {
        issues.push(issue(
            "$.snapshot.schemaVersion",
            format!("Expected snapshot schemaVersion to be {RAG_INDEX_SNAPSHOT_SCHEMA_VERSION}"),
        ));
    }

    let access_granted = access_policy_allows(
        &snapshot.vector_index.access_policy,
        &request.access_grant_refs,
    );
    if !access_granted {
        issues.push(issue(
            "$.accessGrantRefs",
            "This collection requires an access grant before retrieval or citation",
        ));
    }

    let retrieval_query = RetrievalQueryV1 {
        schema_version: RETRIEVAL_QUERY_SCHEMA_VERSION.to_string(),
        query_id: request.request_id.clone(),
        requester: request.requester.clone(),
        query: json!({ "text": request.query }),
        top_k: request.top_k,
        filters: json!({}),
        privacy_tier: request.privacy_tier.clone(),
        embedding_model_ref: Some(snapshot.vector_index.embedding_model_ref.clone()),
        trace_required: true,
    };
    let retrieval_request = RetrievalPlanningRequestV1 {
        schema_version: RETRIEVAL_PLANNING_REQUEST_SCHEMA_VERSION.to_string(),
        query: retrieval_query,
        vector_index: snapshot.vector_index.clone(),
        rag_pipeline: Some(snapshot.rag_pipeline.clone()),
    };
    let retrieval_plan = retrieval_plan(&retrieval_request);
    warnings.extend(retrieval_plan.warnings.clone());
    issues.extend(
        retrieval_plan
            .issues
            .iter()
            .cloned()
            .map(|issue| prefix_issue("$.retrievalPlan", issue)),
    );

    let hits = if issues.is_empty() {
        let query_embedding = deterministic_embedding_vector(
            &request.query,
            &snapshot.vector_index.embedding_model_ref,
            snapshot.vector_index.dimensions,
        );
        let mut scored = snapshot
            .embeddings
            .iter()
            .filter_map(|embedding| {
                let chunk = snapshot
                    .chunks
                    .iter()
                    .find(|chunk| chunk.chunk_id == embedding.chunk_id)?;
                if !access_policy_allows(&chunk.access_policy, &request.access_grant_refs) {
                    return None;
                }
                Some((
                    embedding,
                    chunk,
                    cosine_score(&query_embedding, &embedding.vector),
                ))
            })
            .collect::<Vec<_>>();
        scored.sort_by(|left, right| {
            right
                .2
                .partial_cmp(&left.2)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(left.1.ordinal.cmp(&right.1.ordinal))
        });
        scored
            .into_iter()
            .take(request.top_k as usize)
            .map(|(_embedding, chunk, score)| RagSearchHitV1 {
                chunk_id: chunk.chunk_id.clone(),
                document_id: chunk.document_id.clone(),
                title: snapshot
                    .collection
                    .documents
                    .iter()
                    .find(|document| document.document_id == chunk.document_id)
                    .map(|document| document.title.clone())
                    .unwrap_or_else(|| snapshot.collection.name.clone()),
                score,
                source_ref: chunk.source_ref.clone(),
                quote_hash: chunk.text_sha256.clone(),
                text: if request.include_text {
                    Some(chunk.text.clone())
                } else {
                    None
                },
            })
            .collect()
    } else {
        Vec::new()
    };

    let valid = issues.is_empty();
    RagSearchResultV1 {
        schema_version: RAG_SEARCH_RESULT_SCHEMA_VERSION.to_string(),
        request,
        retrieval_plan,
        hits,
        access_granted,
        valid,
        issues,
        warnings,
    }
}

pub fn rag_ask(snapshot: &RagIndexSnapshotV1, request: RagAskRequestV1) -> RagAnswerResultV1 {
    let mut issues = Vec::new();
    if request.schema_version != RAG_ASK_REQUEST_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {RAG_ASK_REQUEST_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.requestId", &request.request_id);
    require_non_empty(&mut issues, "$.query", &request.query);

    let search_request = RagSearchRequestV1 {
        schema_version: RAG_SEARCH_REQUEST_SCHEMA_VERSION.to_string(),
        request_id: request.request_id.clone(),
        collection: request.collection.clone(),
        requester: request.requester.clone(),
        query: request.query.clone(),
        top_k: request.top_k,
        privacy_tier: request.privacy_tier.clone(),
        access_grant_refs: request.access_grant_refs.clone(),
        include_text: true,
    };
    let search_result = rag_search(snapshot, search_request);
    issues.extend(
        search_result
            .issues
            .iter()
            .cloned()
            .map(|issue| prefix_issue("$.searchResult", issue)),
    );

    let answer = if search_result.hits.is_empty() {
        "No accessible chunks matched the question.".to_string()
    } else {
        let mut excerpts = Vec::new();
        for hit in &search_result.hits {
            if let Some(text) = hit.text.as_deref() {
                excerpts.push(format!("{}: {}", hit.title, compact_excerpt(text, 280)));
            }
        }
        format!(
            "Based on {} retrieved chunk(s), {}",
            search_result.hits.len(),
            excerpts.join(" ")
        )
    };
    let answer_sha256 = sha256_hex_bytes(answer.as_bytes());
    let answer_ref = format!("sha256://{answer_sha256}");
    let output_end = answer.chars().count().try_into().unwrap_or(u32::MAX);
    let citations = search_result
        .hits
        .iter()
        .map(|hit| CitationSpanV1 {
            output_start: 0,
            output_end: output_end.max(1),
            source_ref: hit.source_ref.clone(),
            document_id: Some(hit.document_id.clone()),
            chunk_id: Some(hit.chunk_id.clone()),
            quote_hash: Some(hit.quote_hash.clone()),
            score: Some(hit.score),
            visibility: if search_result.access_granted {
                CitationVisibilityV1::Public
            } else {
                CitationVisibilityV1::HashOnly
            },
        })
        .collect::<Vec<_>>();
    let mut citation_trace = CitationTraceV1 {
        schema_version: CITATION_TRACE_SCHEMA_VERSION.to_string(),
        object_kind: "citation_trace".to_string(),
        trace_id: String::new(),
        query_id: request.request_id.clone(),
        answer_ref,
        retrieval_plan_ref: Some(format!(
            "local://retrieval-plans/{}",
            search_result.retrieval_plan.plan_id
        )),
        pipeline_ref: Some(format!(
            "local://rag-pipelines/{}",
            snapshot.rag_pipeline.pipeline_id
        )),
        citations,
        policy_warnings: search_result
            .warnings
            .iter()
            .map(|warning| warning.message.clone())
            .collect(),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    if !citation_trace.citations.is_empty() {
        sign_citation_trace(&mut citation_trace);
        let citation_verification = verify_citation_trace(&citation_trace);
        issues.extend(citation_verification.issues);
    }

    let answer_receipt = if request.receipt_required && issues.is_empty() {
        let mut document_refs = search_result
            .hits
            .iter()
            .map(|hit| hit.source_ref.clone())
            .collect::<Vec<_>>();
        document_refs.sort();
        document_refs.dedup();
        let chunk_refs = search_result
            .hits
            .iter()
            .map(|hit| format!("local://rag/chunks/{}", hit.chunk_id))
            .collect::<Vec<_>>();
        let receipt_seed = json!({
            "queryId": &request.request_id,
            "answerSha256": &answer_sha256,
            "chunkRefs": &chunk_refs,
            "citationTraceId": &citation_trace.trace_id,
        });
        Some(RagAnswerReceiptV1 {
            schema_version: RAG_ANSWER_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_id: stable_id("rag-answer-receipt", &receipt_seed),
            query_id: request.request_id.clone(),
            collection_id: snapshot.collection.collection_id.clone(),
            answer_sha256,
            document_refs,
            chunk_refs,
            retrieval_plan_ref: format!(
                "local://retrieval-plans/{}",
                search_result.retrieval_plan.plan_id
            ),
            citation_trace_ref: format!("local://citation-traces/{}", citation_trace.trace_id),
            created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        })
    } else {
        None
    };
    let valid = issues.is_empty() && search_result.valid;

    RagAnswerResultV1 {
        schema_version: RAG_ANSWER_RESULT_SCHEMA_VERSION.to_string(),
        request,
        answer,
        search_result,
        citation_trace,
        answer_receipt,
        valid,
        issues,
        warnings: Vec::new(),
    }
}

pub fn rag_snapshot_path(vector_dir: &Path, collection: &str) -> PathBuf {
    vector_dir
        .join("rag")
        .join(format!("{}.rag.json", sanitize_path_id(collection)))
}

pub fn write_rag_index_snapshot(
    vector_dir: &Path,
    collection: &str,
    snapshot: &RagIndexSnapshotV1,
) -> anyhow::Result<PathBuf> {
    let path = rag_snapshot_path(vector_dir, collection);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, serde_json::to_vec_pretty(snapshot)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn read_rag_index_snapshot(
    vector_dir: &Path,
    collection: &str,
) -> anyhow::Result<RagIndexSnapshotV1> {
    let path = rag_snapshot_path(vector_dir, collection);
    let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn sign_document_collection_manifest(manifest: &mut DocumentCollectionManifestV1) {
    manifest.signature = Some(expected_document_collection_signature(manifest));
    manifest.collection_id = canonical_document_collection_id(manifest);
}

pub fn sign_chunk_set_manifest(manifest: &mut ChunkSetManifestV1) {
    manifest.signature = Some(expected_chunk_set_signature(manifest));
    manifest.chunk_set_id = canonical_chunk_set_id(manifest);
}

pub fn sign_embedding_set_manifest(manifest: &mut EmbeddingSetManifestV1) {
    manifest.signature = Some(expected_embedding_set_signature(manifest));
    manifest.embedding_set_id = canonical_embedding_set_id(manifest);
}

pub fn sign_vector_index_manifest_v2(manifest: &mut VectorIndexManifestV2) {
    manifest.signature = Some(expected_vector_index_v2_signature(manifest));
    manifest.vector_index_id = canonical_vector_index_v2_id(manifest);
}

pub fn sign_rag_pipeline_manifest_v2(manifest: &mut RagPipelineManifestV2) {
    manifest.signature = Some(expected_rag_pipeline_v2_signature(manifest));
    manifest.pipeline_id = canonical_rag_pipeline_v2_id(manifest);
}

pub fn sign_citation_trace(trace: &mut CitationTraceV1) {
    trace.signature = Some(expected_citation_trace_signature(trace));
    trace.trace_id = canonical_citation_trace_id(trace);
}

pub fn sign_vector_index_v2_with_identity(
    manifest: &mut VectorIndexManifestV2,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != manifest.owner {
        anyhow::bail!(
            "identity subject {} does not match vector index owner {}",
            identity.subject,
            manifest.owner
        );
    }
    let signing_value = vector_index_v2_signing_value(manifest);
    let envelope = hivemind_identity::sign_value(identity, "vector-index-v2", &signing_value)?;
    manifest.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    manifest.vector_index_id = canonical_vector_index_v2_id(manifest);
    Ok(envelope)
}

pub fn vector_index_v2_from_vector_store(
    manifest: &VectorStoreManifestV1,
) -> VectorIndexManifestV2 {
    let storage_refs = manifest
        .storage_refs
        .iter()
        .map(knowledge_ref_from_vector_storage_ref)
        .collect::<Vec<_>>();
    let mut index = VectorIndexManifestV2 {
        schema_version: VECTOR_INDEX_V2_SCHEMA_VERSION.to_string(),
        object_kind: "vector_index".to_string(),
        vector_index_id: String::new(),
        name: manifest.name.clone(),
        owner: manifest.owner.clone(),
        embedding_set_ref: format!("local://embedding-set/{}", manifest.vector_store_id),
        document_collection_refs: manifest.document_collection_refs.clone(),
        chunk_set_refs: vec![manifest.chunking_strategy_ref.clone()],
        embedding_model_ref: manifest.embedding_model_ref.clone(),
        index_format: manifest.index_format.clone(),
        backend: VectorIndexBackendV2::SwarmStatic,
        dimensions: manifest.dimensions,
        metric: manifest.metric.clone(),
        access_policy: manifest.access_policy.clone(),
        storage_refs,
        refresh_policy: VectorIndexRefreshPolicyV2 {
            update_mode: DocumentCollectionUpdateModeV1::ImmutableSnapshot,
            source_feed_ref: manifest
                .document_collection_refs
                .iter()
                .find(|reference| looks_mutable_ref(reference))
                .cloned(),
            incremental_updates: false,
        },
        created_at: manifest.created_at.clone(),
        signature: None,
    };
    sign_vector_index_manifest_v2(&mut index);
    index
}

pub fn retrieval_query(
    requester: impl Into<String>,
    query: Value,
    privacy_tier: PrivacyTier,
) -> RetrievalQueryV1 {
    RetrievalQueryV1 {
        schema_version: RETRIEVAL_QUERY_SCHEMA_VERSION.to_string(),
        query_id: stable_id("retrieval-query", &query),
        requester: requester.into(),
        query,
        top_k: 5,
        filters: json!({}),
        privacy_tier,
        embedding_model_ref: None,
        trace_required: true,
    }
}

pub fn retrieval_plan(request: &RetrievalPlanningRequestV1) -> RetrievalPlanV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if request.schema_version != RETRIEVAL_PLANNING_REQUEST_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {RETRIEVAL_PLANNING_REQUEST_SCHEMA_VERSION}"),
        ));
    }
    validate_retrieval_query(&request.query, &mut issues);
    let index_verification = verify_vector_index_manifest_v2(&request.vector_index);
    issues.extend(
        index_verification
            .issues
            .into_iter()
            .map(|issue| prefix_issue("$.vectorIndex", issue)),
    );
    warnings.extend(
        index_verification
            .warnings
            .into_iter()
            .map(|issue| prefix_issue("$.vectorIndex", issue)),
    );

    let pipeline_id = request
        .rag_pipeline
        .as_ref()
        .map(|pipeline| pipeline.pipeline_id.clone());
    if let Some(pipeline) = &request.rag_pipeline {
        let pipeline_verification = verify_rag_pipeline_manifest_v2(pipeline);
        issues.extend(
            pipeline_verification
                .issues
                .into_iter()
                .map(|issue| prefix_issue("$.ragPipeline", issue)),
        );
        warnings.extend(
            pipeline_verification
                .warnings
                .into_iter()
                .map(|issue| prefix_issue("$.ragPipeline", issue)),
        );
        if !pipeline
            .vector_index_refs
            .contains(&request.vector_index.vector_index_id)
            && !pipeline
                .vector_index_refs
                .iter()
                .any(|reference| reference == &request.vector_index.embedding_set_ref)
        {
            issues.push(issue(
                "$.ragPipeline.vectorIndexRefs",
                "RAG pipeline must reference the supplied vector index id",
            ));
        }
    }

    if let Some(query_model) = request.query.embedding_model_ref.as_deref() {
        if query_model != request.vector_index.embedding_model_ref {
            issues.push(issue(
                "$.query.embeddingModelRef",
                "Query embedding model must match the vector index embedding model",
            ));
        }
    }
    if request.query.privacy_tier != request.vector_index.access_policy.privacy_tier {
        warnings.push(issue(
            "$.query.privacyTier",
            "Query privacy tier differs from the vector index access policy",
        ));
    }

    let mut immutable_refs = Vec::new();
    let mut mutable_refs = Vec::new();
    append_split_refs(
        &request.vector_index.document_collection_refs,
        &mut immutable_refs,
        &mut mutable_refs,
    );
    append_split_refs(
        &request.vector_index.chunk_set_refs,
        &mut immutable_refs,
        &mut mutable_refs,
    );
    append_split_refs(
        std::slice::from_ref(&request.vector_index.embedding_model_ref),
        &mut immutable_refs,
        &mut mutable_refs,
    );
    for storage_ref in &request.vector_index.storage_refs {
        append_split_ref(
            &storage_ref.reference,
            &mut immutable_refs,
            &mut mutable_refs,
        );
    }
    if let Some(pipeline) = &request.rag_pipeline {
        append_split_refs(
            &pipeline.document_collection_refs,
            &mut immutable_refs,
            &mut mutable_refs,
        );
        append_split_refs(
            &pipeline.vector_index_refs,
            &mut immutable_refs,
            &mut mutable_refs,
        );
        append_split_refs(
            &[
                pipeline.retriever_ref.clone(),
                pipeline.generator_package_ref.clone(),
            ],
            &mut immutable_refs,
            &mut mutable_refs,
        );
    }
    immutable_refs.sort();
    immutable_refs.dedup();
    mutable_refs.sort();
    mutable_refs.dedup();

    let mut embedding_model_refs = vec![request.vector_index.embedding_model_ref.clone()];
    if let Some(query_model) = request.query.embedding_model_ref.clone() {
        embedding_model_refs.push(query_model);
    }
    embedding_model_refs.sort();
    embedding_model_refs.dedup();

    let execution_mode = match &request.vector_index.backend {
        VectorIndexBackendV2::BrowserMemory => RetrievalExecutionModeV1::BrowserLocal,
        VectorIndexBackendV2::LocalService => RetrievalExecutionModeV1::LocalService,
        VectorIndexBackendV2::RemoteService => RetrievalExecutionModeV1::RemoteService,
        VectorIndexBackendV2::MinerHosted => RetrievalExecutionModeV1::MinerHosted,
        VectorIndexBackendV2::SwarmStatic => RetrievalExecutionModeV1::StaticIndexReplay,
    };

    let plan_seed = json!({
        "queryId": request.query.query_id,
        "vectorIndexId": request.vector_index.vector_index_id,
        "pipelineId": pipeline_id,
        "topK": request.query.top_k,
    });
    let valid = issues.is_empty();
    RetrievalPlanV1 {
        schema_version: RETRIEVAL_PLAN_SCHEMA_VERSION.to_string(),
        object_kind: "retrieval_plan".to_string(),
        plan_id: stable_id("retrieval-plan", &plan_seed),
        query_id: request.query.query_id.clone(),
        pipeline_id,
        vector_index_refs: vec![request.vector_index.vector_index_id.clone()],
        document_collection_refs: request.vector_index.document_collection_refs.clone(),
        embedding_model_refs,
        immutable_refs,
        mutable_refs,
        api_surface: if request.rag_pipeline.is_some() {
            ApiSurface::RagQuery
        } else {
            ApiSurface::VectorSearch
        },
        top_k: request.query.top_k,
        privacy_tier: request.query.privacy_tier.clone(),
        access_grant_required: request.vector_index.access_policy.access_grant_required,
        execution_mode,
        citation_trace_required: request.query.trace_required
            || request
                .rag_pipeline
                .as_ref()
                .is_some_and(|pipeline| pipeline.citation_policy == CitationPolicyV1::Required),
        valid,
        issues,
        warnings,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn expected_document_collection_signature(manifest: &DocumentCollectionManifestV1) -> String {
    expected_knowledge_signature(
        "document-collection",
        &document_collection_signing_value(manifest),
    )
}

pub fn expected_chunk_set_signature(manifest: &ChunkSetManifestV1) -> String {
    expected_knowledge_signature("chunk-set", &chunk_set_signing_value(manifest))
}

pub fn expected_embedding_set_signature(manifest: &EmbeddingSetManifestV1) -> String {
    expected_knowledge_signature("embedding-set", &embedding_set_signing_value(manifest))
}

pub fn expected_vector_index_v2_signature(manifest: &VectorIndexManifestV2) -> String {
    expected_knowledge_signature("vector-index-v2", &vector_index_v2_signing_value(manifest))
}

pub fn expected_rag_pipeline_v2_signature(manifest: &RagPipelineManifestV2) -> String {
    expected_knowledge_signature("rag-pipeline-v2", &rag_pipeline_v2_signing_value(manifest))
}

pub fn expected_citation_trace_signature(trace: &CitationTraceV1) -> String {
    expected_knowledge_signature("citation-trace", &citation_trace_signing_value(trace))
}

pub fn canonical_document_collection_id(manifest: &DocumentCollectionManifestV1) -> String {
    stable_id(
        "document-collection",
        &document_collection_signing_value(manifest),
    )
}

pub fn canonical_chunk_set_id(manifest: &ChunkSetManifestV1) -> String {
    stable_id("chunk-set", &chunk_set_signing_value(manifest))
}

pub fn canonical_embedding_set_id(manifest: &EmbeddingSetManifestV1) -> String {
    stable_id("embedding-set", &embedding_set_signing_value(manifest))
}

pub fn canonical_vector_index_v2_id(manifest: &VectorIndexManifestV2) -> String {
    stable_id("vector-index", &vector_index_v2_signing_value(manifest))
}

pub fn canonical_rag_pipeline_v2_id(manifest: &RagPipelineManifestV2) -> String {
    stable_id("rag-pipeline", &rag_pipeline_v2_signing_value(manifest))
}

pub fn canonical_citation_trace_id(trace: &CitationTraceV1) -> String {
    stable_id("citation-trace", &citation_trace_signing_value(trace))
}

pub fn verify_document_collection_manifest(
    manifest: &DocumentCollectionManifestV1,
) -> KnowledgeAssetVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    verify_schema_and_kind(
        &mut issues,
        &manifest.schema_version,
        DOCUMENT_COLLECTION_SCHEMA_VERSION,
        &manifest.object_kind,
        "document_collection",
    );
    verify_id(
        &mut issues,
        "$.collectionId",
        &manifest.collection_id,
        &canonical_document_collection_id(manifest),
        "Document collection id does not match canonical signed content",
    );
    require_non_empty(&mut issues, "$.name", &manifest.name);
    require_non_empty(&mut issues, "$.owner", &manifest.owner);
    require_non_empty(&mut issues, "$.summary", &manifest.summary);
    if manifest.documents.is_empty() {
        issues.push(issue(
            "$.documents",
            "Document collection must include at least one document",
        ));
    }
    for (index, document) in manifest.documents.iter().enumerate() {
        require_non_empty_owned(
            &mut issues,
            format!("$.documents[{index}].documentId"),
            &document.document_id,
        );
        require_non_empty_owned(
            &mut issues,
            format!("$.documents[{index}].sourceRef"),
            &document.source_ref,
        );
        validate_ref(
            &mut warnings,
            format!("$.documents[{index}].sourceRef"),
            &document.source_ref,
        );
        validate_rfc3339_owned(
            &mut issues,
            format!("$.documents[{index}].createdAt"),
            &document.created_at,
        );
    }
    if matches!(
        manifest.access_policy.visibility,
        VectorAccessVisibility::Private
            | VectorAccessVisibility::Organization
            | VectorAccessVisibility::TokenGated
    ) && !manifest.access_policy.access_grant_required
    {
        warnings.push(issue(
            "$.accessPolicy.accessGrantRequired",
            "Private or gated document collections should normally require an access grant",
        ));
    }
    validate_knowledge_refs(&mut warnings, "$.storageRefs", &manifest.storage_refs);
    if let Some(feed_ref) = manifest.feed_ref.as_deref() {
        validate_ref(&mut warnings, "$.feedRef", feed_ref);
    }
    validate_rfc3339(&mut issues, "$.createdAt", &manifest.created_at);
    let mut expected_signature = Some(expected_document_collection_signature(manifest));
    verify_knowledge_signature(
        &mut issues,
        &mut warnings,
        manifest.signature.as_deref(),
        &mut expected_signature,
        "document-collection",
        &document_collection_signing_value(manifest),
        Some(&manifest.owner),
    );
    knowledge_verification(
        "document_collection",
        &manifest.collection_id,
        issues,
        warnings,
        expected_signature,
    )
}

pub fn verify_chunk_set_manifest(manifest: &ChunkSetManifestV1) -> KnowledgeAssetVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    verify_schema_and_kind(
        &mut issues,
        &manifest.schema_version,
        CHUNK_SET_SCHEMA_VERSION,
        &manifest.object_kind,
        "chunk_set",
    );
    verify_id(
        &mut issues,
        "$.chunkSetId",
        &manifest.chunk_set_id,
        &canonical_chunk_set_id(manifest),
        "Chunk set id does not match canonical signed content",
    );
    require_non_empty(&mut issues, "$.collectionRef", &manifest.collection_ref);
    validate_ref(&mut warnings, "$.collectionRef", &manifest.collection_ref);
    if manifest.chunking_strategy.target_tokens == 0 {
        issues.push(issue(
            "$.chunkingStrategy.targetTokens",
            "Chunking strategy targetTokens must be greater than zero",
        ));
    }
    if manifest.chunking_strategy.overlap_tokens >= manifest.chunking_strategy.target_tokens {
        issues.push(issue(
            "$.chunkingStrategy.overlapTokens",
            "Chunk overlap must be smaller than targetTokens",
        ));
    }
    if manifest.chunk_count == 0 {
        issues.push(issue(
            "$.chunkCount",
            "Chunk set must describe at least one chunk",
        ));
    }
    if manifest.chunk_refs.is_empty() {
        issues.push(issue(
            "$.chunkRefs",
            "Chunk set must include chunk storage references",
        ));
    }
    validate_knowledge_refs(&mut warnings, "$.chunkRefs", &manifest.chunk_refs);
    validate_optional_ref(
        &mut warnings,
        "$.metadataRef",
        manifest.metadata_ref.as_deref(),
    );
    validate_rfc3339(&mut issues, "$.createdAt", &manifest.created_at);
    let mut expected_signature = Some(expected_chunk_set_signature(manifest));
    verify_knowledge_signature(
        &mut issues,
        &mut warnings,
        manifest.signature.as_deref(),
        &mut expected_signature,
        "chunk-set",
        &chunk_set_signing_value(manifest),
        None,
    );
    knowledge_verification(
        "chunk_set",
        &manifest.chunk_set_id,
        issues,
        warnings,
        expected_signature,
    )
}

pub fn verify_embedding_set_manifest(
    manifest: &EmbeddingSetManifestV1,
) -> KnowledgeAssetVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    verify_schema_and_kind(
        &mut issues,
        &manifest.schema_version,
        EMBEDDING_SET_SCHEMA_VERSION,
        &manifest.object_kind,
        "embedding_set",
    );
    verify_id(
        &mut issues,
        "$.embeddingSetId",
        &manifest.embedding_set_id,
        &canonical_embedding_set_id(manifest),
        "Embedding set id does not match canonical signed content",
    );
    require_non_empty(&mut issues, "$.chunkSetRef", &manifest.chunk_set_ref);
    require_non_empty(
        &mut issues,
        "$.embeddingModelRef",
        &manifest.embedding_model_ref,
    );
    validate_ref(&mut warnings, "$.chunkSetRef", &manifest.chunk_set_ref);
    validate_ref(
        &mut warnings,
        "$.embeddingModelRef",
        &manifest.embedding_model_ref,
    );
    if manifest.dimensions == 0 {
        issues.push(issue(
            "$.dimensions",
            "Embedding dimensions must be greater than zero",
        ));
    }
    if manifest.vector_count == 0 {
        issues.push(issue(
            "$.vectorCount",
            "Embedding set must describe at least one vector",
        ));
    }
    if manifest.embedding_refs.is_empty() {
        issues.push(issue(
            "$.embeddingRefs",
            "Embedding set must include embedding storage references",
        ));
    }
    validate_knowledge_refs(&mut warnings, "$.embeddingRefs", &manifest.embedding_refs);
    validate_rfc3339(&mut issues, "$.createdAt", &manifest.created_at);
    let mut expected_signature = Some(expected_embedding_set_signature(manifest));
    verify_knowledge_signature(
        &mut issues,
        &mut warnings,
        manifest.signature.as_deref(),
        &mut expected_signature,
        "embedding-set",
        &embedding_set_signing_value(manifest),
        None,
    );
    knowledge_verification(
        "embedding_set",
        &manifest.embedding_set_id,
        issues,
        warnings,
        expected_signature,
    )
}

pub fn verify_vector_index_manifest_v2(
    manifest: &VectorIndexManifestV2,
) -> KnowledgeAssetVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    verify_schema_and_kind(
        &mut issues,
        &manifest.schema_version,
        VECTOR_INDEX_V2_SCHEMA_VERSION,
        &manifest.object_kind,
        "vector_index",
    );
    verify_id(
        &mut issues,
        "$.vectorIndexId",
        &manifest.vector_index_id,
        &canonical_vector_index_v2_id(manifest),
        "Vector index id does not match canonical signed content",
    );
    require_non_empty(&mut issues, "$.name", &manifest.name);
    require_non_empty(&mut issues, "$.owner", &manifest.owner);
    require_non_empty(
        &mut issues,
        "$.embeddingSetRef",
        &manifest.embedding_set_ref,
    );
    require_non_empty(
        &mut issues,
        "$.embeddingModelRef",
        &manifest.embedding_model_ref,
    );
    require_non_empty(&mut issues, "$.indexFormat", &manifest.index_format);
    if manifest.dimensions == 0 {
        issues.push(issue(
            "$.dimensions",
            "Vector index dimensions must be greater than zero",
        ));
    }
    if manifest.document_collection_refs.is_empty() {
        issues.push(issue(
            "$.documentCollectionRefs",
            "Vector index must reference at least one document collection",
        ));
    }
    if manifest.chunk_set_refs.is_empty() {
        issues.push(issue(
            "$.chunkSetRefs",
            "Vector index must reference at least one chunk set",
        ));
    }
    if manifest.storage_refs.is_empty() {
        issues.push(issue(
            "$.storageRefs",
            "Vector index must include index, metadata, or manifest storage references",
        ));
    }
    validate_ref(
        &mut warnings,
        "$.embeddingSetRef",
        &manifest.embedding_set_ref,
    );
    validate_ref(
        &mut warnings,
        "$.embeddingModelRef",
        &manifest.embedding_model_ref,
    );
    validate_string_refs(
        &mut warnings,
        "$.documentCollectionRefs",
        &manifest.document_collection_refs,
    );
    validate_string_refs(&mut warnings, "$.chunkSetRefs", &manifest.chunk_set_refs);
    validate_knowledge_refs(&mut warnings, "$.storageRefs", &manifest.storage_refs);
    if matches!(
        manifest.backend,
        VectorIndexBackendV2::RemoteService | VectorIndexBackendV2::MinerHosted
    ) && manifest.access_policy.privacy_tier == PrivacyTier::LocalOnly
    {
        issues.push(issue(
            "$.backend",
            "Remote or miner-hosted vector indexes cannot satisfy local-only privacy",
        ));
    }
    if manifest.refresh_policy.incremental_updates
        && manifest.refresh_policy.source_feed_ref.is_none()
        && matches!(
            &manifest.refresh_policy.update_mode,
            DocumentCollectionUpdateModeV1::FeedBacked | DocumentCollectionUpdateModeV1::AppendOnly
        )
    {
        warnings.push(issue(
            "$.refreshPolicy.sourceFeedRef",
            "Incremental vector index updates should reference a source feed",
        ));
    }
    validate_optional_ref(
        &mut warnings,
        "$.refreshPolicy.sourceFeedRef",
        manifest.refresh_policy.source_feed_ref.as_deref(),
    );
    validate_rfc3339(&mut issues, "$.createdAt", &manifest.created_at);
    let mut expected_signature = Some(expected_vector_index_v2_signature(manifest));
    verify_knowledge_signature(
        &mut issues,
        &mut warnings,
        manifest.signature.as_deref(),
        &mut expected_signature,
        "vector-index-v2",
        &vector_index_v2_signing_value(manifest),
        Some(&manifest.owner),
    );
    knowledge_verification(
        "vector_index",
        &manifest.vector_index_id,
        issues,
        warnings,
        expected_signature,
    )
}

pub fn verify_rag_pipeline_manifest_v2(
    manifest: &RagPipelineManifestV2,
) -> KnowledgeAssetVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    verify_schema_and_kind(
        &mut issues,
        &manifest.schema_version,
        RAG_PIPELINE_V2_SCHEMA_VERSION,
        &manifest.object_kind,
        "rag_pipeline",
    );
    verify_id(
        &mut issues,
        "$.pipelineId",
        &manifest.pipeline_id,
        &canonical_rag_pipeline_v2_id(manifest),
        "RAG pipeline id does not match canonical signed content",
    );
    require_non_empty(&mut issues, "$.name", &manifest.name);
    require_non_empty(&mut issues, "$.owner", &manifest.owner);
    require_non_empty(&mut issues, "$.retrieverRef", &manifest.retriever_ref);
    require_non_empty(
        &mut issues,
        "$.generatorPackageRef",
        &manifest.generator_package_ref,
    );
    if manifest.document_collection_refs.is_empty() {
        issues.push(issue(
            "$.documentCollectionRefs",
            "RAG pipeline must reference at least one document collection",
        ));
    }
    if manifest.vector_index_refs.is_empty() {
        issues.push(issue(
            "$.vectorIndexRefs",
            "RAG pipeline must reference at least one vector index",
        ));
    }
    if manifest.verification_tiers.is_empty() {
        warnings.push(issue(
            "$.verificationTiers",
            "RAG pipeline should declare verification tiers for answer and citation validation",
        ));
    }
    if manifest.stages.is_empty() {
        issues.push(issue(
            "$.stages",
            "RAG pipeline must describe retrieval, generation, and citation stages",
        ));
    }
    if manifest.citation_policy == CitationPolicyV1::Required
        && !manifest
            .stages
            .iter()
            .any(|stage| stage.stage_kind == RagPipelineStageKindV2::CiteSources)
    {
        issues.push(issue(
            "$.stages",
            "Required citation policy must include a cite-sources stage",
        ));
    }
    if matches!(
        manifest.access_policy.visibility,
        VectorAccessVisibility::Private
            | VectorAccessVisibility::Organization
            | VectorAccessVisibility::TokenGated
    ) && !manifest.access_policy.access_grant_required
    {
        warnings.push(issue(
            "$.accessPolicy.accessGrantRequired",
            "Private or gated RAG pipelines should normally require an access grant",
        ));
    }
    validate_string_refs(
        &mut warnings,
        "$.documentCollectionRefs",
        &manifest.document_collection_refs,
    );
    validate_string_refs(
        &mut warnings,
        "$.vectorIndexRefs",
        &manifest.vector_index_refs,
    );
    validate_ref(&mut warnings, "$.retrieverRef", &manifest.retriever_ref);
    validate_ref(
        &mut warnings,
        "$.generatorPackageRef",
        &manifest.generator_package_ref,
    );
    validate_rfc3339(&mut issues, "$.createdAt", &manifest.created_at);
    let mut expected_signature = Some(expected_rag_pipeline_v2_signature(manifest));
    verify_knowledge_signature(
        &mut issues,
        &mut warnings,
        manifest.signature.as_deref(),
        &mut expected_signature,
        "rag-pipeline-v2",
        &rag_pipeline_v2_signing_value(manifest),
        Some(&manifest.owner),
    );
    knowledge_verification(
        "rag_pipeline",
        &manifest.pipeline_id,
        issues,
        warnings,
        expected_signature,
    )
}

pub fn verify_citation_trace(trace: &CitationTraceV1) -> KnowledgeAssetVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    verify_schema_and_kind(
        &mut issues,
        &trace.schema_version,
        CITATION_TRACE_SCHEMA_VERSION,
        &trace.object_kind,
        "citation_trace",
    );
    verify_id(
        &mut issues,
        "$.traceId",
        &trace.trace_id,
        &canonical_citation_trace_id(trace),
        "Citation trace id does not match canonical signed content",
    );
    require_non_empty(&mut issues, "$.queryId", &trace.query_id);
    require_non_empty(&mut issues, "$.answerRef", &trace.answer_ref);
    validate_ref(&mut warnings, "$.answerRef", &trace.answer_ref);
    validate_optional_ref(
        &mut warnings,
        "$.retrievalPlanRef",
        trace.retrieval_plan_ref.as_deref(),
    );
    validate_optional_ref(
        &mut warnings,
        "$.pipelineRef",
        trace.pipeline_ref.as_deref(),
    );
    if trace.citations.is_empty() {
        issues.push(issue(
            "$.citations",
            "Citation trace must include at least one citation span",
        ));
    }
    for (index, citation) in trace.citations.iter().enumerate() {
        if citation.output_end <= citation.output_start {
            issues.push(issue(
                format!("$.citations[{index}].outputEnd"),
                "Citation outputEnd must be greater than outputStart",
            ));
        }
        require_non_empty_owned(
            &mut issues,
            format!("$.citations[{index}].sourceRef"),
            &citation.source_ref,
        );
        validate_ref(
            &mut warnings,
            format!("$.citations[{index}].sourceRef"),
            &citation.source_ref,
        );
        if let Some(score) = citation.score {
            if !(0.0..=1.0).contains(&score) {
                warnings.push(issue(
                    format!("$.citations[{index}].score"),
                    "Citation score should be normalized between 0 and 1",
                ));
            }
        }
        if citation.visibility == CitationVisibilityV1::Public
            && citation.quote_hash.is_none()
            && citation.chunk_id.is_none()
        {
            warnings.push(issue(
                format!("$.citations[{index}]"),
                "Public citation should include a chunk id or quote hash for provenance",
            ));
        }
    }
    validate_rfc3339(&mut issues, "$.createdAt", &trace.created_at);
    let mut expected_signature = Some(expected_citation_trace_signature(trace));
    verify_knowledge_signature(
        &mut issues,
        &mut warnings,
        trace.signature.as_deref(),
        &mut expected_signature,
        "citation-trace",
        &citation_trace_signing_value(trace),
        None,
    );
    knowledge_verification(
        "citation_trace",
        &trace.trace_id,
        issues,
        warnings,
        expected_signature,
    )
}

fn knowledge_ref_from_vector_storage_ref(storage_ref: &VectorStorageRefV1) -> KnowledgeAssetRefV1 {
    KnowledgeAssetRefV1 {
        role: match storage_ref.role {
            VectorStorageRole::Index => KnowledgeRefRoleV1::VectorIndex,
            VectorStorageRole::Metadata => KnowledgeRefRoleV1::Metadata,
            VectorStorageRole::Chunks => KnowledgeRefRoleV1::ChunkSet,
            VectorStorageRole::Documents => KnowledgeRefRoleV1::Document,
            VectorStorageRole::EmbeddingCache => KnowledgeRefRoleV1::EmbeddingSet,
            VectorStorageRole::Manifest => KnowledgeRefRoleV1::Manifest,
        },
        reference: storage_ref.reference.clone(),
        content_type: storage_ref.content_type.clone(),
        sha256: storage_ref.sha256.clone(),
        size_bytes: storage_ref.size_bytes,
    }
}

fn expected_knowledge_signature(signature_kind: &str, signing_value: &Value) -> String {
    format!(
        "{DEV_KNOWLEDGE_SIGNATURE_PREFIX}:{signature_kind}:{}",
        hash_canonical_json(&canonicalize_json(signing_value))
    )
}

fn document_collection_signing_value(manifest: &DocumentCollectionManifestV1) -> Value {
    knowledge_signing_value(manifest, "collectionId")
}

fn chunk_set_signing_value(manifest: &ChunkSetManifestV1) -> Value {
    knowledge_signing_value(manifest, "chunkSetId")
}

fn embedding_set_signing_value(manifest: &EmbeddingSetManifestV1) -> Value {
    knowledge_signing_value(manifest, "embeddingSetId")
}

fn vector_index_v2_signing_value(manifest: &VectorIndexManifestV2) -> Value {
    knowledge_signing_value(manifest, "vectorIndexId")
}

fn rag_pipeline_v2_signing_value(manifest: &RagPipelineManifestV2) -> Value {
    knowledge_signing_value(manifest, "pipelineId")
}

fn citation_trace_signing_value(trace: &CitationTraceV1) -> Value {
    knowledge_signing_value(trace, "traceId")
}

fn knowledge_signing_value(value: &impl Serialize, id_field: &str) -> Value {
    let mut value = serde_json::to_value(value).expect("knowledge object should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove(id_field);
        object.remove("signature");
    }
    value
}

fn verify_schema_and_kind(
    issues: &mut Vec<ValidationIssue>,
    schema_version: &str,
    expected_schema_version: &str,
    object_kind: &str,
    expected_object_kind: &str,
) {
    if schema_version != expected_schema_version {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {expected_schema_version}"),
        ));
    }
    if object_kind != expected_object_kind {
        issues.push(issue(
            "$.objectKind",
            format!("Expected objectKind to be {expected_object_kind}"),
        ));
    }
}

fn verify_id(
    issues: &mut Vec<ValidationIssue>,
    path: &'static str,
    actual: &str,
    expected: &str,
    message: &'static str,
) {
    require_non_empty(issues, path, actual);
    if !actual.is_empty() && actual != expected {
        issues.push(issue(path, message));
    }
}

fn require_non_empty_owned(issues: &mut Vec<ValidationIssue>, path: String, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value is required"));
    }
}

fn validate_ref(warnings: &mut Vec<ValidationIssue>, path: impl Into<String>, reference: &str) {
    let path = path.into();
    if reference.trim().is_empty() {
        return;
    }
    if !looks_like_ref(reference) {
        warnings.push(issue(
            path,
            "Reference is not a recognized bzz://, local://, ipfs://, sha256://, or https:// reference",
        ));
    }
}

fn validate_optional_ref(
    warnings: &mut Vec<ValidationIssue>,
    path: impl Into<String>,
    reference: Option<&str>,
) {
    if let Some(reference) = reference {
        validate_ref(warnings, path, reference);
    }
}

fn validate_string_refs(
    warnings: &mut Vec<ValidationIssue>,
    base_path: &str,
    references: &[String],
) {
    for (index, reference) in references.iter().enumerate() {
        validate_ref(warnings, format!("{base_path}[{index}]"), reference);
    }
}

fn validate_knowledge_refs(
    warnings: &mut Vec<ValidationIssue>,
    base_path: &str,
    references: &[KnowledgeAssetRefV1],
) {
    for (index, reference) in references.iter().enumerate() {
        validate_ref(
            warnings,
            format!("{base_path}[{index}].reference"),
            &reference.reference,
        );
    }
}

fn validate_rfc3339(issues: &mut Vec<ValidationIssue>, path: &'static str, value: &str) {
    if chrono::DateTime::parse_from_rfc3339(value).is_err() {
        issues.push(issue(path, "Timestamp must be RFC3339"));
    }
}

fn validate_rfc3339_owned(issues: &mut Vec<ValidationIssue>, path: String, value: &str) {
    if chrono::DateTime::parse_from_rfc3339(value).is_err() {
        issues.push(issue(path, "Timestamp must be RFC3339"));
    }
}

fn verify_knowledge_signature(
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
    signature: Option<&str>,
    expected_signature: &mut Option<String>,
    signature_kind: &str,
    signing_value: &Value,
    expected_signer: Option<&str>,
) {
    let signature = signature.map(str::trim).filter(|value| !value.is_empty());
    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                signature_kind,
                signing_value,
                expected_signer,
            );
            *expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(issue(
                "$.signature",
                "Signature does not match canonical dev signature or Ed25519 identity envelope",
            ));
        }
    } else {
        warnings.push(issue(
            "$.signature",
            "Knowledge object is unsigned; verify id and producer through a trusted source",
        ));
    }
}

fn knowledge_verification(
    subject_type: &str,
    subject_id: &str,
    issues: Vec<ValidationIssue>,
    warnings: Vec<ValidationIssue>,
    expected_signature: Option<String>,
) -> KnowledgeAssetVerificationV1 {
    KnowledgeAssetVerificationV1 {
        schema_version: KNOWLEDGE_ASSET_VERIFICATION_SCHEMA_VERSION.to_string(),
        object_kind: "knowledge_asset_verification".to_string(),
        subject_id: subject_id.to_string(),
        subject_type: subject_type.to_string(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

fn prefix_issue(prefix: &str, issue: ValidationIssue) -> ValidationIssue {
    let path = if issue.path == "$" {
        prefix.to_string()
    } else if let Some(rest) = issue.path.strip_prefix('$') {
        format!("{prefix}{rest}")
    } else {
        format!("{prefix}.{}", issue.path)
    };
    ValidationIssue {
        path,
        message: issue.message,
    }
}

#[derive(Debug, Clone)]
struct RawTextChunk {
    ordinal: u64,
    text: String,
    start_char: u64,
    end_char: u64,
    token_count: u32,
}

fn default_text_content_type() -> String {
    "text/plain".to_string()
}

fn default_document_sensitivity() -> DocumentSensitivityV1 {
    DocumentSensitivityV1::Public
}

fn default_rag_chunking_strategy() -> ChunkingStrategyV1 {
    ChunkingStrategyV1 {
        strategy_kind: ChunkingStrategyKindV1::FixedTokens,
        target_tokens: 160,
        overlap_tokens: 24,
        separators: vec!["\n\n".to_string(), "\n".to_string(), " ".to_string()],
        tokenizer_ref: Some("local://tokenizers/whitespace".to_string()),
    }
}

fn default_rag_embedding_model_ref() -> String {
    "local://embeddings/mock-deterministic-v1".to_string()
}

fn default_rag_dimensions() -> u32 {
    64
}

fn default_rag_metric() -> VectorMetric {
    VectorMetric::Cosine
}

fn default_top_k() -> u32 {
    5
}

fn default_privacy_tier() -> PrivacyTier {
    PrivacyTier::Standard
}

fn rag_supports_text_content_type(content_type: &str) -> bool {
    matches!(
        content_type.trim().to_ascii_lowercase().as_str(),
        "text/plain" | "text/markdown" | "text/x-markdown" | "application/markdown"
    )
}

fn access_policy_allows(policy: &VectorAccessPolicyV1, access_grant_refs: &[String]) -> bool {
    if !policy.access_grant_required && matches!(policy.visibility, VectorAccessVisibility::Public)
    {
        return true;
    }
    if policy.access_grant_required {
        return access_grant_refs
            .iter()
            .any(|reference| !reference.trim().is_empty());
    }
    !matches!(
        policy.visibility,
        VectorAccessVisibility::Private
            | VectorAccessVisibility::Organization
            | VectorAccessVisibility::TokenGated
    )
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_json(value: &impl Serialize) -> String {
    sha256_hex_bytes(&serde_json::to_vec(value).unwrap_or_default())
}

fn serde_json_len(value: &impl Serialize) -> u64 {
    serde_json::to_vec(value)
        .unwrap_or_default()
        .len()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn issue_summary(issues: &[ValidationIssue]) -> String {
    issues
        .iter()
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect::<Vec<_>>()
        .join("; ")
}

fn chunk_document_text(text: &str, target_tokens: u32, overlap_tokens: u32) -> Vec<RawTextChunk> {
    let tokens = token_spans(text);
    if tokens.is_empty() || target_tokens == 0 || overlap_tokens >= target_tokens {
        return Vec::new();
    }
    let target = target_tokens as usize;
    let overlap = overlap_tokens as usize;
    let step = target.saturating_sub(overlap).max(1);
    let mut chunks = Vec::new();
    let mut start = 0usize;
    let mut ordinal = 0u64;
    while start < tokens.len() {
        let end = (start + target).min(tokens.len());
        let byte_start = tokens[start].1;
        let byte_end = tokens[end - 1].2;
        let chunk_text = text[byte_start..byte_end].trim().to_string();
        if !chunk_text.is_empty() {
            chunks.push(RawTextChunk {
                ordinal,
                text: chunk_text,
                start_char: text[..byte_start]
                    .chars()
                    .count()
                    .try_into()
                    .unwrap_or(u64::MAX),
                end_char: text[..byte_end]
                    .chars()
                    .count()
                    .try_into()
                    .unwrap_or(u64::MAX),
                token_count: (end - start).try_into().unwrap_or(u32::MAX),
            });
            ordinal += 1;
        }
        if end == tokens.len() {
            break;
        }
        start += step;
    }
    chunks
}

fn token_spans(text: &str) -> Vec<(&str, usize, usize)> {
    let mut spans = Vec::new();
    let mut token_start: Option<usize> = None;
    for (index, character) in text.char_indices() {
        if character.is_whitespace() {
            if let Some(start) = token_start.take() {
                spans.push((&text[start..index], start, index));
            }
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }
    if let Some(start) = token_start {
        spans.push((&text[start..], start, text.len()));
    }
    spans
}

fn deterministic_embedding_vector(text: &str, model_ref: &str, dimensions: u32) -> Vec<f32> {
    let dimensions = dimensions.max(1) as usize;
    let mut vector = Vec::with_capacity(dimensions);
    for index in 0..dimensions {
        let mut hasher = Sha256::new();
        hasher.update(model_ref.as_bytes());
        hasher.update([0]);
        hasher.update(text.as_bytes());
        hasher.update([0]);
        hasher.update(index.to_le_bytes());
        let digest = hasher.finalize();
        let value = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        let scaled = (value as f64 / u32::MAX as f64) * 2.0 - 1.0;
        vector.push(scaled as f32);
    }
    let norm = vector
        .iter()
        .map(|value| (*value as f64) * (*value as f64))
        .sum::<f64>()
        .sqrt();
    if norm > 0.0 {
        for value in &mut vector {
            *value = (*value as f64 / norm) as f32;
        }
    }
    vector
}

fn cosine_score(left: &[f32], right: &[f32]) -> f64 {
    let len = left.len().min(right.len());
    if len == 0 {
        return 0.0;
    }
    let mut dot = 0.0;
    let mut left_norm = 0.0;
    let mut right_norm = 0.0;
    for index in 0..len {
        let left_value = left[index] as f64;
        let right_value = right[index] as f64;
        dot += left_value * right_value;
        left_norm += left_value * left_value;
        right_norm += right_value * right_value;
    }
    if left_norm == 0.0 || right_norm == 0.0 {
        return 0.0;
    }
    ((dot / left_norm.sqrt() / right_norm.sqrt()) + 1.0) / 2.0
}

fn compact_excerpt(text: &str, max_chars: usize) -> String {
    let mut excerpt = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if excerpt.chars().count() > max_chars {
        excerpt = excerpt.chars().take(max_chars).collect::<String>();
        excerpt.push_str("...");
    }
    excerpt
}

fn sanitize_path_id(value: &str) -> String {
    let mut sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while sanitized.contains("--") {
        sanitized = sanitized.replace("--", "-");
    }
    let sanitized = sanitized.trim_matches('-').to_string();
    if sanitized.is_empty() {
        "default".to_string()
    } else {
        sanitized
    }
}

fn validate_retrieval_query(query: &RetrievalQueryV1, issues: &mut Vec<ValidationIssue>) {
    if query.schema_version != RETRIEVAL_QUERY_SCHEMA_VERSION {
        issues.push(issue(
            "$.query.schemaVersion",
            format!("Expected schemaVersion to be {RETRIEVAL_QUERY_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(issues, "$.query.queryId", &query.query_id);
    require_non_empty(issues, "$.query.requester", &query.requester);
    if query.query.is_null() {
        issues.push(issue("$.query.query", "Retrieval query must not be null"));
    }
    if query.top_k == 0 {
        issues.push(issue("$.query.topK", "topK must be greater than zero"));
    }
}

fn append_split_refs(
    references: &[String],
    immutable_refs: &mut Vec<String>,
    mutable_refs: &mut Vec<String>,
) {
    for reference in references {
        append_split_ref(reference, immutable_refs, mutable_refs);
    }
}

fn append_split_ref(
    reference: &str,
    immutable_refs: &mut Vec<String>,
    mutable_refs: &mut Vec<String>,
) {
    if reference.trim().is_empty() {
        return;
    }
    if looks_mutable_ref(reference) {
        mutable_refs.push(reference.to_string());
    } else {
        immutable_refs.push(reference.to_string());
    }
}

fn collect_vector_store_files(vector_dir: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    if !vector_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(vector_dir)
        .with_context(|| format!("failed to read {}", vector_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_vector_store_files(&path, files)?;
        } else if file_type.is_file() && is_json_path(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_json_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
}

fn read_vector_store_file(path: &Path) -> anyhow::Result<Option<VectorStoreManifestV1>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    if schema_version != "swarm-ai.vector-store.v1" {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .with_context(|| format!("failed to parse vector store manifest {}", path.display()))
}

fn vector_store_index_entry(
    manifest: &VectorStoreManifestV1,
    verification: &VectorStoreVerificationV1,
    plan: &VectorSearchPlanV1,
    manifest_path: String,
) -> VectorStoreIndexEntryV1 {
    VectorStoreIndexEntryV1 {
        vector_store_id: manifest.vector_store_id.clone(),
        name: manifest.name.clone(),
        owner: manifest.owner.clone(),
        visibility: manifest.access_policy.visibility.clone(),
        privacy_tier: manifest.access_policy.privacy_tier.clone(),
        access_grant_required: manifest.access_policy.access_grant_required,
        embedding_model_ref: manifest.embedding_model_ref.clone(),
        index_format: manifest.index_format.clone(),
        dimensions: manifest.dimensions,
        metric: manifest.metric.clone(),
        document_collection_count: manifest.document_collection_refs.len(),
        storage_ref_count: manifest.storage_refs.len(),
        mutable_ref_count: plan.mutable_refs.len(),
        warning_count: verification.warnings.len() + plan.warnings.len(),
        valid: verification.valid,
        signature_present: manifest.signature.is_some(),
        created_at: manifest.created_at.clone(),
        manifest_path,
    }
}

fn audit_vector_search_plan(manifest: &VectorStoreManifestV1) -> VectorSearchPlanV1 {
    let vector_store_ref = manifest
        .storage_refs
        .iter()
        .find(|storage_ref| matches!(storage_ref.role, VectorStorageRole::Manifest))
        .or_else(|| manifest.storage_refs.first())
        .map(|storage_ref| storage_ref.reference.clone())
        .unwrap_or_else(|| manifest.vector_store_id.clone());
    let mut request = vector_search_request(
        vector_store_ref,
        manifest.vector_store_id.clone(),
        "local-audit",
        json!({ "text": "audit" }),
    );
    request.privacy_tier = manifest.access_policy.privacy_tier.clone();
    vector_search_plan(manifest, &request)
}

fn vector_store_signing_value(manifest: &VectorStoreManifestV1) -> Value {
    let mut value = serde_json::to_value(manifest).expect("vector store manifest should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("vectorStoreId");
        object.remove("signature");
    }
    value
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("vector object should serialize");
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

fn require_non_empty(issues: &mut Vec<ValidationIssue>, path: &'static str, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value is required"));
    }
}

fn manifest_refs(manifest: &VectorStoreManifestV1) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    refs.push((
        "$.embeddingModelRef".to_string(),
        manifest.embedding_model_ref.clone(),
    ));
    refs.push((
        "$.chunkingStrategyRef".to_string(),
        manifest.chunking_strategy_ref.clone(),
    ));
    append_refs(
        &mut refs,
        "$.documentCollectionRefs",
        &manifest.document_collection_refs,
    );
    for (index, storage_ref) in manifest.storage_refs.iter().enumerate() {
        refs.push((
            format!("$.storageRefs[{index}].reference"),
            storage_ref.reference.clone(),
        ));
    }
    refs
}

fn append_refs(refs: &mut Vec<(String, String)>, base_path: &str, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        refs.push((format!("{base_path}[{index}]"), value.clone()));
    }
}

fn looks_like_ref(reference: &str) -> bool {
    reference.starts_with("bzz://")
        || reference.starts_with("local://")
        || reference.starts_with("ipfs://")
        || reference.starts_with("sha256://")
        || reference.starts_with("https://")
}

fn looks_mutable_ref(reference: &str) -> bool {
    reference.starts_with("https://")
        || reference.contains(":latest")
        || reference.contains("/latest")
        || reference.contains(":stable")
        || reference.contains("/stable")
}

fn signature_issue_path(path: &str) -> String {
    if path == "$" {
        return "$.signature".to_string();
    }
    if let Some(rest) = path.strip_prefix("$.") {
        return format!("$.signature.{rest}");
    }
    format!("$.signature.{path}")
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_signed_vector_store_manifest() {
        let manifest = create_vector_store_manifest(VectorStoreInitOptionsV1 {
            name: "Company Docs".to_string(),
            owner: "0xVectorOwner".to_string(),
            embedding_model_ref: "bzz://embedding-model".to_string(),
            document_collection_refs: vec!["bzz://docs".to_string()],
            index_format: Some("hnsw".to_string()),
            dimensions: 1536,
            metric: Some(VectorMetric::Cosine),
            chunking_strategy_ref: Some("bzz://chunking".to_string()),
            storage_refs: vec![VectorStorageRefV1 {
                role: VectorStorageRole::Index,
                reference: "bzz://index".to_string(),
                content_type: Some("application/octet-stream".to_string()),
                sha256: None,
                size_bytes: Some(42),
            }],
            access_policy: None,
        });

        let verification = verify_vector_store_manifest(&manifest);

        assert!(verification.valid, "{verification:#?}");
        assert!(manifest.vector_store_id.starts_with("vector-store-"));
        assert_eq!(
            manifest.signature.as_deref(),
            Some(expected_vector_store_signature(&manifest).as_str())
        );
    }

    #[test]
    fn identity_signed_vector_store_verifies_and_detects_tampering() {
        let mut manifest = manifest();
        let identity =
            hivemind_identity::identity_from_seed("0xVectorOwner", b"vector-owner-seed").unwrap();

        let envelope = sign_vector_store_with_identity(&mut manifest, &identity).unwrap();
        let verification = verify_vector_store_manifest(&manifest);

        assert_eq!(envelope.signer, manifest.owner);
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .as_deref()
                .unwrap()
                .starts_with("ed25519-payload-hash:")
        );

        manifest.dimensions = 768;
        let tampered = verify_vector_store_manifest(&manifest);
        assert!(!tampered.valid);
        assert!(tampered.issues.iter().any(|issue| {
            issue.path == "$.vectorStoreId" || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn vector_search_plan_reports_mutable_refs_and_request_mismatch() {
        let mut manifest = manifest();
        manifest
            .document_collection_refs
            .push("https://example.com/latest".to_string());
        sign_vector_store_manifest(&mut manifest);
        let mut request = vector_search_request(
            "bzz://vector-store-manifest",
            "wrong-id",
            "local-dev",
            json!({ "text": "find policy documents" }),
        );
        request.top_k = 3;

        let plan = vector_search_plan(&manifest, &request);

        assert!(!plan.valid);
        assert!(
            plan.issues
                .iter()
                .any(|issue| issue.path == "$.request.vectorStoreId")
        );
        assert!(
            plan.mutable_refs
                .contains(&"https://example.com/latest".to_string())
        );
    }

    #[test]
    fn unsigned_vector_store_still_requires_canonical_id() {
        let mut manifest = manifest();
        manifest.signature = None;
        manifest.index_format = "changed".to_string();

        let verification = verify_vector_store_manifest(&manifest);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.vectorStoreId")
        );
    }

    #[test]
    fn vector_store_manifest_store_lists_and_gets_manifests() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("hivemind-vector-store-{unique}"));
        fs::create_dir_all(dir.join("nested")).unwrap();

        let mut manifest = manifest();
        manifest.document_collection_refs = vec![
            "bzz://docs".to_string(),
            "https://example.com/docs/latest".to_string(),
        ];
        manifest.access_policy.visibility = VectorAccessVisibility::Private;
        manifest.access_policy.access_grant_required = true;
        sign_vector_store_manifest(&mut manifest);

        fs::write(
            dir.join("nested").join("company-docs.vector.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("identity.json"),
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": "swarm-ai.identity.keypair.v1",
                "subject": "0xVectorOwner"
            }))
            .unwrap(),
        )
        .unwrap();

        let summary = list_vector_store_manifests(&dir).unwrap();
        assert_eq!(summary.vector_store_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.invalid_count, 0);
        assert_eq!(summary.private_count, 1);
        assert_eq!(summary.access_grant_required_count, 1);
        assert_eq!(summary.mutable_ref_count, 1);
        assert!(summary.warning_count > 0);
        assert_eq!(
            summary.vector_stores[0].vector_store_id,
            manifest.vector_store_id
        );
        assert_eq!(summary.vector_stores[0].document_collection_count, 2);
        assert!(summary.vector_stores[0].signature_present);

        let lookup = get_vector_store_manifest(&dir, &manifest.vector_store_id)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.manifest.vector_store_id, manifest.vector_store_id);
        assert!(lookup.verification.valid, "{:#?}", lookup.verification);
        assert_eq!(lookup.audit_search_plan.mutable_refs.len(), 1);
        assert!(
            get_vector_store_manifest(&dir, "missing")
                .unwrap()
                .is_none()
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn review4_knowledge_assets_verify_plan_and_cite_sources() {
        let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let mut collection = DocumentCollectionManifestV1 {
            schema_version: DOCUMENT_COLLECTION_SCHEMA_VERSION.to_string(),
            object_kind: "document_collection".to_string(),
            collection_id: String::new(),
            name: "Security Handbook".to_string(),
            owner: "0xVectorOwner".to_string(),
            summary: "Internal security policies prepared for RAG retrieval".to_string(),
            update_mode: DocumentCollectionUpdateModeV1::FeedBacked,
            documents: vec![DocumentAssetV1 {
                document_id: "doc-security-policy".to_string(),
                title: "Security Policy".to_string(),
                source_ref: "bzz://docs/security-policy.pdf".to_string(),
                content_type: "application/pdf".to_string(),
                sha256: Some("sha256-security-policy".to_string()),
                size_bytes: Some(2048),
                language: Some("en".to_string()),
                metadata: json!({ "department": "security" }),
                sensitivity: DocumentSensitivityV1::Internal,
                license_ref: Some("local://license/internal".to_string()),
                created_at: created_at.clone(),
            }],
            metadata_schema: json!({ "type": "object" }),
            access_policy: VectorAccessPolicyV1 {
                visibility: VectorAccessVisibility::Organization,
                privacy_tier: PrivacyTier::Standard,
                access_grant_required: true,
                license_ref: Some("local://license/internal".to_string()),
                redaction_policy_ref: None,
            },
            storage_refs: vec![KnowledgeAssetRefV1 {
                role: KnowledgeRefRoleV1::Manifest,
                reference: "bzz://collections/security-handbook".to_string(),
                content_type: Some("application/json".to_string()),
                sha256: None,
                size_bytes: None,
            }],
            feed_ref: Some("bzz://feeds/security-handbook".to_string()),
            created_at: created_at.clone(),
            signature: None,
        };
        sign_document_collection_manifest(&mut collection);
        assert!(
            verify_document_collection_manifest(&collection).valid,
            "{:#?}",
            verify_document_collection_manifest(&collection)
        );

        let mut chunk_set = ChunkSetManifestV1 {
            schema_version: CHUNK_SET_SCHEMA_VERSION.to_string(),
            object_kind: "chunk_set".to_string(),
            chunk_set_id: String::new(),
            collection_ref: format!("local://collections/{}", collection.collection_id),
            collection_id: Some(collection.collection_id.clone()),
            chunking_strategy: ChunkingStrategyV1 {
                strategy_kind: ChunkingStrategyKindV1::MarkdownSection,
                target_tokens: 512,
                overlap_tokens: 64,
                separators: vec!["##".to_string(), "\n\n".to_string()],
                tokenizer_ref: Some("bzz://tokenizers/default".to_string()),
            },
            chunk_count: 2,
            chunk_refs: vec![KnowledgeAssetRefV1 {
                role: KnowledgeRefRoleV1::ChunkSet,
                reference: "bzz://chunks/security-policy.jsonl".to_string(),
                content_type: Some("application/jsonl".to_string()),
                sha256: None,
                size_bytes: Some(4096),
            }],
            metadata_ref: Some("bzz://chunks/security-policy.metadata.json".to_string()),
            created_at: created_at.clone(),
            signature: None,
        };
        sign_chunk_set_manifest(&mut chunk_set);
        assert!(
            verify_chunk_set_manifest(&chunk_set).valid,
            "{:#?}",
            verify_chunk_set_manifest(&chunk_set)
        );

        let mut embedding_set = EmbeddingSetManifestV1 {
            schema_version: EMBEDDING_SET_SCHEMA_VERSION.to_string(),
            object_kind: "embedding_set".to_string(),
            embedding_set_id: String::new(),
            chunk_set_ref: format!("local://chunk-sets/{}", chunk_set.chunk_set_id),
            embedding_model_ref: "bzz://models/security-embedding".to_string(),
            dimensions: 1536,
            metric: VectorMetric::Cosine,
            precision: EmbeddingVectorPrecisionV1::Float32,
            vector_count: 2,
            embedding_refs: vec![KnowledgeAssetRefV1 {
                role: KnowledgeRefRoleV1::EmbeddingSet,
                reference: "bzz://embeddings/security-policy.f32".to_string(),
                content_type: Some("application/octet-stream".to_string()),
                sha256: None,
                size_bytes: Some(8192),
            }],
            created_at: created_at.clone(),
            signature: None,
        };
        sign_embedding_set_manifest(&mut embedding_set);
        assert!(
            verify_embedding_set_manifest(&embedding_set).valid,
            "{:#?}",
            verify_embedding_set_manifest(&embedding_set)
        );

        let mut index = vector_index_v2_from_vector_store(&manifest());
        index.embedding_set_ref =
            format!("local://embedding-sets/{}", embedding_set.embedding_set_id);
        index.embedding_model_ref = embedding_set.embedding_model_ref.clone();
        index.document_collection_refs =
            vec![format!("local://collections/{}", collection.collection_id)];
        index.chunk_set_refs = vec![format!("local://chunk-sets/{}", chunk_set.chunk_set_id)];
        index.storage_refs = vec![KnowledgeAssetRefV1 {
            role: KnowledgeRefRoleV1::VectorIndex,
            reference: "bzz://indexes/security-policy.hnsw".to_string(),
            content_type: Some("application/octet-stream".to_string()),
            sha256: None,
            size_bytes: Some(8192),
        }];
        sign_vector_index_manifest_v2(&mut index);
        assert!(
            verify_vector_index_manifest_v2(&index).valid,
            "{:#?}",
            verify_vector_index_manifest_v2(&index)
        );

        let mut pipeline = RagPipelineManifestV2 {
            schema_version: RAG_PIPELINE_V2_SCHEMA_VERSION.to_string(),
            object_kind: "rag_pipeline".to_string(),
            pipeline_id: String::new(),
            name: "Security Handbook RAG".to_string(),
            owner: "0xVectorOwner".to_string(),
            document_collection_refs: index.document_collection_refs.clone(),
            vector_index_refs: vec![index.vector_index_id.clone()],
            retriever_ref: "local://retrievers/hnsw".to_string(),
            generator_package_ref: "bzz://packages/security-answerer".to_string(),
            citation_policy: CitationPolicyV1::Required,
            answer_output_schema: json!({ "type": "object" }),
            access_policy: index.access_policy.clone(),
            privacy_tier: PrivacyTier::Standard,
            verification_tiers: vec![
                IntegrityTier::ValidatorSpotCheck,
                IntegrityTier::DeterministicReplay,
            ],
            stages: vec![
                RagPipelineStageV2 {
                    stage_id: "retrieve".to_string(),
                    stage_kind: RagPipelineStageKindV2::Retrieve,
                    input_refs: vec![index.vector_index_id.clone()],
                    output_ref: Some("local://rag/retrieval-results".to_string()),
                    required: true,
                },
                RagPipelineStageV2 {
                    stage_id: "cite".to_string(),
                    stage_kind: RagPipelineStageKindV2::CiteSources,
                    input_refs: vec!["local://rag/retrieval-results".to_string()],
                    output_ref: Some("local://rag/citation-trace".to_string()),
                    required: true,
                },
            ],
            created_at: created_at.clone(),
            signature: None,
        };
        sign_rag_pipeline_manifest_v2(&mut pipeline);
        assert!(
            verify_rag_pipeline_manifest_v2(&pipeline).valid,
            "{:#?}",
            verify_rag_pipeline_manifest_v2(&pipeline)
        );

        let mut query = retrieval_query(
            "local-dev",
            json!({ "text": "What does the security policy require?" }),
            PrivacyTier::Standard,
        );
        query.embedding_model_ref = Some(index.embedding_model_ref.clone());
        let plan = retrieval_plan(&RetrievalPlanningRequestV1 {
            schema_version: RETRIEVAL_PLANNING_REQUEST_SCHEMA_VERSION.to_string(),
            query: query.clone(),
            vector_index: index.clone(),
            rag_pipeline: Some(pipeline.clone()),
        });

        assert!(plan.valid, "{plan:#?}");
        assert_eq!(plan.api_surface, ApiSurface::RagQuery);
        assert!(plan.citation_trace_required);
        assert!(
            plan.immutable_refs
                .contains(&"bzz://indexes/security-policy.hnsw".to_string())
        );

        let mut trace = CitationTraceV1 {
            schema_version: CITATION_TRACE_SCHEMA_VERSION.to_string(),
            object_kind: "citation_trace".to_string(),
            trace_id: String::new(),
            query_id: query.query_id,
            answer_ref: "bzz://answers/security-policy-answer.json".to_string(),
            retrieval_plan_ref: Some(format!("local://retrieval-plans/{}", plan.plan_id)),
            pipeline_ref: Some(format!("local://rag-pipelines/{}", pipeline.pipeline_id)),
            citations: vec![CitationSpanV1 {
                output_start: 0,
                output_end: 42,
                source_ref: "bzz://chunks/security-policy.jsonl#chunk=0".to_string(),
                document_id: Some("doc-security-policy".to_string()),
                chunk_id: Some("chunk-0".to_string()),
                quote_hash: Some("sha256-policy-quote".to_string()),
                score: Some(0.94),
                visibility: CitationVisibilityV1::AuthorizedOnly,
            }],
            policy_warnings: vec![],
            created_at,
            signature: None,
        };
        sign_citation_trace(&mut trace);
        assert!(
            verify_citation_trace(&trace).valid,
            "{:#?}",
            verify_citation_trace(&trace)
        );
    }

    #[test]
    fn rag_one_ingests_searches_and_cites_plain_text() {
        let ingest = rag_ingest_plain_text(rag_ingest_request(
            "local/test",
            "Swarm stores documents, chunks, embeddings, vector indexes, citations, and receipts. Hivemind uses those references to make RAG flows replayable.",
            VectorAccessPolicyV1::default(),
        ))
        .unwrap();

        assert_eq!(ingest.schema_version, RAG_INGEST_RESULT_SCHEMA_VERSION);
        assert!(
            ingest
                .verifications
                .iter()
                .all(|verification| verification.valid)
        );
        assert_eq!(ingest.snapshot.chunks.len(), 1);
        assert_eq!(ingest.snapshot.embeddings.len(), 1);

        let search = rag_search(
            &ingest.snapshot,
            RagSearchRequestV1 {
                schema_version: RAG_SEARCH_REQUEST_SCHEMA_VERSION.to_string(),
                request_id: "rag-search-test-1".to_string(),
                collection: "local/test".to_string(),
                requester: "tester".to_string(),
                query: "What does Swarm store for RAG?".to_string(),
                top_k: 3,
                privacy_tier: PrivacyTier::Standard,
                access_grant_refs: vec![],
                include_text: true,
            },
        );

        assert!(search.valid, "{search:#?}");
        assert!(search.access_granted);
        assert_eq!(search.hits.len(), 1);
        assert!(
            search.hits[0]
                .text
                .as_deref()
                .unwrap()
                .contains("citations")
        );

        let answer = rag_ask(
            &ingest.snapshot,
            RagAskRequestV1 {
                schema_version: RAG_ASK_REQUEST_SCHEMA_VERSION.to_string(),
                request_id: "rag-ask-test-1".to_string(),
                collection: "local/test".to_string(),
                requester: "tester".to_string(),
                query: "What can be audited?".to_string(),
                top_k: 3,
                privacy_tier: PrivacyTier::Standard,
                access_grant_refs: vec![],
                receipt_required: true,
            },
        );

        assert!(answer.valid, "{answer:#?}");
        assert!(answer.answer.contains("retrieved chunk"));
        assert_eq!(answer.citation_trace.citations.len(), 1);
        assert!(verify_citation_trace(&answer.citation_trace).valid);
        assert!(answer.answer_receipt.is_some());
        assert_eq!(answer.answer_receipt.as_ref().unwrap().chunk_refs.len(), 1);
    }

    #[test]
    fn rag_one_rejects_private_search_without_access_grant() {
        let private_policy = VectorAccessPolicyV1 {
            visibility: VectorAccessVisibility::Private,
            privacy_tier: PrivacyTier::LocalOnly,
            access_grant_required: true,
            license_ref: Some("local://licenses/private".to_string()),
            redaction_policy_ref: None,
        };
        let ingest = rag_ingest_plain_text(rag_ingest_request(
            "private/test",
            "Private board minutes discuss a confidential GPU procurement plan.",
            private_policy,
        ))
        .unwrap();

        let denied = rag_search(
            &ingest.snapshot,
            RagSearchRequestV1 {
                schema_version: RAG_SEARCH_REQUEST_SCHEMA_VERSION.to_string(),
                request_id: "rag-search-private-denied".to_string(),
                collection: "private/test".to_string(),
                requester: "tester".to_string(),
                query: "GPU procurement".to_string(),
                top_k: 2,
                privacy_tier: PrivacyTier::LocalOnly,
                access_grant_refs: vec![],
                include_text: true,
            },
        );

        assert!(!denied.valid);
        assert!(!denied.access_granted);
        assert!(denied.hits.is_empty());
        assert!(
            denied
                .issues
                .iter()
                .any(|issue| issue.path == "$.accessGrantRefs")
        );

        let allowed = rag_search(
            &ingest.snapshot,
            RagSearchRequestV1 {
                access_grant_refs: vec!["local://access-grants/grant-1".to_string()],
                ..denied.request
            },
        );

        assert!(allowed.valid, "{allowed:#?}");
        assert!(allowed.access_granted);
        assert_eq!(allowed.hits.len(), 1);
    }

    #[test]
    fn retrieval_plan_rejects_embedding_model_mismatch_and_local_only_remote_index() {
        let mut index = vector_index_v2_from_vector_store(&manifest());
        index.backend = VectorIndexBackendV2::RemoteService;
        index.access_policy.privacy_tier = PrivacyTier::LocalOnly;
        sign_vector_index_manifest_v2(&mut index);
        let mut query = retrieval_query(
            "local-dev",
            json!({ "text": "find policy documents" }),
            PrivacyTier::LocalOnly,
        );
        query.embedding_model_ref = Some("bzz://different-embedding-model".to_string());

        let plan = retrieval_plan(&RetrievalPlanningRequestV1 {
            schema_version: RETRIEVAL_PLANNING_REQUEST_SCHEMA_VERSION.to_string(),
            query,
            vector_index: index,
            rag_pipeline: None,
        });

        assert!(!plan.valid);
        assert!(
            plan.issues
                .iter()
                .any(|issue| issue.path == "$.query.embeddingModelRef")
        );
        assert!(
            plan.issues
                .iter()
                .any(|issue| issue.path == "$.vectorIndex.backend")
        );
    }

    #[test]
    fn citation_trace_detects_tampered_signed_source_claims() {
        let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let mut trace = CitationTraceV1 {
            schema_version: CITATION_TRACE_SCHEMA_VERSION.to_string(),
            object_kind: "citation_trace".to_string(),
            trace_id: String::new(),
            query_id: "query-1".to_string(),
            answer_ref: "bzz://answers/answer.json".to_string(),
            retrieval_plan_ref: Some("local://retrieval-plans/plan-1".to_string()),
            pipeline_ref: None,
            citations: vec![CitationSpanV1 {
                output_start: 10,
                output_end: 20,
                source_ref: "bzz://chunks/source.jsonl#chunk=1".to_string(),
                document_id: Some("doc-1".to_string()),
                chunk_id: Some("chunk-1".to_string()),
                quote_hash: Some("sha256-source-quote".to_string()),
                score: Some(0.8),
                visibility: CitationVisibilityV1::Public,
            }],
            policy_warnings: vec![],
            created_at,
            signature: None,
        };
        sign_citation_trace(&mut trace);
        trace.citations[0].source_ref = "bzz://chunks/other.jsonl#chunk=7".to_string();

        let verification = verify_citation_trace(&trace);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| { issue.path == "$.traceId" || issue.path == "$.signature" })
        );
    }

    fn manifest() -> VectorStoreManifestV1 {
        create_vector_store_manifest(VectorStoreInitOptionsV1 {
            name: "Company Docs".to_string(),
            owner: "0xVectorOwner".to_string(),
            embedding_model_ref: "bzz://embedding-model".to_string(),
            document_collection_refs: vec!["bzz://docs".to_string()],
            index_format: Some("hnsw".to_string()),
            dimensions: 1536,
            metric: Some(VectorMetric::Cosine),
            chunking_strategy_ref: Some("bzz://chunking".to_string()),
            storage_refs: vec![
                VectorStorageRefV1 {
                    role: VectorStorageRole::Index,
                    reference: "bzz://index".to_string(),
                    content_type: Some("application/octet-stream".to_string()),
                    sha256: None,
                    size_bytes: Some(42),
                },
                VectorStorageRefV1 {
                    role: VectorStorageRole::Chunks,
                    reference: "bzz://chunks".to_string(),
                    content_type: Some("application/jsonl".to_string()),
                    sha256: None,
                    size_bytes: None,
                },
            ],
            access_policy: None,
        })
    }

    fn rag_ingest_request(
        collection: &str,
        document_text: &str,
        access_policy: VectorAccessPolicyV1,
    ) -> RagIngestRequestV1 {
        RagIngestRequestV1 {
            schema_version: RAG_INGEST_REQUEST_SCHEMA_VERSION.to_string(),
            collection: collection.to_string(),
            owner: "0xVectorOwner".to_string(),
            title: "Test Document".to_string(),
            document_text: document_text.to_string(),
            source_ref: Some("bzz://local-bytes-test-document".to_string()),
            content_type: "text/plain".to_string(),
            language: Some("en".to_string()),
            metadata: json!({ "fixture": true }),
            sensitivity: DocumentSensitivityV1::Public,
            access_policy,
            chunking_strategy: ChunkingStrategyV1 {
                strategy_kind: ChunkingStrategyKindV1::FixedTokens,
                target_tokens: 64,
                overlap_tokens: 0,
                separators: vec![" ".to_string()],
                tokenizer_ref: Some("local://tokenizers/whitespace".to_string()),
            },
            embedding_model_ref: "local://embeddings/test".to_string(),
            dimensions: 16,
            metric: VectorMetric::Cosine,
        }
    }
}
