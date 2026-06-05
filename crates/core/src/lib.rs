pub mod access;
pub mod artifact;
pub mod canonical;
pub mod errors;
pub mod execution;
pub mod interface;
pub mod job;
pub mod manifest;
pub mod policy;
pub mod receipt;
pub mod registry;
pub mod routing;
pub mod runner;
pub mod trust;
pub mod validation;

pub const INTERFACE_VERSION: &str = "0.3";

pub use access::{
    ACCESS_EVALUATION_RESULT_SCHEMA_VERSION, ACCESS_GRANT_V3_SCHEMA_VERSION,
    ACCESS_POLICY_V2_SCHEMA_VERSION, ACCESS_POLICY_V2_VERIFICATION_SCHEMA_VERSION,
    ASSET_ACCESS_RULE_SCHEMA_VERSION, ASSET_ACCESS_RULE_V2_SCHEMA_VERSION, AccessControlMode,
    AccessControlV1, AccessDecision, AccessEvaluationResultV1, AccessEvaluationV1,
    AccessGrantRevocationV1, AccessGrantV1, AccessGrantV2, AccessGrantV3, AccessMethod,
    AccessPaymentRequirementV1, AccessPolicyV1, AccessPolicyV1Context, AccessPolicyV2,
    AccessPolicyV2VerificationV1, AccessPolicyVerificationV1, AccessPrivacyRequirementV1,
    AccessProofV1, AccessRequestV1, AccessRevocationListV1, AccessRightV1, AccessScopeV1,
    AccessSubjectTypeV1, AccessSubjectV1, AccessVerificationRequirementV1, AssetAccessRuleV1,
    AssetAccessRuleV2, LICENSE_POLICY_V2_SCHEMA_VERSION, LicensePolicyV1, LicensePolicyV2,
    PAID_ACCESS_QUOTE_SCHEMA_VERSION, PaidAccessQuoteV1, access_evaluation_result,
    access_grant_v3_from_v2, access_policy_from_license_policy,
    access_policy_from_license_policy_with_context, access_policy_v2_from_license_policy,
    access_policy_v2_from_license_policy_v2, access_policy_v2_from_license_policy_with_context,
    asset_access_rule_v2_from_v1, asset_access_rules_v2_from_access_policy,
    canonical_access_policy_id, canonical_access_policy_v2_id, canonical_asset_access_rule_v2_id,
    default_access_control_mode, default_allowed_uses, expected_access_policy_signature,
    expected_access_policy_v2_signature, license_policy_from_manifest,
    license_policy_v2_from_license_policy, license_policy_v2_from_manifest,
    license_requires_access_grant, paid_access_quote, paid_access_quote_with_listing_ref,
    sign_access_policy, sign_access_policy_v2, verify_access_policy, verify_access_policy_v2,
};
pub use artifact::select_artifact_group;
pub use canonical::{canonicalize_json, hash_canonical_json};
pub use errors::{
    ErrorCode, StandardErrorCatalogV1, StandardErrorCodeV1, StandardErrorDefinitionV1,
    SwarmAiErrorV1, all_standard_error_codes, legacy_error_code_for_standard_code,
    standard_error_catalog, standard_error_code_for_error_code, standard_error_definition,
};
pub use execution::{
    ExecutionMetrics, ExecutionOptions, ExecutionPrivacy, ExecutionRequestV1, ExecutionResponseV1,
    ExecutionStatus, ReceiptMode,
};
pub use interface::{
    AIWorkloadV1, AIWorkloadVerificationV1, AiInputPartType, AiInputPartV1, AiOutputPartType,
    AiOutputPartV1, AiPackageSelectorV1, AiRequestConstraintsV1, AiRequestPrivacyV1, AiRequestV1,
    AiRequestValidationV1, AiRequestVerificationV1, AiResponseErrorV1, AiResponseStatusV1,
    AiResponseV1, AiResponseVerificationV1, AiSamplingOptionsV1, AiUsageV1,
    AiWorkloadExecutionRequirementsV1, AiWorkloadPrivacyRequirementV1,
    AiWorkloadSettlementRequirementV1, AiWorkloadStoragePlanV1, AiWorkloadTraceRequirementV1,
    AiWorkloadValidationRequirementV1, AssetOrInlineInputV1, BudgetV1, ExpectedOutputDescriptorV1,
    JobPolicyV1, PrivacyRequirementV1, RuntimePreferencesV1, TaskEnvelopeV1,
    TaskEnvelopeVerificationV1, TaskStreamingV1, VerificationRequirementV1,
    ai_request_from_execution_request, ai_response_from_execution_response,
    ai_workload_from_ai_request, canonical_ai_request_id, canonical_ai_response_id,
    canonical_ai_workload_id, canonical_task_envelope_id, execution_request_from_ai_request,
    expected_ai_request_signature, expected_ai_response_signature, expected_ai_workload_signature,
    expected_task_envelope_signature, sign_ai_request, sign_ai_response, sign_ai_workload,
    sign_task_envelope, task_envelope_from_ai_request, verify_ai_request, verify_ai_response,
    verify_ai_workload, verify_task_envelope,
};
pub use job::{
    ApiSurface, EXECUTION_LEASE_REQUEST_SCHEMA_VERSION, EXECUTION_LEASE_SCHEMA_VERSION,
    ExecutionConstraintsV1, ExecutionLeaseRequestV1, ExecutionLeaseV1,
    JOB_ACCESS_ATTACHMENT_SCHEMA_VERSION, JOB_ORDER_SCHEMA_VERSION, JOB_QUOTE_SCHEMA_VERSION,
    JobAccessAttachmentV1, JobOrderV1, JobPrivacyV1, JobQuoteV1,
    LEGACY_EXECUTION_LEASE_REQUEST_SCHEMA_VERSION, LEGACY_EXECUTION_LEASE_SCHEMA_VERSION,
    LEGACY_JOB_ORDER_SCHEMA_VERSION, LEGACY_JOB_QUOTE_SCHEMA_VERSION,
    LEGACY_STREAMING_EVENT_SCHEMA_VERSION, Modality, OutputContractV1, PriceModel, PriceV1,
    RetryPolicyV1, STREAMING_EVENT_SCHEMA_VERSION, StreamingEventType, StreamingEventV1,
    attach_access_grant_v2_to_job_order, canonical_execution_lease_id,
    canonical_job_access_attachment_id, canonical_job_order_id, canonical_job_quote_id,
    canonical_streaming_event_id, execution_lease_from_quote, execution_lease_from_request,
    execution_request_input_hash, job_order_from_execution_request,
    job_quote_from_runner_capability, streaming_event,
};
pub use manifest::{
    ArtifactGroup, ArtifactGroupV2, ArtifactMinimum, AssetDescriptorV1, AssetRoleV1,
    BrowserPublishProfileV1, CapabilitySetV1, LicenseInfo, LicenseType, PackageIndexSummaryV1,
    PackageKind, PackageManifestV1, PackageManifestV2, PackageManifestV2Context, PackageManifestV3,
    PackageManifestV3Context, PackageManifestV4, PackageManifestV4Context, PermissionRequest,
    PolicyRefV1, ProvenanceRecordV1, Publisher, RuntimeDescriptorV2, UniversalCapabilityV1,
    artifact_group_v2_from_v1, asset_descriptors_from_manifest_v1, capability_set_from_manifest_v4,
    manifest_supports_capability, package_index_summary_from_manifest_v4,
    package_manifest_v2_from_v1, package_manifest_v2_from_v1_with_context,
    package_manifest_v3_from_v1, package_manifest_v3_from_v1_with_context,
    package_manifest_v4_from_v1, package_manifest_v4_from_v1_with_context,
    runtime_descriptors_from_manifest_v1, universal_capabilities_from_manifest_v1,
};
pub use policy::{
    PolicyDecision, PolicyDecisionV1, evaluate_package_policy, policy_execution_block_reason,
};
pub use receipt::{
    BillingInfo, ExecutionReceiptCostV2, ExecutionReceiptErrorV2, ExecutionReceiptLeaseContextV2,
    ExecutionReceiptTimingV2, ExecutionReceiptUsageV2, ExecutionReceiptV1, ExecutionReceiptV2,
    ExecutionReceiptV2Context, ReceiptDraft, ReceiptPolicyEvidenceV1, canonical_receipt_id,
    create_signed_receipt, create_unsigned_receipt, execution_receipt_v2_from_v1,
    expected_receipt_signature, policy_decision_id, receipt_policy_evidence, sign_receipt,
};
pub use registry::{
    RegistryBenchmarkScoreV1, RegistryEntryV1, RegistryMarketplaceListingSummaryV1,
    RegistryPermissionSummaryV1, RegistryPolicySummaryV1, RegistryQueryV1, RegistrySearchResponse,
};
pub use routing::{
    CandidateRoute, PolicyMode, RouteDecision, RouteEstimate, RoutePlanV1, plan_route_for_runner,
    policy_route_block_reason,
};
pub use runner::{
    RunnerCacheClaimV1, RunnerCapabilityV1, RunnerCapabilityV2, RunnerCapabilityV2Context,
    RunnerDescriptorV1, RunnerHardwareV1, RunnerLatencyHintsV2, RunnerLimits, RunnerMemoryV1,
    RunnerPriceEntryV1, RunnerToolExecutionV2, RunnerType, runner_capability_from_descriptor,
    runner_capability_v2_from_v1, runner_capability_v2_from_v1_with_context,
    runner_supports_capability,
};
pub use trust::{
    DataRetentionRule, IntegrityTier, LoggingRule,
    PRIVACY_REQUIREMENT_ASSESSMENT_REQUEST_SCHEMA_VERSION,
    PRIVACY_REQUIREMENT_ASSESSMENT_SCHEMA_VERSION, PRIVACY_TIER_CATALOG_SCHEMA_VERSION,
    PRIVACY_TIER_PROFILE_SCHEMA_VERSION, PrivacyDataMovementRuleV1, PrivacyExecutionLocationV1,
    PrivacyRequirementAssessmentRequestV1, PrivacyRequirementAssessmentV1, PrivacyTier,
    PrivacyTierCatalogV1, PrivacyTierProfileV1, ToolPermissionRule, TrustPolicyPriceLimitV1,
    TrustPolicyV1, TrustPolicyVerificationV1, assess_privacy_requirement,
    canonical_trust_policy_id, expected_trust_policy_signature, privacy_tier_catalog,
    privacy_tier_preference_order, privacy_tier_profile, privacy_tier_profiles,
    privacy_tier_satisfies, sign_trust_policy, trust_policy_allows_runner, verify_trust_policy,
};
pub use validation::{ValidationIssue, ValidationReport, validate_package_manifest_value};
