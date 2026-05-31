pub mod access;
pub mod artifact;
pub mod canonical;
pub mod errors;
pub mod execution;
pub mod manifest;
pub mod policy;
pub mod receipt;
pub mod registry;
pub mod routing;
pub mod runner;
pub mod validation;

pub const INTERFACE_VERSION: &str = "0.1";

pub use access::{
    AccessControlMode, AccessControlV1, AccessDecision, AccessEvaluationV1,
    AccessGrantRevocationV1, AccessGrantV1, AccessMethod, AccessProofV1, AccessRequestV1,
    AccessRevocationListV1, LicensePolicyV1, default_access_control_mode, default_allowed_uses,
    license_policy_from_manifest, license_requires_access_grant,
};
pub use artifact::select_artifact_group;
pub use canonical::{canonicalize_json, hash_canonical_json};
pub use errors::{ErrorCode, SwarmAiErrorV1};
pub use execution::{
    ExecutionMetrics, ExecutionOptions, ExecutionPrivacy, ExecutionRequestV1, ExecutionResponseV1,
    ExecutionStatus,
};
pub use manifest::{
    ArtifactGroup, ArtifactMinimum, LicenseInfo, LicenseType, PackageKind, PackageManifestV1,
    PermissionRequest, Publisher, manifest_supports_capability,
};
pub use policy::{PolicyDecision, PolicyDecisionV1, evaluate_package_policy};
pub use receipt::{
    ExecutionReceiptV1, ReceiptDraft, ReceiptPolicyEvidenceV1, canonical_receipt_id,
    create_signed_receipt, create_unsigned_receipt, expected_receipt_signature, policy_decision_id,
    receipt_policy_evidence, sign_receipt,
};
pub use registry::{
    RegistryBenchmarkScoreV1, RegistryEntryV1, RegistryPermissionSummaryV1,
    RegistryPolicySummaryV1, RegistryQueryV1, RegistrySearchResponse,
};
pub use routing::{
    CandidateRoute, PolicyMode, RouteDecision, RouteEstimate, RoutePlanV1, plan_route_for_runner,
};
pub use runner::{RunnerDescriptorV1, RunnerLimits, RunnerType, runner_supports_capability};
pub use validation::{ValidationIssue, ValidationReport, validate_package_manifest_value};
