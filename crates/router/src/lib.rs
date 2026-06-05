use chrono::{SecondsFormat, Utc};
use hivemind_access::evaluate_execution_access_with_revocations;
use hivemind_core::{
    AIWorkloadV1, AccessDecision, AccessEvaluationV1, AiRequestV1, ApiSurface, ArtifactGroup,
    CandidateRoute, ErrorCode, ExecutionRequestV1, ExecutionStatus, IntegrityTier, JobOrderV1,
    Modality, PolicyMode, PriceModel, PriceV1, PrivacyTier, RouteDecision, RouteEstimate,
    RoutePlanV1, RunnerDescriptorV1, RunnerPriceEntryV1, RunnerType, TrustPolicyV1,
    ValidationIssue, evaluate_package_policy, hash_canonical_json,
    job_order_from_execution_request, manifest_supports_capability, policy_route_block_reason,
    trust_policy_allows_runner,
};
use hivemind_marketplace::{
    HardwareResourceOfferV1, MarketplaceShortlistV1, MinerTrustTierV1, RunnerOfferScoreV1,
    RunnerOfferV1, shortlist_request_from_execution, shortlist_runner_offers,
};
use hivemind_miner::{MinerBenchmarkResultV1, MinerDaemonStatus, MinerHeartbeatV1};
use hivemind_package::LocalPackage;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CostQuoteV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "routeId")]
    pub route_id: String,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    #[serde(rename = "runnerType")]
    pub runner_type: RunnerType,
    #[serde(rename = "estimatedCost")]
    pub estimated_cost: f64,
    pub currency: String,
    #[serde(rename = "queueMs")]
    pub queue_ms: u64,
    #[serde(rename = "firstTokenMs")]
    pub first_token_ms: u64,
    pub privacy: String,
    pub warm: bool,
    #[serde(rename = "qualityScore")]
    pub quality_score: f64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerReputationSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "qualityScore")]
    pub quality_score: f64,
    #[serde(rename = "latencyScore")]
    pub latency_score: f64,
    #[serde(rename = "overallScore")]
    pub overall_score: f64,
    #[serde(rename = "reportCount")]
    pub report_count: usize,
    #[serde(rename = "evidenceRefs")]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RoutePlannerTimingV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "completedAt")]
    pub completed_at: String,
    #[serde(rename = "elapsedMs")]
    pub elapsed_ms: u64,
    #[serde(rename = "candidateCount")]
    pub candidate_count: usize,
    #[serde(rename = "eligibleCandidateCount")]
    pub eligible_candidate_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RoutePlannerReportV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobOrder", default, skip_serializing_if = "Option::is_none")]
    pub job_order: Option<JobOrderV1>,
    pub plan: RoutePlanV1,
    pub quotes: Vec<CostQuoteV1>,
    #[serde(rename = "marketplaceShortlist", default)]
    pub marketplace_shortlist: Option<MarketplaceShortlistV1>,
    #[serde(
        rename = "runnerReputation",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub runner_reputation: Vec<RunnerReputationSummaryV1>,
    #[serde(
        rename = "minerCapacity",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub miner_capacity: Vec<MinerCapacitySignalV1>,
    #[serde(
        rename = "trustPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub trust_policy: Option<TrustPolicyV1>,
    #[serde(rename = "policyMode")]
    pub policy_mode: PolicyMode,
    #[serde(
        rename = "planningTiming",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub planning_timing: Option<RoutePlannerTimingV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StorageMovementActionV1 {
    InlineOnly,
    UseExistingRef,
    UploadBeforeExecution,
    EncryptAndUpload,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteInputAssetPlanV1 {
    #[serde(rename = "assetId")]
    pub asset_id: String,
    #[serde(rename = "assetClass")]
    pub asset_class: String,
    #[serde(rename = "storageRefs", default)]
    pub storage_refs: Vec<String>,
    #[serde(
        rename = "contentHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_hash: Option<String>,
    #[serde(rename = "byteSize", default, skip_serializing_if = "Option::is_none")]
    pub byte_size: Option<u64>,
    #[serde(
        rename = "sensitivityLabel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sensitivity_label: Option<String>,
    pub movement: StorageMovementActionV1,
    #[serde(rename = "uploadRequired")]
    pub upload_required: bool,
    #[serde(rename = "encryptionRequired")]
    pub encryption_required: bool,
    #[serde(
        rename = "preferredProvider",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub preferred_provider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteOutputAssetPlanV1 {
    #[serde(rename = "outputStrategy")]
    pub output_strategy: String,
    #[serde(
        rename = "outputAssetClass",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_asset_class: Option<String>,
    #[serde(rename = "publishToSwarm")]
    pub publish_to_swarm: bool,
    #[serde(rename = "inlineAllowed")]
    pub inline_allowed: bool,
    #[serde(rename = "storageReceiptRequired")]
    pub storage_receipt_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteStorageProviderPlanV1 {
    #[serde(rename = "inputStrategy")]
    pub input_strategy: String,
    #[serde(rename = "outputStrategy")]
    pub output_strategy: String,
    #[serde(rename = "allowedProviders", default)]
    pub allowed_providers: Vec<String>,
    #[serde(
        rename = "selectedProvider",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub selected_provider: Option<String>,
    #[serde(rename = "fallbackProviders", default)]
    pub fallback_providers: Vec<String>,
    #[serde(rename = "requiresBrowserSession")]
    pub requires_browser_session: bool,
    #[serde(rename = "requiresStorageReceipts")]
    pub requires_storage_receipts: bool,
    #[serde(rename = "encryptInputs")]
    pub encrypt_inputs: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteExecutionCandidateV1 {
    #[serde(rename = "routeId")]
    pub route_id: String,
    #[serde(rename = "runnerType")]
    pub runner_type: RunnerType,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(
        rename = "artifactGroup",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub artifact_group: Option<String>,
    pub decision: RouteDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "inputDeliveryStrategy")]
    pub input_delivery_strategy: String,
    #[serde(rename = "outputDeliveryStrategy")]
    pub output_delivery_strategy: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RoutePrivacyDecisionV1 {
    pub tier: PrivacyTier,
    #[serde(rename = "remoteExecutionAllowed")]
    pub remote_execution_allowed: bool,
    #[serde(rename = "plaintextMinerAllowed")]
    pub plaintext_miner_allowed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteVerificationDecisionV1 {
    pub tier: IntegrityTier,
    #[serde(rename = "validationRequired")]
    pub validation_required: bool,
    #[serde(rename = "methodHints", default)]
    pub method_hints: Vec<String>,
    #[serde(rename = "storageReceiptsRequired")]
    pub storage_receipts_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteSettlementDecisionV1 {
    #[serde(rename = "paymentMode")]
    pub payment_mode: String,
    #[serde(rename = "releaseCondition")]
    pub release_condition: String,
    #[serde(rename = "maxPrice", default, skip_serializing_if = "Option::is_none")]
    pub max_price: Option<PriceV1>,
    #[serde(rename = "quoteCount")]
    pub quote_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteConsentRequirementV1 {
    pub action: String,
    pub reason: String,
    #[serde(
        rename = "storageSessionRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub storage_session_ref: Option<String>,
    #[serde(
        rename = "providerHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub provider_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UniversalRoutePlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "resolvedPackageRef")]
    pub resolved_package_ref: String,
    #[serde(rename = "selectedCapability")]
    pub selected_capability: String,
    #[serde(rename = "inputAssetPlan", default)]
    pub input_asset_plan: Vec<RouteInputAssetPlanV1>,
    #[serde(rename = "outputAssetPlan")]
    pub output_asset_plan: RouteOutputAssetPlanV1,
    #[serde(rename = "storageProviderPlan")]
    pub storage_provider_plan: RouteStorageProviderPlanV1,
    #[serde(rename = "executionCandidates", default)]
    pub execution_candidates: Vec<RouteExecutionCandidateV1>,
    #[serde(rename = "privacyDecision")]
    pub privacy_decision: RoutePrivacyDecisionV1,
    #[serde(rename = "verificationDecision")]
    pub verification_decision: RouteVerificationDecisionV1,
    #[serde(rename = "settlementDecision")]
    pub settlement_decision: RouteSettlementDecisionV1,
    #[serde(rename = "fallbackChain", default)]
    pub fallback_chain: Vec<String>,
    #[serde(rename = "userConsentRequirements", default)]
    pub user_consent_requirements: Vec<RouteConsentRequirementV1>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiExecutionPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "aiRequest")]
    pub ai_request: AiRequestV1,
    #[serde(rename = "executionRequest")]
    pub execution_request: ExecutionRequestV1,
    #[serde(rename = "routeReport")]
    pub route_report: RoutePlannerReportV1,
    #[serde(rename = "readyToExecute")]
    pub ready_to_execute: bool,
    #[serde(rename = "selectedRouteId", default)]
    pub selected_route_id: Option<String>,
    #[serde(rename = "eligibleRouteCount")]
    pub eligible_route_count: usize,
    #[serde(rename = "rejectedRouteCount")]
    pub rejected_route_count: usize,
    #[serde(
        rename = "universalRoutePlan",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub universal_route_plan: Option<UniversalRoutePlanV1>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl AiExecutionPlanV1 {
    pub fn from_report(
        ai_request: AiRequestV1,
        execution_request: ExecutionRequestV1,
        package_ref: impl Into<String>,
        package_id: impl Into<String>,
        route_report: RoutePlannerReportV1,
    ) -> Self {
        let package_ref = package_ref.into();
        let package_id = package_id.into();
        let eligible_route_count = route_report
            .plan
            .candidate_routes
            .iter()
            .filter(|route| route.decision == RouteDecision::Eligible)
            .count();
        let rejected_route_count = route_report
            .plan
            .candidate_routes
            .len()
            .saturating_sub(eligible_route_count);
        let selected_route_id = route_report.plan.selected_route_id.clone();
        let mut warnings = Vec::new();
        if selected_route_id.is_none() {
            warnings.push(route_report.plan.reason.clone());
        }
        if route_report.quotes.is_empty() {
            warnings.push("No cost quotes were produced for this AI request".to_string());
        }
        let workload = hivemind_core::ai_workload_from_ai_request(&ai_request);
        let universal_route_plan = Some(universal_route_plan_from_workload(
            &workload,
            &route_report,
            &package_ref,
        ));

        Self {
            schema_version: "hivemind.ai-execution-plan.v1".to_string(),
            request_id: execution_request.request_id.clone(),
            package_ref,
            package_id,
            ai_request,
            execution_request,
            route_report,
            ready_to_execute: selected_route_id.is_some(),
            selected_route_id,
            eligible_route_count,
            rejected_route_count,
            universal_route_plan,
            warnings,
        }
    }
}

pub fn universal_route_plan_from_workload(
    workload: &AIWorkloadV1,
    route_report: &RoutePlannerReportV1,
    resolved_package_ref: impl Into<String>,
) -> UniversalRoutePlanV1 {
    let selected_candidate = route_report
        .plan
        .selected_route_id
        .as_deref()
        .and_then(|route_id| {
            route_report
                .plan
                .candidate_routes
                .iter()
                .find(|candidate| candidate.route_id == route_id)
        });
    let allowed_providers = allowed_storage_providers_for_workload(workload);
    let selected_provider =
        selected_storage_provider_for_workload(workload, selected_candidate, &allowed_providers);
    let fallback_providers = allowed_providers
        .iter()
        .filter(|provider| Some(provider.as_str()) != selected_provider.as_deref())
        .cloned()
        .collect::<Vec<_>>();
    let requires_browser_session = requires_browser_storage_session(workload);
    let mut warnings = Vec::new();
    if workload.storage_plan.required_storage_receipts && selected_provider.is_none() {
        warnings.push(
            "Storage receipts are required, but the workload does not allow a storage provider"
                .to_string(),
        );
    }
    if requires_browser_session
        && !allowed_providers.iter().any(|provider| {
            matches!(
                provider.as_str(),
                "weeb3_npm" | "bee_js_gateway" | "hosted_upload_relay"
            )
        })
    {
        warnings.push(
            "Browser-originated storage requires a browser-capable provider in allowedProviders"
                .to_string(),
        );
    }

    UniversalRoutePlanV1 {
        schema_version: "hivemind.universal-route-plan.v1".to_string(),
        request_id: route_report.plan.request_id.clone(),
        resolved_package_ref: resolved_package_ref.into(),
        selected_capability: workload.selected_capability.clone(),
        input_asset_plan: input_asset_plan_for_workload(workload, selected_provider.clone()),
        output_asset_plan: output_asset_plan_for_workload(workload),
        storage_provider_plan: RouteStorageProviderPlanV1 {
            input_strategy: workload.storage_plan.input_strategy.clone(),
            output_strategy: workload.storage_plan.output_strategy.clone(),
            allowed_providers,
            selected_provider,
            fallback_providers,
            requires_browser_session,
            requires_storage_receipts: workload.storage_plan.required_storage_receipts,
            encrypt_inputs: workload.storage_plan.encrypt_inputs,
            warnings: warnings.clone(),
        },
        execution_candidates: route_report
            .plan
            .candidate_routes
            .iter()
            .map(|candidate| execution_candidate_for_workload(workload, candidate))
            .collect(),
        privacy_decision: privacy_decision_for_workload(workload),
        verification_decision: RouteVerificationDecisionV1 {
            tier: workload.validation_requirement.tier.clone(),
            validation_required: workload.validation_requirement.validation_required,
            method_hints: workload.validation_requirement.method_hints.clone(),
            storage_receipts_required: workload.trace_requirement.storage_receipts_required,
        },
        settlement_decision: RouteSettlementDecisionV1 {
            payment_mode: workload.settlement_requirement.payment_mode.clone(),
            release_condition: workload.settlement_requirement.release_condition.clone(),
            max_price: workload.settlement_requirement.max_price.clone(),
            quote_count: route_report.quotes.len(),
        },
        fallback_chain: route_report.plan.fallback_route_ids.clone(),
        user_consent_requirements: consent_requirements_for_workload(workload),
        warnings,
    }
}

fn input_asset_plan_for_workload(
    workload: &AIWorkloadV1,
    preferred_provider: Option<String>,
) -> Vec<RouteInputAssetPlanV1> {
    workload
        .input_assets
        .iter()
        .map(|asset| {
            let encryption_required =
                workload.storage_plan.encrypt_inputs || asset_requires_encryption(asset);
            let upload_required = asset.storage_refs.is_empty();
            let movement = if upload_required && encryption_required {
                StorageMovementActionV1::EncryptAndUpload
            } else if upload_required {
                StorageMovementActionV1::UploadBeforeExecution
            } else if encryption_required {
                StorageMovementActionV1::EncryptAndUpload
            } else {
                StorageMovementActionV1::UseExistingRef
            };
            RouteInputAssetPlanV1 {
                asset_id: asset.asset_id.clone(),
                asset_class: asset.asset_class.clone(),
                storage_refs: asset.storage_refs.clone(),
                content_hash: asset.content_hash.clone(),
                byte_size: asset.byte_size,
                sensitivity_label: asset.sensitivity_label.clone(),
                movement,
                upload_required,
                encryption_required,
                preferred_provider: preferred_provider.clone(),
            }
        })
        .collect()
}

fn output_asset_plan_for_workload(workload: &AIWorkloadV1) -> RouteOutputAssetPlanV1 {
    let output_strategy = workload.storage_plan.output_strategy.clone();
    let publish_to_swarm = output_strategy.contains("swarm")
        || output_strategy.contains("upload")
        || workload.trace_requirement.storage_receipts_required;
    RouteOutputAssetPlanV1 {
        output_strategy,
        output_asset_class: workload.storage_plan.output_asset_class.clone(),
        publish_to_swarm,
        inline_allowed: !publish_to_swarm
            || workload.storage_plan.output_strategy.contains("inline"),
        storage_receipt_required: workload.trace_requirement.storage_receipts_required,
    }
}

fn execution_candidate_for_workload(
    workload: &AIWorkloadV1,
    candidate: &CandidateRoute,
) -> RouteExecutionCandidateV1 {
    RouteExecutionCandidateV1 {
        route_id: candidate.route_id.clone(),
        runner_type: candidate.runner_type.clone(),
        runner_id: candidate.runner_id.clone(),
        artifact_group: candidate.artifact_group.clone(),
        decision: candidate.decision.clone(),
        reason: candidate.reason.clone(),
        input_delivery_strategy: input_delivery_strategy(workload, &candidate.runner_type),
        output_delivery_strategy: output_delivery_strategy(workload, &candidate.runner_type),
    }
}

fn privacy_decision_for_workload(workload: &AIWorkloadV1) -> RoutePrivacyDecisionV1 {
    let remote_execution_allowed = !matches!(
        workload.privacy_requirement.tier,
        PrivacyTier::LocalOnly | PrivacyTier::BrowserOnly
    );
    let reason = if remote_execution_allowed {
        "Privacy tier permits non-local routes that satisfy runner policy".to_string()
    } else {
        "Privacy tier requires local-device or browser-only execution before remote routing"
            .to_string()
    };
    RoutePrivacyDecisionV1 {
        tier: workload.privacy_requirement.tier.clone(),
        remote_execution_allowed,
        plaintext_miner_allowed: workload.privacy_requirement.allow_plaintext_miner,
        reason,
    }
}

fn consent_requirements_for_workload(workload: &AIWorkloadV1) -> Vec<RouteConsentRequirementV1> {
    let mut requirements = Vec::new();
    let session_ref = browser_storage_session_ref(workload);
    if requires_browser_storage_session(workload) {
        requirements.push(RouteConsentRequirementV1 {
            action: "reuse_storage_session".to_string(),
            reason: "Workload metadata references a browser storage session".to_string(),
            storage_session_ref: session_ref.clone(),
            provider_hint: selected_browser_provider_hint(workload),
        });
    }
    if workload
        .input_assets
        .iter()
        .any(|asset| asset.storage_refs.is_empty())
        || workload.storage_plan.input_strategy.contains("upload")
    {
        requirements.push(RouteConsentRequirementV1 {
            action: if workload.storage_plan.encrypt_inputs {
                "upload_private_data".to_string()
            } else {
                "upload_file".to_string()
            },
            reason: "Input data must be uploaded or re-published before execution".to_string(),
            storage_session_ref: session_ref.clone(),
            provider_hint: selected_browser_provider_hint(workload),
        });
    }
    if output_asset_plan_for_workload(workload).publish_to_swarm {
        requirements.push(RouteConsentRequirementV1 {
            action: "publish_runner_outputs".to_string(),
            reason: "Output strategy may publish large or auditable outputs to Swarm".to_string(),
            storage_session_ref: session_ref,
            provider_hint: selected_browser_provider_hint(workload),
        });
    }
    requirements
}

fn allowed_storage_providers_for_workload(workload: &AIWorkloadV1) -> Vec<String> {
    let mut providers = workload
        .storage_plan
        .allowed_providers
        .iter()
        .filter(|provider| !provider.trim().is_empty())
        .cloned()
        .collect::<Vec<_>>();
    providers.sort();
    providers.dedup();
    providers
}

fn selected_storage_provider_for_workload(
    workload: &AIWorkloadV1,
    selected_candidate: Option<&CandidateRoute>,
    allowed_providers: &[String],
) -> Option<String> {
    if allowed_providers.is_empty() {
        return None;
    }
    if requires_browser_storage_session(workload) {
        if let Some(provider) = first_allowed_provider(
            allowed_providers,
            &[
                "weeb3_npm",
                "bee_js_gateway",
                "hosted_upload_relay",
                "local_dev",
            ],
        ) {
            return Some(provider);
        }
    }
    if let Some(candidate) = selected_candidate {
        let priority = match candidate.runner_type {
            RunnerType::Browser => ["weeb3_npm", "bee_js_gateway", "local_dev", "bee_http"],
            RunnerType::Local => ["local_dev", "bee_http", "weeb3_npm", "bee_js_gateway"],
            RunnerType::RemoteGpu | RunnerType::Marketplace => {
                ["bee_http", "local_dev", "bee_js_gateway", "weeb3_npm"]
            }
        };
        if let Some(provider) = first_allowed_provider(allowed_providers, &priority) {
            return Some(provider);
        }
    }
    allowed_providers.first().cloned()
}

fn first_allowed_provider(allowed_providers: &[String], priority: &[&str]) -> Option<String> {
    priority.iter().find_map(|provider| {
        allowed_providers
            .iter()
            .find(|allowed| allowed.as_str() == *provider)
            .cloned()
    })
}

fn input_delivery_strategy(workload: &AIWorkloadV1, runner_type: &RunnerType) -> String {
    if workload.input_assets.is_empty() {
        return "inline_small".to_string();
    }
    if workload.storage_plan.encrypt_inputs {
        return "encrypted_storage_ref".to_string();
    }
    match runner_type {
        RunnerType::Browser => "browser_storage_session_or_local_file".to_string(),
        RunnerType::Local => "local_cache_or_storage_ref".to_string(),
        RunnerType::RemoteGpu | RunnerType::Marketplace => {
            "storage_ref_or_runner_upload".to_string()
        }
    }
}

fn output_delivery_strategy(workload: &AIWorkloadV1, runner_type: &RunnerType) -> String {
    if output_asset_plan_for_workload(workload).publish_to_swarm {
        match runner_type {
            RunnerType::Browser => "browser_upload_output_to_swarm".to_string(),
            RunnerType::Local => "local_upload_output_to_swarm".to_string(),
            RunnerType::RemoteGpu | RunnerType::Marketplace => {
                "runner_or_relay_upload_output_to_swarm".to_string()
            }
        }
    } else {
        "inline_response_with_receipt".to_string()
    }
}

fn requires_browser_storage_session(workload: &AIWorkloadV1) -> bool {
    browser_storage_session_ref(workload).is_some()
        || workload.storage_plan.input_strategy.contains("browser")
        || workload.storage_plan.output_strategy.contains("browser")
}

fn browser_storage_session_ref(workload: &AIWorkloadV1) -> Option<String> {
    workload
        .metadata
        .get("sourceMetadata")
        .and_then(|metadata| metadata.get("browserStorageSessionRef"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn selected_browser_provider_hint(workload: &AIWorkloadV1) -> Option<String> {
    first_allowed_provider(
        &allowed_storage_providers_for_workload(workload),
        &[
            "weeb3_npm",
            "bee_js_gateway",
            "hosted_upload_relay",
            "local_dev",
        ],
    )
}

fn asset_requires_encryption(asset: &hivemind_core::AssetDescriptorV1) -> bool {
    asset
        .sensitivity_label
        .as_deref()
        .map(|label| {
            let label = label.to_ascii_lowercase();
            label.contains("private")
                || label.contains("secret")
                || label.contains("confidential")
                || label.contains("enterprise")
        })
        .unwrap_or(false)
}

fn default_policy_mode() -> PolicyMode {
    PolicyMode::Balanced
}

fn default_max_marketplace_results() -> usize {
    3
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RoutePlannerRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub request: ExecutionRequestV1,
    #[serde(rename = "policyMode", default = "default_policy_mode")]
    pub policy_mode: PolicyMode,
    #[serde(
        rename = "maxMarketplaceResults",
        default = "default_max_marketplace_results"
    )]
    pub max_marketplace_results: usize,
    #[serde(
        rename = "trustPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub trust_policy: Option<TrustPolicyV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerCapacityInputV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "hardwareOffer")]
    pub hardware_offer: HardwareResourceOfferV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<MinerHeartbeatV1>,
    #[serde(default)]
    pub benchmarks: Vec<MinerBenchmarkResultV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerCapacitySignalV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "routeId")]
    pub route_id: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "minerId", default, skip_serializing_if = "Option::is_none")]
    pub miner_id: Option<String>,
    pub operator: String,
    #[serde(rename = "trustTier")]
    pub trust_tier: MinerTrustTierV1,
    #[serde(rename = "privacyTiers")]
    pub privacy_tiers: Vec<PrivacyTier>,
    #[serde(rename = "verificationTiers")]
    pub verification_tiers: Vec<IntegrityTier>,
    pub decision: RouteDecision,
    pub reasons: Vec<String>,
    #[serde(rename = "selectedArtifactGroup", default)]
    pub selected_artifact_group: Option<String>,
    #[serde(rename = "queueDepth")]
    pub queue_depth: u32,
    #[serde(rename = "activeJobs")]
    pub active_jobs: u32,
    #[serde(rename = "maxConcurrentJobs")]
    pub max_concurrent_jobs: u32,
    #[serde(rename = "estimatedQueueMs")]
    pub estimated_queue_ms: u64,
    #[serde(rename = "estimatedFirstTokenMs")]
    pub estimated_first_token_ms: u64,
    #[serde(rename = "estimatedCost")]
    pub estimated_cost: f64,
    pub currency: String,
    #[serde(rename = "warmCache")]
    pub warm_cache: bool,
    #[serde(rename = "benchmarkCount")]
    pub benchmark_count: usize,
    #[serde(rename = "validBenchmarkCount")]
    pub valid_benchmark_count: usize,
    #[serde(rename = "qualityScore")]
    pub quality_score: f64,
    #[serde(rename = "availableVramGb", default)]
    pub available_vram_gb: Option<f64>,
    #[serde(rename = "availableRamGb")]
    pub available_ram_gb: f64,
    #[serde(rename = "selectedPrivacyTier", default)]
    pub selected_privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "selectedVerificationTier", default)]
    pub selected_verification_tier: Option<IntegrityTier>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteAttemptV1 {
    #[serde(rename = "routeId")]
    pub route_id: String,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    #[serde(rename = "runnerType")]
    pub runner_type: RunnerType,
    pub status: ExecutionStatus,
    #[serde(rename = "errorCode", default)]
    pub error_code: Option<ErrorCode>,
    #[serde(rename = "errorMessage", default)]
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteExecutionTraceV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "selectedRouteId", default)]
    pub selected_route_id: Option<String>,
    #[serde(rename = "attemptedRouteIds")]
    pub attempted_route_ids: Vec<String>,
    #[serde(rename = "fallbackApplied")]
    pub fallback_applied: bool,
    pub attempts: Vec<RouteAttemptV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteTraceIndexEntryV1 {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "selectedRouteId", default)]
    pub selected_route_id: Option<String>,
    #[serde(rename = "attemptedRouteCount")]
    pub attempted_route_count: usize,
    #[serde(rename = "fallbackApplied")]
    pub fallback_applied: bool,
    #[serde(rename = "finalStatus", default)]
    pub final_status: Option<ExecutionStatus>,
    #[serde(rename = "runnerIds")]
    pub runner_ids: Vec<String>,
    #[serde(rename = "traceRef")]
    pub trace_ref: String,
    #[serde(rename = "tracePath")]
    pub trace_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteTraceStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "traceCount")]
    pub trace_count: usize,
    #[serde(rename = "fallbackTraceCount")]
    pub fallback_trace_count: usize,
    #[serde(rename = "failedTraceCount")]
    pub failed_trace_count: usize,
    pub traces: Vec<RouteTraceIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteTraceLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "tracePath")]
    pub trace_path: String,
    pub trace: RouteExecutionTraceV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteDecisionIndexEntryV1 {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub task: String,
    #[serde(rename = "policyMode")]
    pub policy_mode: PolicyMode,
    #[serde(rename = "selectedRouteId", default)]
    pub selected_route_id: Option<String>,
    #[serde(rename = "candidateCount")]
    pub candidate_count: usize,
    #[serde(rename = "eligibleCandidateCount")]
    pub eligible_candidate_count: usize,
    #[serde(rename = "rejectedCandidateCount")]
    pub rejected_candidate_count: usize,
    #[serde(rename = "fallbackRouteCount")]
    pub fallback_route_count: usize,
    #[serde(rename = "quoteCount")]
    pub quote_count: usize,
    #[serde(
        rename = "planningElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub planning_elapsed_ms: Option<u64>,
    #[serde(rename = "proofHash", default)]
    pub proof_hash: Option<String>,
    #[serde(rename = "proofValid")]
    pub proof_valid: bool,
    #[serde(rename = "selectedEstimatedCost", default)]
    pub selected_estimated_cost: Option<f64>,
    #[serde(rename = "selectedEstimatedCurrency", default)]
    pub selected_estimated_currency: Option<String>,
    #[serde(rename = "decisionRef")]
    pub decision_ref: String,
    #[serde(rename = "decisionPath")]
    pub decision_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteDecisionStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "decisionCount")]
    pub decision_count: usize,
    #[serde(rename = "withSelectedRouteCount")]
    pub with_selected_route_count: usize,
    #[serde(rename = "rejectedOnlyCount")]
    pub rejected_only_count: usize,
    #[serde(rename = "fallbackPlannedCount")]
    pub fallback_planned_count: usize,
    #[serde(rename = "validProofCount")]
    pub valid_proof_count: usize,
    #[serde(rename = "invalidProofCount")]
    pub invalid_proof_count: usize,
    #[serde(rename = "withPlanningTimingCount")]
    pub with_planning_timing_count: usize,
    #[serde(rename = "averagePlanningElapsedMs", default)]
    pub average_planning_elapsed_ms: Option<f64>,
    #[serde(rename = "maxPlanningElapsedMs", default)]
    pub max_planning_elapsed_ms: Option<u64>,
    pub decisions: Vec<RouteDecisionIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteDecisionProofV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "proofType")]
    pub proof_type: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "reportHash")]
    pub report_hash: String,
    #[serde(rename = "generatedBy")]
    pub generated_by: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteDecisionProofVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub valid: bool,
    #[serde(rename = "expectedReportHash")]
    pub expected_report_hash: String,
    #[serde(rename = "observedReportHash")]
    pub observed_report_hash: String,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteDecisionRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub report: RoutePlannerReportV1,
    pub proof: RouteDecisionProofV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteDecisionLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "decisionPath")]
    pub decision_path: String,
    pub report: RoutePlannerReportV1,
    pub proof: RouteDecisionProofV1,
    pub verification: RouteDecisionProofVerificationV1,
}

impl RouteExecutionTraceV1 {
    pub fn new(request_id: impl Into<String>, selected_route_id: Option<String>) -> Self {
        Self {
            schema_version: "swarm-ai.route-execution-trace.v1".to_string(),
            request_id: request_id.into(),
            selected_route_id,
            attempted_route_ids: Vec::new(),
            fallback_applied: false,
            attempts: Vec::new(),
        }
    }

    pub fn push_attempt(&mut self, attempt: RouteAttemptV1) {
        self.fallback_applied = !self.attempts.is_empty();
        self.attempted_route_ids.push(attempt.route_id.clone());
        self.attempts.push(attempt);
    }
}

pub fn write_route_execution_trace(
    route_trace_dir: &Path,
    trace: &RouteExecutionTraceV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(route_trace_dir)?;
    let path = route_trace_path(route_trace_dir, &trace.request_id);
    fs::write(&path, serde_json::to_vec_pretty(trace)?)?;
    Ok(path)
}

pub fn get_route_execution_trace(
    route_trace_dir: &Path,
    request_id: &str,
) -> anyhow::Result<Option<RouteTraceLookupV1>> {
    let path = route_trace_path(route_trace_dir, request_id);
    if !path.exists() {
        return Ok(None);
    }
    let trace = read_route_execution_trace(&path)?;
    Ok(Some(route_trace_lookup(trace, path)))
}

pub fn list_route_execution_traces(
    route_trace_dir: &Path,
) -> anyhow::Result<RouteTraceStoreSummaryV1> {
    let mut traces = Vec::new();
    if route_trace_dir.exists() {
        for entry in fs::read_dir(route_trace_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let trace = read_route_execution_trace(&path)?;
                traces.push(route_trace_index_entry(&trace, path.display().to_string()));
            }
        }
    }
    traces.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    let fallback_trace_count = traces.iter().filter(|trace| trace.fallback_applied).count();
    let failed_trace_count = traces
        .iter()
        .filter(|trace| trace.final_status == Some(ExecutionStatus::Failed))
        .count();
    Ok(RouteTraceStoreSummaryV1 {
        schema_version: "swarm-ai.route-trace-store-summary.v1".to_string(),
        root: route_trace_dir.display().to_string(),
        trace_count: traces.len(),
        fallback_trace_count,
        failed_trace_count,
        traces,
    })
}

pub fn write_route_decision(
    route_audit_dir: &Path,
    report: &RoutePlannerReportV1,
) -> anyhow::Result<PathBuf> {
    let decisions_dir = route_decisions_dir(route_audit_dir);
    fs::create_dir_all(&decisions_dir)?;
    let path = route_decision_path(route_audit_dir, &report.plan.request_id);
    let record = route_decision_record(report);
    fs::write(&path, serde_json::to_vec_pretty(&record)?)?;
    Ok(path)
}

pub fn get_route_decision(
    route_audit_dir: &Path,
    request_id: &str,
) -> anyhow::Result<Option<RouteDecisionLookupV1>> {
    let path = route_decision_path(route_audit_dir, request_id);
    if !path.exists() {
        return Ok(None);
    }
    let record = read_route_decision(&path)?;
    Ok(Some(route_decision_lookup(record, path)))
}

pub fn list_route_decisions(route_audit_dir: &Path) -> anyhow::Result<RouteDecisionStoreSummaryV1> {
    let mut decisions = Vec::new();
    let decisions_dir = route_decisions_dir(route_audit_dir);
    if decisions_dir.exists() {
        for entry in fs::read_dir(&decisions_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let record = read_route_decision(&path)?;
                decisions.push(route_decision_index_entry(
                    &record,
                    path.display().to_string(),
                ));
            }
        }
    }
    decisions.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    let with_selected_route_count = decisions
        .iter()
        .filter(|decision| decision.selected_route_id.is_some())
        .count();
    let fallback_planned_count = decisions
        .iter()
        .filter(|decision| decision.fallback_route_count > 0)
        .count();
    let valid_proof_count = decisions
        .iter()
        .filter(|decision| decision.proof_valid)
        .count();
    let planning_elapsed_values: Vec<u64> = decisions
        .iter()
        .filter_map(|decision| decision.planning_elapsed_ms)
        .collect();
    let with_planning_timing_count = planning_elapsed_values.len();
    let average_planning_elapsed_ms = if planning_elapsed_values.is_empty() {
        None
    } else {
        Some(
            planning_elapsed_values.iter().copied().sum::<u64>() as f64
                / planning_elapsed_values.len() as f64,
        )
    };
    let max_planning_elapsed_ms = planning_elapsed_values.iter().copied().max();
    Ok(RouteDecisionStoreSummaryV1 {
        schema_version: "swarm-ai.route-decision-store-summary.v1".to_string(),
        root: route_audit_dir.display().to_string(),
        decision_count: decisions.len(),
        with_selected_route_count,
        rejected_only_count: decisions.len().saturating_sub(with_selected_route_count),
        fallback_planned_count,
        valid_proof_count,
        invalid_proof_count: decisions.len().saturating_sub(valid_proof_count),
        with_planning_timing_count,
        average_planning_elapsed_ms,
        max_planning_elapsed_ms,
        decisions,
    })
}

pub fn route_decision_record(report: &RoutePlannerReportV1) -> RouteDecisionRecordV1 {
    RouteDecisionRecordV1 {
        schema_version: "swarm-ai.route-decision-record.v1".to_string(),
        request_id: report.plan.request_id.clone(),
        report: report.clone(),
        proof: route_decision_proof(report),
    }
}

pub fn route_decision_proof(report: &RoutePlannerReportV1) -> RouteDecisionProofV1 {
    RouteDecisionProofV1 {
        schema_version: "swarm-ai.route-decision-proof.v1".to_string(),
        proof_type: "canonical-sha256-local-dev".to_string(),
        request_id: report.plan.request_id.clone(),
        report_hash: route_decision_report_hash(report),
        generated_by: "hivemind-router".to_string(),
    }
}

pub fn route_decision_report_hash(report: &RoutePlannerReportV1) -> String {
    let value = serde_json::to_value(report).expect("route report should serialize");
    hash_canonical_json(&value)
}

pub fn verify_route_decision_proof(
    report: &RoutePlannerReportV1,
    proof: &RouteDecisionProofV1,
) -> RouteDecisionProofVerificationV1 {
    let observed_report_hash = route_decision_report_hash(report);
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if proof.schema_version != "swarm-ai.route-decision-proof.v1" {
        issues.push(validation_issue(
            "$.proof.schemaVersion",
            "Expected schemaVersion to be swarm-ai.route-decision-proof.v1",
        ));
    }
    if proof.proof_type != "canonical-sha256-local-dev" {
        issues.push(validation_issue(
            "$.proof.proofType",
            "Route decision proof type is not supported",
        ));
    }
    if proof.request_id != report.plan.request_id {
        issues.push(validation_issue(
            "$.proof.requestId",
            "Route decision proof requestId must match report plan requestId",
        ));
    }
    if proof.report_hash != observed_report_hash {
        issues.push(validation_issue(
            "$.proof.reportHash",
            "Route decision proof hash does not match canonical report hash",
        ));
    }
    if proof.generated_by.trim().is_empty() {
        warnings.push(validation_issue(
            "$.proof.generatedBy",
            "Route decision proof does not identify a generator",
        ));
    }

    RouteDecisionProofVerificationV1 {
        schema_version: "swarm-ai.route-decision-proof-verification.v1".to_string(),
        request_id: report.plan.request_id.clone(),
        valid: issues.is_empty(),
        expected_report_hash: proof.report_hash.clone(),
        observed_report_hash,
        issues,
        warnings,
    }
}

pub fn plan_route(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runner: &RunnerDescriptorV1,
    policy_mode: PolicyMode,
) -> RoutePlanV1 {
    plan_routes(request, package, &[runner.clone()], policy_mode)
}

fn read_route_execution_trace(path: &Path) -> anyhow::Result<RouteExecutionTraceV1> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_route_decision(path: &Path) -> anyhow::Result<RouteDecisionRecordV1> {
    let bytes = fs::read(path)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    if value
        .get("schemaVersion")
        .and_then(Value::as_str)
        .is_some_and(|version| version == "swarm-ai.route-decision-record.v1")
    {
        Ok(serde_json::from_value(value)?)
    } else {
        let report: RoutePlannerReportV1 = serde_json::from_value(value)?;
        Ok(route_decision_record(&report))
    }
}

fn route_trace_lookup(trace: RouteExecutionTraceV1, path: PathBuf) -> RouteTraceLookupV1 {
    RouteTraceLookupV1 {
        schema_version: "swarm-ai.route-trace-lookup.v1".to_string(),
        request_id: trace.request_id.clone(),
        trace_path: path.display().to_string(),
        trace,
    }
}

fn route_decision_lookup(record: RouteDecisionRecordV1, path: PathBuf) -> RouteDecisionLookupV1 {
    let verification = verify_route_decision_proof(&record.report, &record.proof);
    RouteDecisionLookupV1 {
        schema_version: "swarm-ai.route-decision-lookup.v1".to_string(),
        request_id: record.report.plan.request_id.clone(),
        decision_path: path.display().to_string(),
        report: record.report,
        proof: record.proof,
        verification,
    }
}

fn route_trace_index_entry(
    trace: &RouteExecutionTraceV1,
    trace_path: String,
) -> RouteTraceIndexEntryV1 {
    let mut runner_ids: Vec<_> = trace
        .attempts
        .iter()
        .filter_map(|attempt| attempt.runner_id.clone())
        .collect();
    runner_ids.sort();
    runner_ids.dedup();
    RouteTraceIndexEntryV1 {
        request_id: trace.request_id.clone(),
        selected_route_id: trace.selected_route_id.clone(),
        attempted_route_count: trace.attempts.len(),
        fallback_applied: trace.fallback_applied,
        final_status: trace.attempts.last().map(|attempt| attempt.status.clone()),
        runner_ids,
        trace_ref: route_trace_ref(&trace.request_id),
        trace_path,
    }
}

fn route_decision_index_entry(
    record: &RouteDecisionRecordV1,
    decision_path: String,
) -> RouteDecisionIndexEntryV1 {
    let report = &record.report;
    let verification = verify_route_decision_proof(&record.report, &record.proof);
    let selected = report.plan.selected_route_id.as_ref().and_then(|route_id| {
        report
            .plan
            .candidate_routes
            .iter()
            .find(|candidate| candidate.route_id == *route_id)
    });
    let eligible_candidate_count = report
        .plan
        .candidate_routes
        .iter()
        .filter(|candidate| candidate.decision == RouteDecision::Eligible)
        .count();
    let candidate_count = report.plan.candidate_routes.len();
    RouteDecisionIndexEntryV1 {
        request_id: report.plan.request_id.clone(),
        package_ref: report.plan.package_ref.clone(),
        task: report.plan.task.clone(),
        policy_mode: report.policy_mode.clone(),
        selected_route_id: report.plan.selected_route_id.clone(),
        candidate_count,
        eligible_candidate_count,
        rejected_candidate_count: candidate_count.saturating_sub(eligible_candidate_count),
        fallback_route_count: report.plan.fallback_route_ids.len(),
        quote_count: report.quotes.len(),
        planning_elapsed_ms: report
            .planning_timing
            .as_ref()
            .map(|timing| timing.elapsed_ms),
        proof_hash: Some(record.proof.report_hash.clone()),
        proof_valid: verification.valid,
        selected_estimated_cost: selected.map(|candidate| candidate.estimated.cost),
        selected_estimated_currency: selected.map(|candidate| candidate.estimated.currency.clone()),
        decision_ref: route_decision_ref(&report.plan.request_id),
        decision_path,
    }
}

pub fn route_trace_ref(request_id: &str) -> String {
    format!("local://route-trace/{}", safe_record_component(request_id))
}

pub fn route_decision_ref(request_id: &str) -> String {
    format!(
        "local://route-decision/{}",
        safe_record_component(request_id)
    )
}

fn route_trace_path(route_trace_dir: &Path, request_id: &str) -> PathBuf {
    route_trace_dir.join(format!("{}.json", safe_record_component(request_id)))
}

fn route_decision_path(route_audit_dir: &Path, request_id: &str) -> PathBuf {
    route_decisions_dir(route_audit_dir).join(format!("{}.json", safe_record_component(request_id)))
}

fn route_decisions_dir(route_audit_dir: &Path) -> PathBuf {
    route_audit_dir.join("decisions")
}

fn validation_issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn safe_record_component(value: &str) -> String {
    let component: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let component = component.trim_matches('_');
    if component.is_empty() {
        "record".to_string()
    } else {
        component.to_string()
    }
}

pub fn plan_routes(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    policy_mode: PolicyMode,
) -> RoutePlanV1 {
    plan_routes_with_reputation(request, package, runners, policy_mode, &[])
}

pub fn plan_routes_with_reputation(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    policy_mode: PolicyMode,
    runner_reputation: &[RunnerReputationSummaryV1],
) -> RoutePlanV1 {
    plan_routes_with_marketplace_offers_and_reputation(
        request,
        package,
        runners,
        &[],
        policy_mode,
        0,
        runner_reputation,
    )
}

pub fn plan_routes_with_marketplace_offers(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    offers: &[RunnerOfferV1],
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
) -> RoutePlanV1 {
    plan_routes_with_marketplace_offers_and_reputation(
        request,
        package,
        runners,
        offers,
        policy_mode,
        max_marketplace_results,
        &[],
    )
}

pub fn plan_routes_with_marketplace_offers_and_reputation(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    offers: &[RunnerOfferV1],
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
    runner_reputation: &[RunnerReputationSummaryV1],
) -> RoutePlanV1 {
    plan_routes_with_miner_capacity_and_reputation(
        request,
        package,
        runners,
        offers,
        &[],
        policy_mode,
        max_marketplace_results,
        runner_reputation,
    )
}

pub fn plan_routes_with_miner_capacity_and_reputation(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    offers: &[RunnerOfferV1],
    miner_capacity: &[MinerCapacityInputV1],
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
    runner_reputation: &[RunnerReputationSummaryV1],
) -> RoutePlanV1 {
    plan_routes_with_trust_policy(
        request,
        package,
        runners,
        offers,
        miner_capacity,
        policy_mode,
        max_marketplace_results,
        runner_reputation,
        None,
    )
}

pub fn plan_routes_with_trust_policy(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    offers: &[RunnerOfferV1],
    miner_capacity: &[MinerCapacityInputV1],
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
    runner_reputation: &[RunnerReputationSummaryV1],
    trust_policy: Option<&TrustPolicyV1>,
) -> RoutePlanV1 {
    plan_routes_with_marketplace_shortlist_and_reputation(
        request,
        package,
        runners,
        marketplace_shortlist(
            request,
            offers,
            policy_mode.clone(),
            max_marketplace_results,
        )
        .as_ref(),
        miner_capacity,
        policy_mode,
        runner_reputation,
        trust_policy,
    )
}

pub fn plan_routes_with_marketplace_shortlist(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    marketplace_shortlist: Option<&MarketplaceShortlistV1>,
    policy_mode: PolicyMode,
) -> RoutePlanV1 {
    plan_routes_with_marketplace_shortlist_and_reputation(
        request,
        package,
        runners,
        marketplace_shortlist,
        &[],
        policy_mode,
        &[],
        None,
    )
}

pub fn plan_routes_with_marketplace_shortlist_and_reputation(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    marketplace_shortlist: Option<&MarketplaceShortlistV1>,
    miner_capacity: &[MinerCapacityInputV1],
    policy_mode: PolicyMode,
    runner_reputation: &[RunnerReputationSummaryV1],
    trust_policy: Option<&TrustPolicyV1>,
) -> RoutePlanV1 {
    let request_access = access_for_runner(request, package, None);
    let mut candidates =
        runner_candidates(request, package, runners, &policy_mode, runner_reputation);
    if let Some(shortlist) = marketplace_shortlist {
        candidates.extend(shortlist.rankings.iter().map(|ranking| {
            marketplace_candidate(request, ranking, package, &policy_mode, runner_reputation)
        }));
    }
    let signals = miner_capacity_signals(
        request,
        package,
        miner_capacity,
        &policy_mode,
        runner_reputation,
        trust_policy,
    );
    candidates.extend(signals.iter().map(miner_capacity_candidate));
    apply_trust_policy_to_candidates(&mut candidates, package, runner_reputation, trust_policy);

    finish_plan(request, package, candidates, policy_mode, request_access)
}

pub fn marketplace_shortlist(
    request: &ExecutionRequestV1,
    offers: &[RunnerOfferV1],
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
) -> Option<MarketplaceShortlistV1> {
    if offers.is_empty() || max_marketplace_results == 0 {
        return None;
    }
    let shortlist_request =
        shortlist_request_from_execution(request, policy_mode, max_marketplace_results);
    Some(shortlist_runner_offers(&shortlist_request, offers))
}

pub fn planner_report(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    policy_mode: PolicyMode,
) -> RoutePlannerReportV1 {
    planner_report_with_reputation(request, package, runners, policy_mode, &[])
}

pub fn planner_report_with_reputation(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    policy_mode: PolicyMode,
    runner_reputation: &[RunnerReputationSummaryV1],
) -> RoutePlannerReportV1 {
    let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let started = Instant::now();
    let plan = plan_routes_with_reputation(
        request,
        package,
        runners,
        policy_mode.clone(),
        runner_reputation,
    );
    let quotes = cost_quotes(&plan, runners);
    let mut report = RoutePlannerReportV1 {
        schema_version: "swarm-ai.route-planner-report.v1".to_string(),
        job_order: Some(job_order_from_execution_request(
            request,
            "local-dev",
            ApiSurface::HivemindNative,
        )),
        plan,
        quotes,
        marketplace_shortlist: None,
        runner_reputation: runner_reputation.to_vec(),
        miner_capacity: Vec::new(),
        trust_policy: None,
        policy_mode,
        planning_timing: None,
    };
    stamp_route_planner_timing(&mut report, Some((started_at, started)));
    report
}

pub fn planner_report_with_marketplace_offers(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    offers: &[RunnerOfferV1],
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
) -> RoutePlannerReportV1 {
    planner_report_with_marketplace_offers_and_reputation(
        request,
        package,
        runners,
        offers,
        policy_mode,
        max_marketplace_results,
        &[],
    )
}

pub fn planner_report_with_marketplace_offers_and_reputation(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    offers: &[RunnerOfferV1],
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
    runner_reputation: &[RunnerReputationSummaryV1],
) -> RoutePlannerReportV1 {
    planner_report_with_miner_capacity_and_reputation(
        request,
        package,
        runners,
        offers,
        &[],
        policy_mode,
        max_marketplace_results,
        runner_reputation,
    )
}

pub fn planner_report_with_miner_capacity_and_reputation(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    offers: &[RunnerOfferV1],
    miner_capacity: &[MinerCapacityInputV1],
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
    runner_reputation: &[RunnerReputationSummaryV1],
) -> RoutePlannerReportV1 {
    planner_report_with_trust_policy(
        request,
        package,
        runners,
        offers,
        miner_capacity,
        policy_mode,
        max_marketplace_results,
        runner_reputation,
        None,
    )
}

pub fn planner_report_with_trust_policy(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    offers: &[RunnerOfferV1],
    miner_capacity: &[MinerCapacityInputV1],
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
    runner_reputation: &[RunnerReputationSummaryV1],
    trust_policy: Option<&TrustPolicyV1>,
) -> RoutePlannerReportV1 {
    let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let started = Instant::now();
    let shortlist = marketplace_shortlist(
        request,
        offers,
        policy_mode.clone(),
        max_marketplace_results,
    );
    let miner_signals = miner_capacity_signals(
        request,
        package,
        miner_capacity,
        &policy_mode,
        runner_reputation,
        trust_policy,
    );
    let plan = plan_routes_with_marketplace_shortlist_and_reputation(
        request,
        package,
        runners,
        shortlist.as_ref(),
        miner_capacity,
        policy_mode.clone(),
        runner_reputation,
        trust_policy,
    );
    let quotes = cost_quotes(&plan, runners);
    let mut report = RoutePlannerReportV1 {
        schema_version: "swarm-ai.route-planner-report.v1".to_string(),
        job_order: Some(job_order_from_execution_request(
            request,
            "local-dev",
            ApiSurface::HivemindNative,
        )),
        plan,
        quotes,
        marketplace_shortlist: shortlist,
        runner_reputation: runner_reputation.to_vec(),
        miner_capacity: miner_signals,
        trust_policy: trust_policy.cloned(),
        policy_mode,
        planning_timing: None,
    };
    stamp_route_planner_timing(&mut report, Some((started_at, started)));
    report
}

pub fn stamp_route_planner_timing(
    report: &mut RoutePlannerReportV1,
    started: Option<(String, Instant)>,
) {
    let (started_at, elapsed_ms) = if let Some((started_at, started)) = started {
        (
            started_at,
            started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        )
    } else {
        (Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true), 0)
    };
    let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let eligible_candidate_count = report
        .plan
        .candidate_routes
        .iter()
        .filter(|candidate| candidate.decision == RouteDecision::Eligible)
        .count();
    report.planning_timing = Some(RoutePlannerTimingV1 {
        schema_version: "swarm-ai.route-planner-timing.v1".to_string(),
        started_at,
        completed_at,
        elapsed_ms,
        candidate_count: report.plan.candidate_routes.len(),
        eligible_candidate_count,
    });
}

pub fn cost_quotes(plan: &RoutePlanV1, runners: &[RunnerDescriptorV1]) -> Vec<CostQuoteV1> {
    plan.candidate_routes
        .iter()
        .map(|candidate| {
            let runner = candidate
                .runner_id
                .as_deref()
                .and_then(|runner_id| runners.iter().find(|runner| runner.runner_id == runner_id));
            CostQuoteV1 {
                schema_version: "swarm-ai.cost-quote.v1".to_string(),
                route_id: candidate.route_id.clone(),
                runner_id: candidate.runner_id.clone(),
                runner_type: candidate.runner_type.clone(),
                estimated_cost: candidate.estimated.cost,
                currency: candidate.estimated.currency.clone(),
                queue_ms: candidate.estimated.queue_ms,
                first_token_ms: candidate.estimated.first_token_ms,
                privacy: candidate.estimated.privacy.clone(),
                warm: runner
                    .map(|runner| !runner.warm_package_refs.is_empty())
                    .unwrap_or(false),
                quality_score: candidate
                    .quality_score
                    .unwrap_or_else(|| quality_score(&candidate.runner_type)),
                reasons: candidate.reason.clone().into_iter().collect(),
            }
        })
        .collect()
}

fn runner_candidates(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    policy_mode: &PolicyMode,
    runner_reputation: &[RunnerReputationSummaryV1],
) -> Vec<CandidateRoute> {
    let mut candidates = Vec::new();
    for runner in runners {
        let access = access_for_runner(request, package, Some(&runner.runner_id));
        let mut single = hivemind_core::plan_route_for_runner(
            request,
            &package.manifest,
            &request.package_ref,
            runner,
            policy_mode.clone(),
        );
        let Some(mut candidate) = single.candidate_routes.pop() else {
            continue;
        };
        apply_estimates(&mut candidate, runner, request, package);
        apply_reputation(&mut candidate, &runner.runner_id, runner_reputation);
        if access.decision != AccessDecision::Granted {
            candidate.decision = RouteDecision::Rejected;
            candidate.reason = Some(access.reasons.join("; "));
        }
        candidates.push(candidate);
    }
    candidates
}

fn marketplace_candidate(
    request: &ExecutionRequestV1,
    ranking: &RunnerOfferScoreV1,
    package: &LocalPackage,
    policy_mode: &PolicyMode,
    runner_reputation: &[RunnerReputationSummaryV1],
) -> CandidateRoute {
    let access = access_for_runner(request, package, Some(&ranking.runner_id));
    let mut decision = if ranking.eligible {
        RouteDecision::Eligible
    } else {
        RouteDecision::Rejected
    };
    let mut reasons = ranking.reasons.clone();
    let policy = evaluate_package_policy(
        &package.manifest,
        &request.package_ref,
        Some(ranking.runner_id.clone()),
    );
    if let Some(policy_reason) = policy_route_block_reason(&policy, policy_mode) {
        decision = RouteDecision::Rejected;
        reasons.push(policy_reason);
    }
    if !manifest_supports_capability(&package.manifest, &request.task) {
        decision = RouteDecision::Rejected;
        reasons.push(format!(
            "Package does not declare support for task {}",
            request.task
        ));
    }
    if *policy_mode == PolicyMode::PrivacyFirst
        && matches!(
            ranking.runner_type,
            RunnerType::RemoteGpu | RunnerType::Marketplace
        )
    {
        decision = RouteDecision::Rejected;
        reasons.push("Privacy-first policy avoids marketplace or remote GPU execution".to_string());
    }
    if access.decision != AccessDecision::Granted {
        decision = RouteDecision::Rejected;
        reasons.push(access.reasons.join("; "));
    }
    let quality_score =
        if let Some(reputation) = reputation_for_runner(&ranking.runner_id, runner_reputation) {
            let score = effective_reputation_score(reputation);
            reasons.push(reputation_reason(reputation, score));
            score
        } else {
            ranking.validator_score.clamp(0.0, 1.0)
        };

    CandidateRoute {
        route_id: format!("marketplace-offer-{}", ranking.offer_id),
        runner_type: RunnerType::Marketplace,
        runner_id: Some(ranking.runner_id.clone()),
        artifact_group: None,
        estimated: RouteEstimate {
            cost: ranking.estimated_cost,
            currency: ranking.currency.clone(),
            queue_ms: 0,
            first_token_ms: ranking.first_token_ms,
            privacy: ranking
                .selected_privacy_tier
                .as_ref()
                .map(|tier| format!("marketplace:{}", tier_name(tier)))
                .unwrap_or_else(|| {
                    match ranking.runner_type {
                        RunnerType::Browser | RunnerType::Local => "local",
                        RunnerType::RemoteGpu | RunnerType::Marketplace => "remote",
                    }
                    .to_string()
                }),
        },
        quality_score: Some(quality_score),
        policy_decision: Some(policy),
        decision,
        reason: Some(reasons.join("; ")),
    }
}

pub fn miner_capacity_signals(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    miner_capacity: &[MinerCapacityInputV1],
    policy_mode: &PolicyMode,
    runner_reputation: &[RunnerReputationSummaryV1],
    trust_policy: Option<&TrustPolicyV1>,
) -> Vec<MinerCapacitySignalV1> {
    miner_capacity
        .iter()
        .map(|input| {
            miner_capacity_signal(
                request,
                package,
                input,
                policy_mode,
                runner_reputation,
                trust_policy,
            )
        })
        .collect()
}

fn miner_capacity_signal(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    input: &MinerCapacityInputV1,
    policy_mode: &PolicyMode,
    runner_reputation: &[RunnerReputationSummaryV1],
    trust_policy: Option<&TrustPolicyV1>,
) -> MinerCapacitySignalV1 {
    let offer = &input.hardware_offer;
    let mut decision = RouteDecision::Eligible;
    let mut reasons = Vec::new();
    let offer_verification = hivemind_marketplace::verify_hardware_resource_offer(offer);
    if offer_verification.valid {
        reasons.push("Hardware offer signature and required fields are valid".to_string());
    } else {
        decision = RouteDecision::Rejected;
        reasons.extend(offer_verification.issues.iter().map(|issue| {
            format!(
                "Hardware offer invalid at {}: {}",
                issue.path, issue.message
            )
        }));
    }

    let artifact_group = artifact_for_hardware_offer(request, package, offer);
    if artifact_group.is_none() {
        decision = RouteDecision::Rejected;
        reasons.push("Hardware offer does not support a matching artifact engine".to_string());
    }

    let policy = evaluate_package_policy(
        &package.manifest,
        &request.package_ref,
        Some(offer.runner_id.clone()),
    );
    if let Some(policy_reason) = policy_route_block_reason(&policy, policy_mode) {
        decision = RouteDecision::Rejected;
        reasons.push(policy_reason);
    }
    if !manifest_supports_capability(&package.manifest, &request.task) {
        decision = RouteDecision::Rejected;
        reasons.push(format!(
            "Package does not declare support for task {}",
            request.task
        ));
    }
    if !hardware_offer_supports_task(offer, &request.task) {
        decision = RouteDecision::Rejected;
        reasons.push(format!(
            "Hardware offer does not declare support for task {}",
            request.task
        ));
    }
    if *policy_mode == PolicyMode::PrivacyFirst {
        decision = RouteDecision::Rejected;
        reasons.push("Privacy-first policy avoids marketplace miner execution".to_string());
    }

    let access = access_for_runner(request, package, Some(&offer.runner_id));
    if access.decision != AccessDecision::Granted {
        decision = RouteDecision::Rejected;
        reasons.push(access.reasons.join("; "));
    }

    let heartbeat = input.heartbeat.as_ref();
    let miner_id = heartbeat.map(|heartbeat| heartbeat.miner_id.clone());
    if let Some(heartbeat) = heartbeat {
        let heartbeat_verification = hivemind_miner::verify_miner_heartbeat(heartbeat, None);
        if !heartbeat_verification.valid {
            decision = RouteDecision::Rejected;
            reasons.extend(heartbeat_verification.issues.iter().map(|issue| {
                format!(
                    "Miner heartbeat invalid at {}: {}",
                    issue.path, issue.message
                )
            }));
        }
        if heartbeat.runner_id != offer.runner_id {
            decision = RouteDecision::Rejected;
            reasons.push("Miner heartbeat runnerId does not match hardware offer".to_string());
        }
        match heartbeat.status {
            MinerDaemonStatus::Available => {
                reasons.push("Miner heartbeat reports available capacity".to_string());
            }
            MinerDaemonStatus::Busy => {
                reasons.push("Miner heartbeat reports busy capacity".to_string());
            }
            MinerDaemonStatus::Starting => {
                decision = RouteDecision::Rejected;
                reasons.push("Miner heartbeat reports starting status".to_string());
            }
            MinerDaemonStatus::Draining => {
                decision = RouteDecision::Rejected;
                reasons.push("Miner heartbeat reports draining status".to_string());
            }
            MinerDaemonStatus::Offline => {
                decision = RouteDecision::Rejected;
                reasons.push("Miner heartbeat reports offline status".to_string());
            }
            MinerDaemonStatus::Error => {
                decision = RouteDecision::Rejected;
                reasons.push("Miner heartbeat reports error status".to_string());
            }
        }
    } else {
        reasons.push("No miner heartbeat was provided; using offer availability only".to_string());
    }

    if !offer.availability.available_now {
        decision = RouteDecision::Rejected;
        reasons.push("Hardware offer is not currently available".to_string());
    }

    let queue_depth = heartbeat
        .map(|heartbeat| heartbeat.queue_depth)
        .unwrap_or(offer.availability.queue_depth);
    let active_jobs = heartbeat
        .map(|heartbeat| heartbeat.active_jobs)
        .unwrap_or(0);
    let max_concurrent_jobs = offer.availability.max_concurrent_jobs.max(1);
    if active_jobs >= max_concurrent_jobs && queue_depth > 0 {
        decision = RouteDecision::Rejected;
        reasons.push("Miner capacity is saturated at maxConcurrentJobs".to_string());
    }
    if queue_depth > 64 {
        decision = RouteDecision::Rejected;
        reasons.push("Miner queue depth is too high for new interactive routing".to_string());
    } else if queue_depth > 0 {
        reasons.push(format!("Miner queue depth is {queue_depth}"));
    }

    let available_ram_gb = heartbeat
        .map(|heartbeat| heartbeat.available_ram_gb)
        .unwrap_or(offer.hardware.ram_gb);
    let available_vram_gb = heartbeat
        .and_then(|heartbeat| heartbeat.available_vram_gb)
        .or(offer.hardware.vram_gb);
    if let Some(artifact) = artifact_group.as_ref() {
        if let Some(required_memory_mb) = artifact.minimum.memory_mb {
            let required_gb = required_memory_mb as f64 / 1024.0;
            if available_ram_gb + f64::EPSILON < required_gb {
                decision = RouteDecision::Rejected;
                reasons.push(format!(
                    "Insufficient RAM: requires {:.2} GiB, available {:.2} GiB",
                    required_gb, available_ram_gb
                ));
            }
            if offer.hardware.gpu_count > 0
                && available_vram_gb
                    .map(|vram| vram + f64::EPSILON < required_gb)
                    .unwrap_or(true)
            {
                decision = RouteDecision::Rejected;
                reasons.push(format!(
                    "Insufficient GPU VRAM: requires {:.2} GiB, available {} GiB",
                    required_gb,
                    available_vram_gb
                        .map(|value| format!("{value:.2}"))
                        .unwrap_or_else(|| "unknown".to_string())
                ));
            }
        }
        if let Some(required_disk_mb) = artifact.minimum.disk_mb
            && let Some(available_disk_gb) = offer.hardware.disk_gb
        {
            let required_gb = required_disk_mb as f64 / 1024.0;
            if available_disk_gb + f64::EPSILON < required_gb {
                decision = RouteDecision::Rejected;
                reasons.push(format!(
                    "Insufficient disk: requires {:.2} GiB, available {:.2} GiB",
                    required_gb, available_disk_gb
                ));
            }
        }
    }

    let valid_benchmark_count = input
        .benchmarks
        .iter()
        .filter(|benchmark| {
            hivemind_miner::verify_miner_benchmark_result(benchmark, None, Some(offer)).valid
        })
        .count();
    if !input.benchmarks.is_empty() {
        reasons.push(format!(
            "{valid_benchmark_count} of {} benchmark records verify for this offer",
            input.benchmarks.len()
        ));
    }
    if valid_benchmark_count == 0 && !offer.benchmark_result_refs.is_empty() {
        reasons.push(
            "Hardware offer references benchmark evidence not present in route input".to_string(),
        );
    }

    let warm_cache = offer
        .cache_claims
        .iter()
        .chain(
            heartbeat
                .map(|heartbeat| heartbeat.cache_claims.iter())
                .into_iter()
                .flatten(),
        )
        .any(|claim| {
            claim.warmed
                && (claim.package_ref == request.package_ref
                    || claim.package_ref == package.package_ref)
        });
    let estimated_queue_ms = u64::from(queue_depth) * 75 + u64::from(active_jobs) * 125;
    let estimated_first_token_ms = if warm_cache { 500 } else { 1_200 };
    let selected_privacy_tier = select_privacy_tier_for_policy(&offer.privacy_tiers, trust_policy);
    let selected_verification_tier =
        select_integrity_tier_for_policy(&offer.verification_tiers, trust_policy);
    let (estimated_cost, currency) =
        estimate_miner_cost(offer.price_table.first(), estimate_input_tokens(request));
    let estimated_latency_ms = estimated_queue_ms + estimated_first_token_ms;
    let quality_score = miner_quality_score(
        offer,
        valid_benchmark_count,
        reputation_for_runner(&offer.runner_id, runner_reputation),
    );
    apply_trust_policy_to_miner_signal(
        trust_policy,
        offer,
        package,
        selected_privacy_tier.as_ref(),
        selected_verification_tier.as_ref(),
        estimated_cost,
        &currency,
        estimated_latency_ms,
        valid_benchmark_count,
        reputation_for_runner(&offer.runner_id, runner_reputation),
        &mut decision,
        &mut reasons,
    );

    MinerCapacitySignalV1 {
        schema_version: "swarm-ai.miner-capacity-signal.v1".to_string(),
        route_id: format!("miner-offer-{}", offer.offer_id),
        offer_id: offer.offer_id.clone(),
        runner_id: offer.runner_id.clone(),
        miner_id,
        operator: offer.operator.clone(),
        trust_tier: offer.trust_tier.clone(),
        privacy_tiers: offer.privacy_tiers.clone(),
        verification_tiers: offer.verification_tiers.clone(),
        decision,
        reasons,
        selected_artifact_group: artifact_group.map(|group| group.id.clone()),
        queue_depth,
        active_jobs,
        max_concurrent_jobs,
        estimated_queue_ms,
        estimated_first_token_ms,
        estimated_cost,
        currency,
        warm_cache,
        benchmark_count: input.benchmarks.len(),
        valid_benchmark_count,
        quality_score,
        available_vram_gb,
        available_ram_gb,
        selected_privacy_tier,
        selected_verification_tier,
    }
}

fn miner_capacity_candidate(signal: &MinerCapacitySignalV1) -> CandidateRoute {
    CandidateRoute {
        route_id: signal.route_id.clone(),
        runner_type: RunnerType::Marketplace,
        runner_id: Some(signal.runner_id.clone()),
        artifact_group: signal.selected_artifact_group.clone(),
        estimated: RouteEstimate {
            cost: signal.estimated_cost,
            currency: signal.currency.clone(),
            queue_ms: signal.estimated_queue_ms,
            first_token_ms: signal.estimated_first_token_ms,
            privacy: signal
                .selected_privacy_tier
                .as_ref()
                .map(|tier| format!("remote:{}", tier_name(tier)))
                .unwrap_or_else(|| "remote".to_string()),
        },
        quality_score: Some(signal.quality_score),
        policy_decision: None,
        decision: signal.decision.clone(),
        reason: Some(signal.reasons.join("; ")),
    }
}

fn apply_trust_policy_to_candidates(
    candidates: &mut [CandidateRoute],
    package: &LocalPackage,
    runner_reputation: &[RunnerReputationSummaryV1],
    trust_policy: Option<&TrustPolicyV1>,
) {
    let Some(policy) = trust_policy else {
        return;
    };
    for candidate in candidates {
        if !policy_allows_publisher(policy, package) {
            candidate.decision = RouteDecision::Rejected;
            append_candidate_reason(
                candidate,
                "Trust policy does not allow this package publisher",
            );
        }
        if let Some(runner_id) = candidate.runner_id.clone() {
            if !trust_policy_allows_runner(policy, &runner_id) {
                candidate.decision = RouteDecision::Rejected;
                append_candidate_reason(candidate, "Trust policy does not allow this runner");
            }
            if policy.require_validation
                && reputation_for_runner(&runner_id, runner_reputation).is_none()
            {
                candidate.decision = RouteDecision::Rejected;
                append_candidate_reason(
                    candidate,
                    "Trust policy requires validation evidence for this runner",
                );
            }
        }
        let privacy_tier = candidate_privacy_tier(candidate);
        if !privacy_tier_allowed(privacy_tier.as_ref(), &policy.allowed_privacy_tiers) {
            candidate.decision = RouteDecision::Rejected;
            append_candidate_reason(
                candidate,
                "Trust policy does not allow this route privacy tier",
            );
        }
        if !integrity_tier_allowed(
            &candidate_integrity_tiers(candidate),
            &policy.allowed_verification_tiers,
        ) {
            candidate.decision = RouteDecision::Rejected;
            append_candidate_reason(
                candidate,
                "Trust policy does not allow this route verification tier",
            );
        }
        if let Some(max_price) = &policy.max_price {
            if candidate.estimated.currency != max_price.currency {
                candidate.decision = RouteDecision::Rejected;
                append_candidate_reason(
                    candidate,
                    "Trust policy maxPrice currency does not match route estimate",
                );
            } else if candidate.estimated.cost > max_price.amount {
                candidate.decision = RouteDecision::Rejected;
                append_candidate_reason(candidate, "Trust policy maxPrice is exceeded");
            }
        }
        if let Some(max_latency_ms) = policy.max_latency_ms {
            let latency_ms = candidate.estimated.queue_ms + candidate.estimated.first_token_ms;
            if latency_ms > max_latency_ms {
                candidate.decision = RouteDecision::Rejected;
                append_candidate_reason(candidate, "Trust policy maxLatencyMs is exceeded");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_trust_policy_to_miner_signal(
    trust_policy: Option<&TrustPolicyV1>,
    offer: &HardwareResourceOfferV1,
    package: &LocalPackage,
    selected_privacy_tier: Option<&PrivacyTier>,
    selected_verification_tier: Option<&IntegrityTier>,
    estimated_cost: f64,
    currency: &str,
    estimated_latency_ms: u64,
    valid_benchmark_count: usize,
    reputation: Option<&RunnerReputationSummaryV1>,
    decision: &mut RouteDecision,
    reasons: &mut Vec<String>,
) {
    let Some(policy) = trust_policy else {
        return;
    };
    if !policy_allows_publisher(policy, package) {
        *decision = RouteDecision::Rejected;
        reasons.push("Trust policy does not allow this package publisher".to_string());
    }
    if !trust_policy_allows_runner(policy, &offer.runner_id) {
        *decision = RouteDecision::Rejected;
        reasons.push("Trust policy does not allow this miner runner".to_string());
    }
    if offer.trust_tier == MinerTrustTierV1::Open && !policy.allow_open_miners {
        *decision = RouteDecision::Rejected;
        reasons.push("Trust policy does not allow open miners".to_string());
    }
    if !policy.allow_consumer_gpu && is_consumer_gpu_offer(offer) {
        *decision = RouteDecision::Rejected;
        reasons.push("Trust policy does not allow consumer GPU miners".to_string());
    }
    if !privacy_tier_allowed(selected_privacy_tier, &policy.allowed_privacy_tiers) {
        *decision = RouteDecision::Rejected;
        reasons.push("Trust policy does not allow this miner privacy tier".to_string());
    }
    if !integrity_tier_allowed(
        &selected_verification_tier
            .into_iter()
            .cloned()
            .collect::<Vec<_>>(),
        &policy.allowed_verification_tiers,
    ) {
        *decision = RouteDecision::Rejected;
        reasons.push("Trust policy does not allow this miner verification tier".to_string());
    }
    if let Some(max_price) = &policy.max_price {
        if currency != max_price.currency {
            *decision = RouteDecision::Rejected;
            reasons
                .push("Trust policy maxPrice currency does not match miner estimate".to_string());
        } else if estimated_cost > max_price.amount {
            *decision = RouteDecision::Rejected;
            reasons.push("Trust policy maxPrice is exceeded".to_string());
        }
    }
    if let Some(max_latency_ms) = policy.max_latency_ms
        && estimated_latency_ms > max_latency_ms
    {
        *decision = RouteDecision::Rejected;
        reasons.push("Trust policy maxLatencyMs is exceeded".to_string());
    }
    if policy.require_validation && valid_benchmark_count == 0 && reputation.is_none() {
        *decision = RouteDecision::Rejected;
        reasons.push(
            "Trust policy requires benchmark or validation evidence for this miner".to_string(),
        );
    }
}

fn artifact_for_hardware_offer<'a>(
    request: &ExecutionRequestV1,
    package: &'a LocalPackage,
    offer: &HardwareResourceOfferV1,
) -> Option<&'a ArtifactGroup> {
    package
        .manifest
        .artifact_groups
        .iter()
        .filter(|group| {
            request
                .preferred_artifact_group
                .as_ref()
                .map(|preferred| preferred == &group.id)
                .unwrap_or(true)
        })
        .find(|group| {
            offer
                .supported_engines
                .iter()
                .any(|engine| engine == &group.engine)
        })
        .or_else(|| {
            package
                .manifest
                .artifact_groups
                .iter()
                .filter(|group| request.preferred_artifact_group.as_ref() == Some(&group.id))
                .find(|group| {
                    offer
                        .supported_engines
                        .iter()
                        .any(|engine| engine == &group.engine)
                })
        })
}

fn hardware_offer_supports_task(offer: &HardwareResourceOfferV1, task: &str) -> bool {
    match task {
        "embedding" | "embeddings" => offer.supported_modalities.contains(&Modality::Embedding),
        "chat" | "completion" | "completions" => {
            offer.supported_modalities.contains(&Modality::Chat)
                || offer.supported_modalities.contains(&Modality::Text)
        }
        "ocr" | "image" | "image-generation" | "image-edit" => {
            offer.supported_modalities.contains(&Modality::Image)
        }
        "audio-transcription" | "speech-to-text" | "text-to-speech" => {
            offer.supported_modalities.contains(&Modality::Audio)
        }
        "classification" | "moderation" => {
            offer.supported_modalities.contains(&Modality::Text)
                || offer
                    .supported_modalities
                    .contains(&Modality::StructuredOutput)
        }
        _ => true,
    }
}

fn policy_allows_publisher(policy: &TrustPolicyV1, package: &LocalPackage) -> bool {
    policy.allowed_publishers.is_empty()
        || policy.allowed_publishers.iter().any(|publisher| {
            publisher == &package.manifest.publisher.address
                || publisher == &package.manifest.publisher.display_name
        })
}

fn select_privacy_tier_for_policy(
    tiers: &[PrivacyTier],
    trust_policy: Option<&TrustPolicyV1>,
) -> Option<PrivacyTier> {
    let preferred = preferred_privacy_order();
    if let Some(policy) = trust_policy
        && !policy.allowed_privacy_tiers.is_empty()
    {
        return preferred
            .iter()
            .find(|tier| {
                tiers.contains(tier)
                    && policy
                        .allowed_privacy_tiers
                        .iter()
                        .any(|allowed| privacy_tier_satisfies(tier, allowed))
            })
            .cloned();
    }
    preferred.into_iter().find(|tier| tiers.contains(tier))
}

fn select_integrity_tier_for_policy(
    tiers: &[IntegrityTier],
    trust_policy: Option<&TrustPolicyV1>,
) -> Option<IntegrityTier> {
    let preferred = preferred_integrity_order();
    if let Some(policy) = trust_policy
        && !policy.allowed_verification_tiers.is_empty()
    {
        return preferred
            .iter()
            .find(|tier| {
                tiers.contains(tier)
                    && policy
                        .allowed_verification_tiers
                        .iter()
                        .any(|allowed| integrity_tier_satisfies(tier, allowed))
            })
            .cloned();
    }
    preferred.into_iter().find(|tier| tiers.contains(tier))
}

fn preferred_privacy_order() -> Vec<PrivacyTier> {
    hivemind_core::privacy_tier_preference_order()
}

fn preferred_integrity_order() -> Vec<IntegrityTier> {
    vec![
        IntegrityTier::ZkProofWhenSupported,
        IntegrityTier::TeeAttested,
        IntegrityTier::DeterministicReplay,
        IntegrityTier::RedundantExecution,
        IntegrityTier::ValidatorSpotCheck,
        IntegrityTier::ReceiptOnly,
    ]
}

fn privacy_tier_allowed(selected: Option<&PrivacyTier>, allowed: &[PrivacyTier]) -> bool {
    allowed.is_empty()
        || selected
            .map(|selected| {
                allowed
                    .iter()
                    .any(|allowed| privacy_tier_satisfies(selected, allowed))
            })
            .unwrap_or(false)
}

fn integrity_tier_allowed(selected: &[IntegrityTier], allowed: &[IntegrityTier]) -> bool {
    allowed.is_empty()
        || selected.iter().any(|selected| {
            allowed
                .iter()
                .any(|allowed| integrity_tier_satisfies(selected, allowed))
        })
}

fn privacy_tier_satisfies(available: &PrivacyTier, required: &PrivacyTier) -> bool {
    hivemind_core::privacy_tier_satisfies(available, required)
}

fn integrity_tier_satisfies(available: &IntegrityTier, required: &IntegrityTier) -> bool {
    if available == required {
        return true;
    }
    match available {
        IntegrityTier::ZkProofWhenSupported => true,
        IntegrityTier::TeeAttested => matches!(
            required,
            IntegrityTier::ReceiptOnly
                | IntegrityTier::ValidatorSpotCheck
                | IntegrityTier::TeeAttested
        ),
        IntegrityTier::DeterministicReplay => matches!(
            required,
            IntegrityTier::ReceiptOnly | IntegrityTier::DeterministicReplay
        ),
        IntegrityTier::RedundantExecution => matches!(
            required,
            IntegrityTier::ReceiptOnly
                | IntegrityTier::ValidatorSpotCheck
                | IntegrityTier::RedundantExecution
        ),
        IntegrityTier::ValidatorSpotCheck => matches!(
            required,
            IntegrityTier::ReceiptOnly | IntegrityTier::ValidatorSpotCheck
        ),
        IntegrityTier::ReceiptOnly => matches!(required, IntegrityTier::ReceiptOnly),
    }
}

fn candidate_privacy_tier(candidate: &CandidateRoute) -> Option<PrivacyTier> {
    if candidate.estimated.privacy == "local" {
        return Some(PrivacyTier::LocalOnly);
    }
    let raw = candidate
        .estimated
        .privacy
        .strip_prefix("remote:")
        .unwrap_or(candidate.estimated.privacy.as_str());
    match raw {
        "public" => Some(PrivacyTier::Public),
        "standard" | "remote" => Some(PrivacyTier::Standard),
        "standard-remote" => Some(PrivacyTier::StandardRemote),
        "no-log" => Some(PrivacyTier::NoLog),
        "no-log-remote" => Some(PrivacyTier::NoLogRemote),
        "redacted-input" => Some(PrivacyTier::RedactedInput),
        "local-only" => Some(PrivacyTier::LocalOnly),
        "browser-only" => Some(PrivacyTier::BrowserOnly),
        "encrypted-storage" => Some(PrivacyTier::EncryptedStorage),
        "tee-confidential" => Some(PrivacyTier::TeeConfidential),
        "fhe-encrypted" => Some(PrivacyTier::FheEncrypted),
        "fhe-encrypted-inference" => Some(PrivacyTier::FheEncryptedInference),
        "split-trust-redundant" => Some(PrivacyTier::SplitTrustRedundant),
        "zk-verified-inference" => Some(PrivacyTier::ZkVerifiedInference),
        "mpc-experimental" => Some(PrivacyTier::MpcExperimental),
        _ => None,
    }
}

fn candidate_integrity_tiers(candidate: &CandidateRoute) -> Vec<IntegrityTier> {
    match candidate.runner_type {
        RunnerType::Browser | RunnerType::Local => vec![
            IntegrityTier::ReceiptOnly,
            IntegrityTier::DeterministicReplay,
        ],
        RunnerType::RemoteGpu => vec![
            IntegrityTier::ReceiptOnly,
            IntegrityTier::ValidatorSpotCheck,
        ],
        RunnerType::Marketplace => vec![IntegrityTier::ReceiptOnly],
    }
}

fn is_consumer_gpu_offer(offer: &HardwareResourceOfferV1) -> bool {
    let model = offer
        .hardware
        .gpu_model
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    ["rtx", "geforce", "radeon", "arc"]
        .iter()
        .any(|needle| model.contains(needle))
}

fn estimate_miner_cost(entry: Option<&RunnerPriceEntryV1>, input_tokens: u64) -> (f64, String) {
    let Some(entry) = entry else {
        return (0.02 + input_tokens as f64 * 0.000_002, "xDAI".to_string());
    };
    let units = match &entry.price_model {
        PriceModel::Fixed => 1.0,
        PriceModel::PerToken => input_tokens.max(1) as f64,
        PriceModel::PerSecond => 2.0,
        PriceModel::PerImage => 1.0,
        PriceModel::PerAudioMinute => 1.0,
        PriceModel::PerEmbedding => 1.0,
        PriceModel::PerBatchItem => 1.0,
        PriceModel::Auction => 1.0,
        PriceModel::Subscription => 1.0,
    };
    (entry.price.amount * units, entry.price.currency.clone())
}

fn miner_quality_score(
    offer: &HardwareResourceOfferV1,
    valid_benchmark_count: usize,
    reputation: Option<&RunnerReputationSummaryV1>,
) -> f64 {
    if let Some(reputation) = reputation {
        return effective_reputation_score(reputation);
    }
    let trust = match offer.trust_tier {
        MinerTrustTierV1::Open => 0.55,
        MinerTrustTierV1::Staked => 0.68,
        MinerTrustTierV1::Verified => 0.78,
        MinerTrustTierV1::Confidential => 0.86,
        MinerTrustTierV1::Cryptographic => 0.90,
    };
    let benchmark_bonus = (valid_benchmark_count as f64 * 0.04).min(0.12);
    (trust + benchmark_bonus).min(1.0)
}

fn tier_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn apply_reputation(
    candidate: &mut CandidateRoute,
    runner_id: &str,
    runner_reputation: &[RunnerReputationSummaryV1],
) {
    let Some(reputation) = reputation_for_runner(runner_id, runner_reputation) else {
        return;
    };
    let score = effective_reputation_score(reputation);
    candidate.quality_score = Some(score);
    append_candidate_reason(candidate, &reputation_reason(reputation, score));
}

fn reputation_for_runner<'a>(
    runner_id: &str,
    runner_reputation: &'a [RunnerReputationSummaryV1],
) -> Option<&'a RunnerReputationSummaryV1> {
    runner_reputation
        .iter()
        .filter(|reputation| reputation.runner_id == runner_id && reputation.report_count > 0)
        .max_by(|left, right| {
            left.report_count.cmp(&right.report_count).then_with(|| {
                effective_reputation_score(left)
                    .partial_cmp(&effective_reputation_score(right))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        })
}

fn effective_reputation_score(reputation: &RunnerReputationSummaryV1) -> f64 {
    if reputation.overall_score.is_finite() {
        reputation.overall_score.clamp(0.0, 1.0)
    } else {
        reputation.quality_score.clamp(0.0, 1.0)
    }
}

fn reputation_reason(reputation: &RunnerReputationSummaryV1, score: f64) -> String {
    let report_label = if reputation.report_count == 1 {
        "report"
    } else {
        "reports"
    };
    format!(
        "Validation reputation score {:.2} from {} {}",
        score, reputation.report_count, report_label
    )
}

fn append_candidate_reason(candidate: &mut CandidateRoute, reason: &str) {
    match &mut candidate.reason {
        Some(existing) if !existing.trim().is_empty() => {
            existing.push_str("; ");
            existing.push_str(reason);
        }
        _ => candidate.reason = Some(reason.to_string()),
    }
}

fn access_for_runner(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runner_id: Option<&str>,
) -> AccessEvaluationV1 {
    evaluate_execution_access_with_revocations(
        &package.manifest,
        &request.package_ref,
        &request.request_id,
        "local-dev",
        "runner-service",
        runner_id,
        request.access_grant.as_ref(),
        request.access_revocation_list.as_ref(),
    )
}

fn finish_plan(
    request: &ExecutionRequestV1,
    _package: &LocalPackage,
    candidates: Vec<CandidateRoute>,
    policy_mode: PolicyMode,
    access: AccessEvaluationV1,
) -> RoutePlanV1 {
    let selected_route_id =
        select_candidate(&candidates, &policy_mode).map(|candidate| candidate.route_id.clone());
    let fallback_route_ids =
        fallback_routes(&candidates, selected_route_id.as_deref(), &policy_mode);
    let reason = route_reason(
        &candidates,
        selected_route_id.as_deref(),
        &policy_mode,
        &access,
    );

    RoutePlanV1 {
        schema_version: "swarm-ai.route-plan.v1".to_string(),
        request_id: request.request_id.clone(),
        package_ref: request.package_ref.clone(),
        task: request.task.clone(),
        candidate_routes: candidates,
        selected_route_id,
        fallback_route_ids,
        reason,
    }
}

fn apply_estimates(
    candidate: &mut CandidateRoute,
    runner: &RunnerDescriptorV1,
    request: &ExecutionRequestV1,
    package: &LocalPackage,
) {
    let warm = runner
        .warm_package_refs
        .iter()
        .any(|reference| reference == &package.package_ref || reference == &request.package_ref);
    let input_tokens = estimate_input_tokens(request);
    match runner.runner_type {
        RunnerType::Browser => {
            candidate.estimated.cost = 0.0;
            candidate.estimated.currency = "none".to_string();
            candidate.estimated.queue_ms = 0;
            candidate.estimated.first_token_ms = if warm { 150 } else { 1_400 };
            candidate.estimated.privacy = "local".to_string();
        }
        RunnerType::Local => {
            candidate.estimated.cost = 0.0;
            candidate.estimated.currency = "none".to_string();
            candidate.estimated.queue_ms = u64::from(runner.queue_depth) * 25;
            candidate.estimated.first_token_ms = if warm { 175 } else { 700 };
            candidate.estimated.privacy = "local".to_string();
        }
        RunnerType::RemoteGpu => {
            candidate.estimated.cost = 0.01 + input_tokens as f64 * 0.000_001;
            candidate.estimated.currency = "xDAI".to_string();
            candidate.estimated.queue_ms = u64::from(runner.queue_depth) * 50;
            candidate.estimated.first_token_ms = if warm { 450 } else { 900 };
            candidate.estimated.privacy = "remote".to_string();
        }
        RunnerType::Marketplace => {
            candidate.estimated.cost = 0.02 + input_tokens as f64 * 0.000_002;
            candidate.estimated.currency = "xDAI".to_string();
            candidate.estimated.queue_ms = u64::from(runner.queue_depth) * 75;
            candidate.estimated.first_token_ms = if warm { 650 } else { 1_200 };
            candidate.estimated.privacy = "remote".to_string();
        }
    }
}

fn select_candidate<'a>(
    candidates: &'a [CandidateRoute],
    policy_mode: &PolicyMode,
) -> Option<&'a CandidateRoute> {
    let mut eligible: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.decision == RouteDecision::Eligible)
        .collect();
    eligible.sort_by(|left, right| {
        score_candidate(left, policy_mode)
            .partial_cmp(&score_candidate(right, policy_mode))
            .unwrap_or(std::cmp::Ordering::Equal)
            .reverse()
            .then(left.route_id.cmp(&right.route_id))
    });
    eligible.into_iter().next()
}

fn fallback_routes(
    candidates: &[CandidateRoute],
    selected_route_id: Option<&str>,
    policy_mode: &PolicyMode,
) -> Vec<String> {
    let mut eligible: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            candidate.decision == RouteDecision::Eligible
                && Some(candidate.route_id.as_str()) != selected_route_id
        })
        .collect();
    eligible.sort_by(|left, right| {
        score_candidate(left, policy_mode)
            .partial_cmp(&score_candidate(right, policy_mode))
            .unwrap_or(std::cmp::Ordering::Equal)
            .reverse()
            .then(left.route_id.cmp(&right.route_id))
    });
    eligible
        .into_iter()
        .map(|candidate| candidate.route_id.clone())
        .collect()
}

fn route_reason(
    candidates: &[CandidateRoute],
    selected_route_id: Option<&str>,
    policy_mode: &PolicyMode,
    access: &hivemind_core::AccessEvaluationV1,
) -> String {
    let Some(selected_route_id) = selected_route_id else {
        let reasons: Vec<_> = candidates
            .iter()
            .filter_map(|candidate| candidate.reason.clone())
            .collect();
        return if reasons.is_empty() {
            if access.decision != AccessDecision::Granted {
                access.reasons.join("; ")
            } else {
                "No eligible runner matched the request".to_string()
            }
        } else {
            reasons.join("; ")
        };
    };
    let Some(selected) = candidates
        .iter()
        .find(|candidate| candidate.route_id == selected_route_id)
    else {
        return "Selected route was not found in candidate set".to_string();
    };
    match policy_mode {
        PolicyMode::PrivacyFirst => format!(
            "Selected {} because privacy-first mode prefers {} execution.",
            selected.route_id, selected.estimated.privacy
        ),
        PolicyMode::SpeedFirst => format!(
            "Selected {} because it has the best estimated latency.",
            selected.route_id
        ),
        PolicyMode::CostFirst => format!(
            "Selected {} because it has the lowest eligible estimated cost.",
            selected.route_id
        ),
        PolicyMode::QualityFirst => format!(
            "Selected {} because quality-first mode prefers the highest quality eligible runner.",
            selected.route_id
        ),
        PolicyMode::Balanced => format!(
            "Selected {} using balanced cost, speed, privacy, and quality scoring.",
            selected.route_id
        ),
        PolicyMode::Developer => format!(
            "Selected {} while preserving all route diagnostics for developer mode.",
            selected.route_id
        ),
    }
}

fn score_candidate(candidate: &CandidateRoute, policy_mode: &PolicyMode) -> f64 {
    if candidate.decision != RouteDecision::Eligible {
        return f64::NEG_INFINITY;
    }
    let speed = 1.0
        / (1.0
            + (candidate.estimated.queue_ms + candidate.estimated.first_token_ms) as f64 / 1_000.0);
    let cost = 1.0 / (1.0 + candidate.estimated.cost * 100.0);
    let privacy = if candidate.estimated.privacy == "local" {
        1.0
    } else {
        0.35
    };
    let quality = candidate
        .quality_score
        .unwrap_or_else(|| quality_score(&candidate.runner_type));
    match policy_mode {
        PolicyMode::PrivacyFirst => privacy * 10.0 + speed + cost,
        PolicyMode::SpeedFirst => speed * 10.0 + quality + cost,
        PolicyMode::CostFirst => cost * 10.0 + privacy + speed,
        PolicyMode::QualityFirst => quality * 10.0 + speed + privacy,
        PolicyMode::Balanced => privacy * 2.0 + speed * 3.0 + cost * 2.0 + quality * 3.0,
        PolicyMode::Developer => privacy + speed + cost + quality,
    }
}

fn quality_score(runner_type: &RunnerType) -> f64 {
    match runner_type {
        RunnerType::RemoteGpu => 0.92,
        RunnerType::Marketplace => 0.85,
        RunnerType::Local => 0.76,
        RunnerType::Browser => 0.68,
    }
}

fn estimate_input_tokens(request: &ExecutionRequestV1) -> u64 {
    request
        .input
        .get("text")
        .and_then(|value| value.as_str())
        .map(|text| text.split_whitespace().count() as u64)
        .unwrap_or_else(|| request.input.to_string().split_whitespace().count() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ArtifactGroup, ArtifactMinimum, ExecutionOptions, ExecutionPrivacy, LicenseInfo,
        LicenseType, PackageKind, PackageManifestV1, PermissionRequest, Publisher,
        RunnerCacheClaimV1, RunnerLimits, license_policy_from_manifest,
    };
    use hivemind_marketplace::{
        HardwareResourceOfferV1, MarketplaceShortlistRequestV1, RunnerPricingV1,
        RunnerReputationV1, RunnerServiceLevelV1, default_hardware_resource_offer,
        offer_from_runner_descriptor, shortlist_runner_offers, sign_hardware_resource_offer,
    };

    #[test]
    fn route_trace_store_lists_and_gets_traces() {
        let dir = test_temp_dir("hivemind-route-trace-store");
        let mut trace = RouteExecutionTraceV1::new("request/trace store", None);
        trace.push_attempt(RouteAttemptV1 {
            route_id: "local-local-dev".to_string(),
            runner_id: Some("local-dev".to_string()),
            runner_type: RunnerType::Local,
            status: ExecutionStatus::Failed,
            error_code: Some(ErrorCode::ExecutionFailed),
            error_message: Some("local runner unavailable".to_string()),
        });
        trace.push_attempt(RouteAttemptV1 {
            route_id: "remote-remote-dev".to_string(),
            runner_id: Some("remote-dev".to_string()),
            runner_type: RunnerType::RemoteGpu,
            status: ExecutionStatus::Succeeded,
            error_code: None,
            error_message: None,
        });
        trace.selected_route_id = Some("remote-remote-dev".to_string());

        let path = write_route_execution_trace(&dir, &trace).unwrap();
        assert!(path.exists());

        let summary = list_route_execution_traces(&dir).unwrap();
        assert_eq!(summary.trace_count, 1);
        assert_eq!(summary.fallback_trace_count, 1);
        assert_eq!(summary.failed_trace_count, 0);
        assert_eq!(summary.traces[0].request_id, trace.request_id);
        assert_eq!(summary.traces[0].attempted_route_count, 2);
        assert_eq!(
            summary.traces[0].selected_route_id.as_deref(),
            Some("remote-remote-dev")
        );
        assert_eq!(
            summary.traces[0].trace_ref,
            "local://route-trace/request_trace_store"
        );

        let lookup = get_route_execution_trace(&dir, "request/trace store")
            .unwrap()
            .expect("stored trace should be found");
        assert_eq!(lookup.trace, trace);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn route_decision_store_lists_and_gets_reports() {
        let dir = test_temp_dir("hivemind-route-decision-store");
        let package = local_package();
        let request = request(&package);
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);
        let remote = runner(
            "remote-dev",
            RunnerType::RemoteGpu,
            "local-mock",
            "rust-mock",
            0,
        );
        let report = planner_report(
            &request,
            &package,
            &[remote, local],
            PolicyMode::PrivacyFirst,
        );

        let path = write_route_decision(&dir, &report).unwrap();
        assert!(path.exists());

        let summary = list_route_decisions(&dir).unwrap();
        assert_eq!(summary.decision_count, 1);
        assert_eq!(summary.with_selected_route_count, 1);
        assert_eq!(summary.rejected_only_count, 0);
        assert_eq!(summary.valid_proof_count, 1);
        assert_eq!(summary.invalid_proof_count, 0);
        assert_eq!(summary.with_planning_timing_count, 1);
        assert!(summary.average_planning_elapsed_ms.is_some());
        assert!(summary.max_planning_elapsed_ms.is_some());
        assert_eq!(summary.decisions[0].request_id, request.request_id);
        assert_eq!(summary.decisions[0].candidate_count, 2);
        assert_eq!(summary.decisions[0].eligible_candidate_count, 1);
        assert_eq!(summary.decisions[0].rejected_candidate_count, 1);
        assert!(summary.decisions[0].planning_elapsed_ms.is_some());
        assert!(summary.decisions[0].proof_valid);
        assert!(summary.decisions[0].proof_hash.is_some());
        assert_eq!(
            summary.decisions[0].decision_ref,
            "local://route-decision/request-1"
        );

        let lookup = get_route_decision(&dir, "request-1")
            .unwrap()
            .expect("stored route decision should be found");
        assert_eq!(lookup.report, report);
        assert!(lookup.report.planning_timing.is_some());
        assert!(lookup.verification.valid, "{:#?}", lookup.verification);
        assert_eq!(
            lookup.proof.report_hash,
            route_decision_report_hash(&report)
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn balanced_plan_prefers_local_for_small_package_with_remote_fallback() {
        let package = local_package();
        let request = request(&package);
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);
        let remote = runner(
            "remote-dev",
            RunnerType::RemoteGpu,
            "local-mock",
            "rust-mock",
            0,
        );

        let plan = plan_routes(&request, &package, &[remote, local], PolicyMode::Balanced);

        assert_eq!(plan.selected_route_id.as_deref(), Some("local-local-dev"));
        assert_eq!(
            plan.fallback_route_ids,
            vec!["remote-remote-dev".to_string()]
        );
    }

    #[test]
    fn plan_reports_the_execution_request_package_ref() {
        let package = local_package();
        let mut request = request(&package);
        request.package_ref = "bzz://published-router-ref".to_string();
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);

        let plan = plan_routes(&request, &package, &[local], PolicyMode::Balanced);

        assert_eq!(plan.package_ref, "bzz://published-router-ref");
        assert_eq!(
            plan.candidate_routes
                .first()
                .and_then(|candidate| candidate.policy_decision.as_ref())
                .map(|decision| decision.package_ref.as_str()),
            Some("bzz://published-router-ref")
        );
    }

    #[test]
    fn speed_first_prefers_remote_when_local_queue_is_deep() {
        let package = local_package();
        let request = request(&package);
        let local = runner(
            "local-dev",
            RunnerType::Local,
            "local-mock",
            "rust-mock",
            50,
        );
        let remote = runner(
            "remote-dev",
            RunnerType::RemoteGpu,
            "local-mock",
            "rust-mock",
            0,
        );

        let plan = plan_routes(&request, &package, &[local, remote], PolicyMode::SpeedFirst);

        assert_eq!(plan.selected_route_id.as_deref(), Some("remote-remote-dev"));
    }

    #[test]
    fn privacy_first_rejects_remote() {
        let package = local_package();
        let request = request(&package);
        let remote = runner(
            "remote-dev",
            RunnerType::RemoteGpu,
            "local-mock",
            "rust-mock",
            0,
        );

        let plan = plan_routes(&request, &package, &[remote], PolicyMode::PrivacyFirst);

        assert!(plan.selected_route_id.is_none());
        assert_eq!(plan.candidate_routes[0].decision, RouteDecision::Rejected);
    }

    #[test]
    fn privacy_first_rejects_marketplace_offer_routes() {
        let package = local_package();
        let request = request(&package);
        let offer = marketplace_offer("market-runner", 0.0, 300, 0.99, 1_000);
        let shortlist = shortlist_runner_offers(
            &MarketplaceShortlistRequestV1 {
                schema_version: "swarm-ai.marketplace.shortlist-request.v1".to_string(),
                package_ref: package.package_ref.clone(),
                task: request.task.clone(),
                api_surface: None,
                modality: None,
                estimated_input_tokens: 1,
                estimated_output_tokens: 1,
                required_privacy_tier: None,
                required_verification_tier: None,
                policy_mode: PolicyMode::PrivacyFirst,
                max_results: 3,
                include_rejected: true,
            },
            &[offer],
        );

        let plan = plan_routes_with_marketplace_shortlist_and_reputation(
            &request,
            &package,
            &[],
            Some(&shortlist),
            &[],
            PolicyMode::PrivacyFirst,
            &[],
            None,
        );

        assert!(plan.selected_route_id.is_none());
        let marketplace = plan
            .candidate_routes
            .iter()
            .find(|candidate| candidate.route_id.starts_with("marketplace-offer-"))
            .expect("marketplace candidate should be present");
        assert_eq!(marketplace.decision, RouteDecision::Rejected);
        assert!(
            marketplace
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("Privacy-first policy avoids marketplace")
        );
    }

    #[test]
    fn consent_required_policy_is_not_auto_selected_without_developer_mode() {
        let mut package = local_package();
        package.manifest.permissions.push(PermissionRequest {
            name: "network.http".to_string(),
            purpose: Some("call an external API".to_string()),
            required: false,
            limits: serde_json::json!({ "allowedHosts": ["api.example.com"] }),
        });
        let request = request(&package);
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);

        let plan = plan_routes(&request, &package, &[local], PolicyMode::Balanced);

        assert!(plan.selected_route_id.is_none());
        let candidate = &plan.candidate_routes[0];
        assert_eq!(candidate.decision, RouteDecision::Rejected);
        let policy = candidate
            .policy_decision
            .as_ref()
            .expect("candidate should expose policy decision");
        assert_eq!(policy.decision, hivemind_core::PolicyDecision::AskUser);
        assert!(
            candidate
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("explicit user approval")
        );
    }

    #[test]
    fn developer_mode_keeps_consent_required_policy_candidate_selectable() {
        let mut package = local_package();
        package.manifest.permissions.push(PermissionRequest {
            name: "network.http".to_string(),
            purpose: Some("call an external API".to_string()),
            required: false,
            limits: serde_json::json!({ "allowedHosts": ["api.example.com"] }),
        });
        let request = request(&package);
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);

        let plan = plan_routes(&request, &package, &[local], PolicyMode::Developer);

        assert_eq!(plan.selected_route_id.as_deref(), Some("local-local-dev"));
        let candidate = &plan.candidate_routes[0];
        assert_eq!(candidate.decision, RouteDecision::Eligible);
        let policy = candidate
            .policy_decision
            .as_ref()
            .expect("candidate should expose policy decision");
        assert_eq!(policy.decision, hivemind_core::PolicyDecision::AskUser);
    }

    #[test]
    fn runner_scoped_grant_only_authorizes_matching_route() {
        let mut package = local_package();
        package.manifest.license.license_type = LicenseType::Commercial;
        package.manifest.license.name = Some("Commercial".to_string());
        let policy = license_policy_from_manifest(&package.manifest, &package.package_ref);
        let mut request = request(&package);
        request.access_grant = Some(hivemind_access::dev_access_grant(
            &policy,
            "local-dev",
            "runner-service",
            Some("authorized-runner".to_string()),
            None,
        ));
        let unauthorized = runner(
            "unauthorized-runner",
            RunnerType::Local,
            "local-mock",
            "rust-mock",
            0,
        );
        let authorized = runner(
            "authorized-runner",
            RunnerType::Local,
            "local-mock",
            "rust-mock",
            0,
        );

        let plan = plan_routes(
            &request,
            &package,
            &[unauthorized, authorized],
            PolicyMode::Balanced,
        );

        assert_eq!(
            plan.selected_route_id.as_deref(),
            Some("local-authorized-runner")
        );
        let rejected = plan
            .candidate_routes
            .iter()
            .find(|candidate| candidate.runner_id.as_deref() == Some("unauthorized-runner"))
            .expect("unauthorized candidate should be present");
        assert_eq!(rejected.decision, RouteDecision::Rejected);
        assert!(
            rejected
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("runnerId")
        );
    }

    #[test]
    fn rejects_routes_for_unsupported_package_task() {
        let package = local_package();
        let mut request = request(&package);
        request.task = "chat".to_string();
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);
        let offer = marketplace_offer("market-runner", 0.0, 300, 0.99, 1_000);

        let plan = plan_routes_with_marketplace_offers(
            &request,
            &package,
            &[local],
            &[offer],
            PolicyMode::Balanced,
            3,
        );

        assert!(plan.selected_route_id.is_none());
        assert!(plan.fallback_route_ids.is_empty());
        assert!(plan.candidate_routes.iter().all(|candidate| {
            candidate
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("Package does not declare support for task chat")
        }));
    }

    #[test]
    fn report_includes_marketplace_shortlist_and_offer_route() {
        let package = local_package();
        let request = request(&package);
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);
        let offer = marketplace_offer("market-runner", 0.0, 300, 0.99, 1_000);

        let report = planner_report_with_marketplace_offers(
            &request,
            &package,
            &[local],
            &[offer],
            PolicyMode::QualityFirst,
            3,
        );

        let job_order = report
            .job_order
            .as_ref()
            .expect("planner report should include a job order");
        assert_eq!(job_order.request_id, request.request_id);
        assert_eq!(job_order.package_ref, package.package_ref);
        assert_eq!(job_order.task, "embedding");
        assert!(job_order.job_id.starts_with("job-"));
        assert!(report.marketplace_shortlist.is_some());
        assert!(
            report
                .plan
                .candidate_routes
                .iter()
                .any(|candidate| candidate.route_id.starts_with("marketplace-offer-"))
        );
        assert!(
            report
                .quotes
                .iter()
                .any(|quote| quote.route_id.starts_with("marketplace-offer-"))
        );
    }

    #[test]
    fn quality_policy_can_select_marketplace_offer() {
        let package = local_package();
        let request = request(&package);
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);
        let offer = marketplace_offer("market-runner", 0.0, 300, 0.99, 1_000);

        let plan = plan_routes_with_marketplace_offers(
            &request,
            &package,
            &[local],
            &[offer],
            PolicyMode::QualityFirst,
            3,
        );

        assert_eq!(
            plan.selected_route_id.as_deref(),
            plan.candidate_routes
                .iter()
                .find(|candidate| candidate.route_id.starts_with("marketplace-offer-"))
                .map(|candidate| candidate.route_id.as_str())
        );
    }

    #[test]
    fn ai_execution_plan_wraps_report_and_readiness_counts() {
        let package = local_package();
        let request = request(&package);
        let ai_request = AiRequestV1::text(
            request.request_id.clone(),
            "local-dev",
            ApiSurface::HivemindNative,
            hivemind_core::AiPackageSelectorV1 {
                package_id: Some(package.manifest.package_id.clone()),
                package_ref: Some(package.package_ref.clone()),
                ..Default::default()
            },
            "hello planning",
        );
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);
        let remote = runner(
            "remote-dev",
            RunnerType::RemoteGpu,
            "unsupported-target",
            "rust-mock",
            0,
        );

        let report = planner_report_with_reputation(
            &request,
            &package,
            &[local, remote],
            PolicyMode::Balanced,
            &[],
        );
        let plan = AiExecutionPlanV1::from_report(
            ai_request,
            request.clone(),
            package.package_ref.clone(),
            package.manifest.package_id.clone(),
            report,
        );

        assert_eq!(plan.schema_version, "hivemind.ai-execution-plan.v1");
        assert!(plan.ready_to_execute);
        assert_eq!(plan.selected_route_id.as_deref(), Some("local-local-dev"));
        assert_eq!(plan.eligible_route_count, 1);
        assert_eq!(plan.rejected_route_count, 1);
        assert!(plan.warnings.is_empty());
        assert_eq!(plan.execution_request.request_id, request.request_id);
        assert!(plan.universal_route_plan.is_some());
    }

    #[test]
    fn ai_execution_plan_includes_storage_aware_universal_route_plan() {
        let package = local_package();
        let request = request(&package);
        let mut ai_request = AiRequestV1::text(
            request.request_id.clone(),
            "local-dev",
            ApiSurface::HivemindNative,
            hivemind_core::AiPackageSelectorV1 {
                package_id: Some(package.manifest.package_id.clone()),
                package_ref: Some(package.package_ref.clone()),
                ..Default::default()
            },
            "classify this private document",
        );
        ai_request.inputs[0].content_ref = Some("bzz://encrypted-input".to_string());
        ai_request.inputs[0].hash = Some("sha256:input".to_string());
        ai_request.inputs[0].metadata = serde_json::json!({
            "assetId": "invoice_pdf",
            "byteSize": 800000,
            "sensitivityLabel": "private_enterprise"
        });
        ai_request.privacy.privacy_tier = PrivacyTier::TeeConfidential;
        ai_request.metadata = serde_json::json!({
            "browserStorageSessionRef": "local://browser-storage/session/session-1",
            "storagePlan": {
                "inputStrategy": "browser_upload_encrypted",
                "outputStrategy": "upload_output_to_swarm",
                "allowedProviders": ["weeb3_npm", "bee_http", "gateway"]
            }
        });
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);
        let remote = runner(
            "remote-dev",
            RunnerType::RemoteGpu,
            "local-mock",
            "rust-mock",
            0,
        );
        let report = planner_report_with_reputation(
            &request,
            &package,
            &[local, remote],
            PolicyMode::Balanced,
            &[],
        );
        let plan = AiExecutionPlanV1::from_report(
            ai_request,
            request,
            package.package_ref.clone(),
            package.manifest.package_id.clone(),
            report,
        );
        let universal = plan
            .universal_route_plan
            .as_ref()
            .expect("AI execution plans should carry the v0.3 universal route plan");

        assert_eq!(universal.schema_version, "hivemind.universal-route-plan.v1");
        assert_eq!(
            universal.storage_provider_plan.selected_provider.as_deref(),
            Some("weeb3_npm")
        );
        assert!(universal.storage_provider_plan.requires_browser_session);
        assert!(universal.storage_provider_plan.encrypt_inputs);
        assert!(
            universal
                .storage_provider_plan
                .fallback_providers
                .contains(&"bee_http".to_string())
        );
        assert_eq!(
            universal.input_asset_plan[0].movement,
            StorageMovementActionV1::EncryptAndUpload
        );
        assert!(universal.output_asset_plan.publish_to_swarm);
        assert!(
            universal
                .user_consent_requirements
                .iter()
                .any(|requirement| requirement.action == "upload_private_data")
        );
        assert_eq!(
            universal.fallback_chain,
            vec!["remote-remote-dev".to_string()]
        );
    }

    #[test]
    fn speed_policy_prefers_low_queue_miner_capacity() {
        let package = local_package();
        let request = request(&package);
        let slow = miner_capacity("slow-miner", hivemind_miner::MinerDaemonStatus::Busy, 18, 1);
        let fast = miner_capacity(
            "fast-miner",
            hivemind_miner::MinerDaemonStatus::Available,
            0,
            0,
        );
        let fast_route = format!("miner-offer-{}", fast.hardware_offer.offer_id);

        let plan = plan_routes_with_miner_capacity_and_reputation(
            &request,
            &package,
            &[],
            &[],
            &[slow, fast],
            PolicyMode::SpeedFirst,
            0,
            &[],
        );

        assert_eq!(plan.selected_route_id.as_deref(), Some(fast_route.as_str()));
        let fast_candidate = plan
            .candidate_routes
            .iter()
            .find(|candidate| candidate.route_id == fast_route)
            .expect("fast miner candidate should be present");
        assert_eq!(fast_candidate.decision, RouteDecision::Eligible);
        assert_eq!(fast_candidate.estimated.queue_ms, 0);
        assert!(
            plan.candidate_routes
                .iter()
                .any(|candidate| candidate.route_id.starts_with("miner-offer-")
                    && candidate.estimated.queue_ms > fast_candidate.estimated.queue_ms)
        );
    }

    #[test]
    fn miner_capacity_rejects_insufficient_vram_before_selection() {
        let package = local_package();
        let request = request(&package);
        let mut offer = hardware_offer("low-vram-miner");
        offer.hardware.vram_gb = Some(0.01);
        sign_hardware_resource_offer(&mut offer);
        let capacity = MinerCapacityInputV1 {
            schema_version: "swarm-ai.miner-capacity-input.v1".to_string(),
            hardware_offer: offer,
            heartbeat: None,
            benchmarks: Vec::new(),
        };

        let plan = plan_routes_with_miner_capacity_and_reputation(
            &request,
            &package,
            &[],
            &[],
            &[capacity],
            PolicyMode::Balanced,
            0,
            &[],
        );

        assert!(plan.selected_route_id.is_none());
        let candidate = plan
            .candidate_routes
            .iter()
            .find(|candidate| candidate.route_id.starts_with("miner-offer-"))
            .expect("miner candidate should be present");
        assert_eq!(candidate.decision, RouteDecision::Rejected);
        assert!(
            candidate
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("Insufficient GPU VRAM")
        );
    }

    #[test]
    fn trust_policy_keeps_local_only_routes_local() {
        let package = local_package();
        let request = request(&package);
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);
        let capacity = miner_capacity(
            "policy-miner",
            hivemind_miner::MinerDaemonStatus::Available,
            0,
            0,
        );
        let policy = TrustPolicyV1::local_only("enterprise-user");

        let report = planner_report_with_trust_policy(
            &request,
            &package,
            &[local],
            &[],
            &[capacity],
            PolicyMode::Balanced,
            0,
            &[],
            Some(&policy),
        );

        assert_eq!(
            report.plan.selected_route_id.as_deref(),
            Some("local-local-dev")
        );
        assert_eq!(
            report
                .trust_policy
                .as_ref()
                .map(|policy| policy.policy_id.as_str()),
            Some(policy.policy_id.as_str())
        );
        let miner = report
            .plan
            .candidate_routes
            .iter()
            .find(|candidate| candidate.route_id.starts_with("miner-offer-"))
            .expect("miner candidate should be present");
        assert_eq!(miner.decision, RouteDecision::Rejected);
        assert!(
            miner
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("Trust policy does not allow")
        );
    }

    #[test]
    fn trust_policy_blocks_open_miners_when_disallowed() {
        let package = local_package();
        let request = request(&package);
        let capacity = miner_capacity(
            "open-policy-miner",
            hivemind_miner::MinerDaemonStatus::Available,
            0,
            0,
        );
        let mut policy = TrustPolicyV1::open_marketplace("enterprise-user");
        policy.allow_open_miners = false;

        let plan = plan_routes_with_trust_policy(
            &request,
            &package,
            &[],
            &[],
            &[capacity],
            PolicyMode::Balanced,
            0,
            &[],
            Some(&policy),
        );

        assert!(plan.selected_route_id.is_none());
        let miner = plan
            .candidate_routes
            .iter()
            .find(|candidate| candidate.route_id.starts_with("miner-offer-"))
            .expect("miner candidate should be present");
        assert_eq!(miner.decision, RouteDecision::Rejected);
        assert!(
            miner
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("Trust policy does not allow open miners")
        );
    }

    #[test]
    fn quality_policy_uses_runner_reputation_summaries() {
        let package = local_package();
        let request = request(&package);
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);
        let remote = runner(
            "remote-dev",
            RunnerType::RemoteGpu,
            "local-mock",
            "rust-mock",
            0,
        );
        let reputation = vec![
            runner_reputation("local-dev", 0.99, 3),
            runner_reputation("remote-dev", 0.10, 2),
        ];

        let plan = plan_routes_with_reputation(
            &request,
            &package,
            &[remote, local],
            PolicyMode::QualityFirst,
            &reputation,
        );

        assert_eq!(plan.selected_route_id.as_deref(), Some("local-local-dev"));
        let local_candidate = plan
            .candidate_routes
            .iter()
            .find(|candidate| candidate.runner_id.as_deref() == Some("local-dev"))
            .expect("local candidate should be present");
        assert_eq!(local_candidate.quality_score, Some(0.99));
        assert!(
            local_candidate
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("Validation reputation score 0.99 from 3 reports")
        );
        let remote_candidate = plan
            .candidate_routes
            .iter()
            .find(|candidate| candidate.runner_id.as_deref() == Some("remote-dev"))
            .expect("remote candidate should be present");
        assert_eq!(remote_candidate.quality_score, Some(0.10));
    }

    #[test]
    fn report_includes_runner_reputation_evidence() {
        let package = local_package();
        let request = request(&package);
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);
        let reputation = vec![runner_reputation("local-dev", 0.93, 4)];

        let report = planner_report_with_reputation(
            &request,
            &package,
            &[local],
            PolicyMode::QualityFirst,
            &reputation,
        );

        assert_eq!(report.runner_reputation, reputation);
        let quote = report
            .quotes
            .iter()
            .find(|quote| quote.runner_id.as_deref() == Some("local-dev"))
            .expect("local quote should be present");
        assert_eq!(quote.quality_score, 0.93);
        assert!(
            quote
                .reasons
                .iter()
                .any(|reason| reason.contains("Validation reputation score 0.93 from 4 reports"))
        );
    }

    #[test]
    fn marketplace_offer_cannot_bypass_denied_package_policy() {
        let mut package = local_package();
        package.manifest.permissions.push(PermissionRequest {
            name: "local.shell".to_string(),
            purpose: Some("test blocked policy routing".to_string()),
            required: true,
            limits: serde_json::json!({}),
        });
        let request = request(&package);
        let local = runner("local-dev", RunnerType::Local, "local-mock", "rust-mock", 0);
        let offer = marketplace_offer("market-runner", 0.0, 300, 0.99, 1_000);

        let plan = plan_routes_with_marketplace_offers(
            &request,
            &package,
            &[local],
            &[offer],
            PolicyMode::Balanced,
            3,
        );

        assert!(plan.selected_route_id.is_none());
        let marketplace = plan
            .candidate_routes
            .iter()
            .find(|candidate| candidate.route_id.starts_with("marketplace-offer-"))
            .expect("marketplace candidate should be present");
        assert_eq!(marketplace.decision, RouteDecision::Rejected);
        assert!(
            marketplace
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("Permission local.shell is denied by default")
        );
    }

    fn local_package() -> LocalPackage {
        LocalPackage {
            root: std::path::PathBuf::new(),
            manifest: PackageManifestV1 {
                schema_version: "swarm-ai.package.v1".to_string(),
                package_id: "hivemind/router-test".to_string(),
                kind: PackageKind::Model,
                name: "Router Test".to_string(),
                version: "0.1.0".to_string(),
                publisher: Publisher {
                    address: "0x0".to_string(),
                    display_name: "Router".to_string(),
                    publisher_profile_ref: None,
                },
                capabilities: vec!["embedding".to_string()],
                artifact_groups: vec![ArtifactGroup {
                    id: "local-rust-mock".to_string(),
                    target: "local-mock".to_string(),
                    engine: "rust-mock".to_string(),
                    format: "json".to_string(),
                    paths: vec!["model/config.json".to_string()],
                    total_bytes: 512,
                    sha256: "0".repeat(64),
                    minimum: ArtifactMinimum {
                        memory_mb: Some(128),
                        webgpu: Some(false),
                        disk_mb: None,
                    },
                }],
                input_schema: serde_json::json!({ "type": "object" }),
                output_schema: serde_json::json!({ "type": "object" }),
                permissions: Vec::new(),
                license: LicenseInfo {
                    license_type: LicenseType::Open,
                    name: Some("Apache-2.0".to_string()),
                    url: None,
                },
            },
            manifest_hash: "hash".to_string(),
            package_ref: "bzz://pkg".to_string(),
        }
    }

    fn request(package: &LocalPackage) -> ExecutionRequestV1 {
        ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: package.package_ref.clone(),
            package_id: package.manifest.package_id.clone(),
            package_version: package.manifest.version.clone(),
            preferred_artifact_group: None,
            task: "embedding".to_string(),
            input: serde_json::json!({ "text": "hello" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        }
    }

    fn runner(
        id: &str,
        runner_type: RunnerType,
        target: &str,
        engine: &str,
        queue_depth: u32,
    ) -> RunnerDescriptorV1 {
        RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: id.to_string(),
            runner_type,
            targets: vec![target.to_string()],
            engines: vec![engine.to_string()],
            capabilities: vec!["embedding".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 4096,
                max_input_bytes: 128 * 1024,
                max_concurrent_jobs: 4,
            },
            queue_depth,
            warm_package_refs: Vec::new(),
        }
    }

    fn marketplace_offer(
        id: &str,
        token_price: f64,
        p95_first_token_ms: u64,
        validator_score: f64,
        completed_jobs: u64,
    ) -> RunnerOfferV1 {
        let descriptor = runner(
            id,
            RunnerType::Marketplace,
            "marketplace",
            "offer-router",
            0,
        );
        offer_from_runner_descriptor(
            &descriptor,
            format!("bzz://marketplace-descriptor/{id}"),
            vec!["bzz://pkg".to_string()],
            RunnerPricingV1 {
                input_token_price: token_price,
                output_token_price: token_price,
                currency: "xDAI".to_string(),
            },
            RunnerServiceLevelV1 {
                p95_first_token_ms,
                availability_target: 0.995,
            },
            RunnerReputationV1 {
                validator_score,
                completed_jobs,
            },
        )
    }

    fn hardware_offer(id: &str) -> HardwareResourceOfferV1 {
        let mut descriptor = runner(id, RunnerType::Marketplace, "local-mock", "rust-mock", 0);
        descriptor.warm_package_refs = vec!["bzz://pkg".to_string()];
        let mut offer = default_hardware_resource_offer(&descriptor, format!("operator-{id}"));
        offer.cache_claims = vec![RunnerCacheClaimV1 {
            package_ref: "bzz://pkg".to_string(),
            warmed: true,
        }];
        sign_hardware_resource_offer(&mut offer);
        offer
    }

    fn miner_capacity(
        id: &str,
        status: hivemind_miner::MinerDaemonStatus,
        queue_depth: u32,
        active_jobs: u32,
    ) -> MinerCapacityInputV1 {
        let offer = hardware_offer(id);
        let profile = hivemind_miner::miner_profile_from_hardware_offer(&offer, "0.1.0-test");
        let heartbeat = hivemind_miner::miner_heartbeat_from_profile(
            &profile,
            status,
            queue_depth,
            active_jobs,
            Vec::new(),
            if active_jobs > 0 { 0.5 } else { 0.0 },
        );
        MinerCapacityInputV1 {
            schema_version: "swarm-ai.miner-capacity-input.v1".to_string(),
            hardware_offer: offer,
            heartbeat: Some(heartbeat),
            benchmarks: Vec::new(),
        }
    }

    fn runner_reputation(
        id: &str,
        overall_score: f64,
        report_count: usize,
    ) -> RunnerReputationSummaryV1 {
        RunnerReputationSummaryV1 {
            schema_version: "swarm-ai.runner-reputation-summary.v1".to_string(),
            runner_id: id.to_string(),
            quality_score: overall_score,
            latency_score: 0.8,
            overall_score,
            report_count,
            evidence_refs: vec![format!("validation-{id}")],
        }
    }

    fn test_temp_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
