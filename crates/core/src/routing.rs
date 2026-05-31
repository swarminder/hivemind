use crate::artifact::select_artifact_group;
use crate::execution::ExecutionRequestV1;
use crate::manifest::{PackageManifestV1, manifest_supports_capability};
use crate::policy::{PolicyDecision, evaluate_package_policy};
use crate::runner::{RunnerDescriptorV1, RunnerType, runner_supports_capability};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyMode {
    PrivacyFirst,
    SpeedFirst,
    CostFirst,
    QualityFirst,
    Balanced,
    Developer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RouteDecision {
    Eligible,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RouteEstimate {
    pub cost: f64,
    pub currency: String,
    #[serde(rename = "queueMs")]
    pub queue_ms: u64,
    #[serde(rename = "firstTokenMs")]
    pub first_token_ms: u64,
    pub privacy: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CandidateRoute {
    #[serde(rename = "routeId")]
    pub route_id: String,
    #[serde(rename = "runnerType")]
    pub runner_type: RunnerType,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    #[serde(rename = "artifactGroup", default)]
    pub artifact_group: Option<String>,
    pub estimated: RouteEstimate,
    #[serde(
        rename = "qualityScore",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub quality_score: Option<f64>,
    pub decision: RouteDecision,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RoutePlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub task: String,
    #[serde(rename = "candidateRoutes")]
    pub candidate_routes: Vec<CandidateRoute>,
    #[serde(rename = "selectedRouteId", default)]
    pub selected_route_id: Option<String>,
    #[serde(rename = "fallbackRouteIds", default)]
    pub fallback_route_ids: Vec<String>,
    pub reason: String,
}

pub fn plan_route_for_runner(
    request: &ExecutionRequestV1,
    manifest: &PackageManifestV1,
    package_ref: &str,
    runner: &RunnerDescriptorV1,
    policy_mode: PolicyMode,
) -> RoutePlanV1 {
    let artifact = select_artifact_group(
        manifest,
        request.preferred_artifact_group.as_deref(),
        &runner.targets,
        &runner.engines,
    );
    let policy = evaluate_package_policy(manifest, package_ref, Some(runner.runner_id.clone()));
    let mut decision = RouteDecision::Eligible;
    let mut reason = "Runner can execute the selected artifact group".to_string();

    if artifact.is_none() {
        decision = RouteDecision::Rejected;
        reason = "Runner does not support any matching artifact group".to_string();
    }

    if policy.decision == PolicyDecision::Deny {
        decision = RouteDecision::Rejected;
        reason = policy.reasons.join("; ");
    }

    if !manifest_supports_capability(manifest, &request.task) {
        decision = RouteDecision::Rejected;
        reason = format!("Package does not declare support for task {}", request.task);
    }

    if !runner_supports_capability(runner, &request.task) {
        decision = RouteDecision::Rejected;
        let runner_reason = format!(
            "Runner {} does not declare support for task {}",
            runner.runner_id, request.task
        );
        reason = if decision == RouteDecision::Rejected
            && reason != "Runner can execute the selected artifact group"
        {
            format!("{reason}; {runner_reason}")
        } else {
            runner_reason
        };
    }

    if policy_mode == PolicyMode::PrivacyFirst && runner.runner_type == RunnerType::RemoteGpu {
        decision = RouteDecision::Rejected;
        reason = "Privacy-first policy avoids remote GPU execution".to_string();
    }

    let privacy = match runner.runner_type {
        RunnerType::Browser | RunnerType::Local => "local",
        RunnerType::RemoteGpu | RunnerType::Marketplace => "remote",
    };

    let route_id = format!("{}-{}", privacy, runner.runner_id);
    let candidate = CandidateRoute {
        route_id: route_id.clone(),
        runner_type: runner.runner_type.clone(),
        runner_id: Some(runner.runner_id.clone()),
        artifact_group: artifact.map(|group| group.id.clone()),
        estimated: RouteEstimate {
            cost: 0.0,
            currency: "none".to_string(),
            queue_ms: u64::from(runner.queue_depth) * 25,
            first_token_ms: if runner
                .warm_package_refs
                .iter()
                .any(|value| value == package_ref)
            {
                250
            } else {
                900
            },
            privacy: privacy.to_string(),
        },
        quality_score: None,
        decision,
        reason: Some(reason.clone()),
    };

    let selected_route_id = if candidate.decision == RouteDecision::Eligible {
        Some(route_id)
    } else {
        None
    };

    RoutePlanV1 {
        schema_version: "swarm-ai.route-plan.v1".to_string(),
        request_id: request.request_id.clone(),
        package_ref: package_ref.to_string(),
        task: request.task.clone(),
        candidate_routes: vec![candidate],
        selected_route_id,
        fallback_route_ids: Vec::new(),
        reason,
    }
}
