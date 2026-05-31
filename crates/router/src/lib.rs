use hivemind_access::evaluate_execution_access_with_revocations;
use hivemind_core::{
    AccessDecision, AccessEvaluationV1, CandidateRoute, ErrorCode, ExecutionRequestV1,
    ExecutionStatus, PolicyDecision, PolicyMode, RouteDecision, RouteEstimate, RoutePlanV1,
    RunnerDescriptorV1, RunnerType, evaluate_package_policy, manifest_supports_capability,
};
use hivemind_marketplace::{
    MarketplaceShortlistV1, RunnerOfferScoreV1, RunnerOfferV1, shortlist_request_from_execution,
    shortlist_runner_offers,
};
use hivemind_package::LocalPackage;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
pub struct RoutePlannerReportV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub plan: RoutePlanV1,
    pub quotes: Vec<CostQuoteV1>,
    #[serde(rename = "marketplaceShortlist", default)]
    pub marketplace_shortlist: Option<MarketplaceShortlistV1>,
    #[serde(rename = "policyMode")]
    pub policy_mode: PolicyMode,
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

pub fn plan_route(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runner: &RunnerDescriptorV1,
    policy_mode: PolicyMode,
) -> RoutePlanV1 {
    plan_routes(request, package, &[runner.clone()], policy_mode)
}

pub fn plan_routes(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    policy_mode: PolicyMode,
) -> RoutePlanV1 {
    plan_routes_with_marketplace_offers(request, package, runners, &[], policy_mode, 0)
}

pub fn plan_routes_with_marketplace_offers(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    offers: &[RunnerOfferV1],
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
) -> RoutePlanV1 {
    plan_routes_with_marketplace_shortlist(
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
        policy_mode,
    )
}

pub fn plan_routes_with_marketplace_shortlist(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    marketplace_shortlist: Option<&MarketplaceShortlistV1>,
    policy_mode: PolicyMode,
) -> RoutePlanV1 {
    let request_access = access_for_runner(request, package, None);
    let mut candidates = runner_candidates(request, package, runners, &policy_mode);
    if let Some(shortlist) = marketplace_shortlist {
        candidates.extend(
            shortlist
                .rankings
                .iter()
                .map(|ranking| marketplace_candidate(request, ranking, package)),
        );
    }

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
    let plan = plan_routes(request, package, runners, policy_mode.clone());
    let quotes = cost_quotes(&plan, runners);
    RoutePlannerReportV1 {
        schema_version: "swarm-ai.route-planner-report.v1".to_string(),
        plan,
        quotes,
        marketplace_shortlist: None,
        policy_mode,
    }
}

pub fn planner_report_with_marketplace_offers(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    runners: &[RunnerDescriptorV1],
    offers: &[RunnerOfferV1],
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
) -> RoutePlannerReportV1 {
    let shortlist = marketplace_shortlist(
        request,
        offers,
        policy_mode.clone(),
        max_marketplace_results,
    );
    let plan = plan_routes_with_marketplace_shortlist(
        request,
        package,
        runners,
        shortlist.as_ref(),
        policy_mode.clone(),
    );
    let quotes = cost_quotes(&plan, runners);
    RoutePlannerReportV1 {
        schema_version: "swarm-ai.route-planner-report.v1".to_string(),
        plan,
        quotes,
        marketplace_shortlist: shortlist,
        policy_mode,
    }
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
) -> Vec<CandidateRoute> {
    let mut candidates = Vec::new();
    for runner in runners {
        let access = access_for_runner(request, package, Some(&runner.runner_id));
        let mut single = hivemind_core::plan_route_for_runner(
            request,
            &package.manifest,
            &package.package_ref,
            runner,
            policy_mode.clone(),
        );
        let Some(mut candidate) = single.candidate_routes.pop() else {
            continue;
        };
        apply_estimates(&mut candidate, runner, request, package);
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
        &package.package_ref,
        Some(ranking.runner_id.clone()),
    );
    if policy.decision == PolicyDecision::Deny {
        decision = RouteDecision::Rejected;
        reasons.push(policy.reasons.join("; "));
    }
    if !manifest_supports_capability(&package.manifest, &request.task) {
        decision = RouteDecision::Rejected;
        reasons.push(format!(
            "Package does not declare support for task {}",
            request.task
        ));
    }
    if access.decision != AccessDecision::Granted {
        decision = RouteDecision::Rejected;
        reasons.push(access.reasons.join("; "));
    }
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
            privacy: match ranking.runner_type {
                RunnerType::Browser | RunnerType::Local => "local",
                RunnerType::RemoteGpu | RunnerType::Marketplace => "remote",
            }
            .to_string(),
        },
        quality_score: Some(ranking.validator_score.clamp(0.0, 1.0)),
        decision,
        reason: Some(reasons.join("; ")),
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
    package: &LocalPackage,
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
        package_ref: package.package_ref.clone(),
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
        LicenseType, PackageKind, PackageManifestV1, PermissionRequest, Publisher, RunnerLimits,
        license_policy_from_manifest,
    };
    use hivemind_marketplace::{
        RunnerPricingV1, RunnerReputationV1, RunnerServiceLevelV1, offer_from_runner_descriptor,
    };

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
}
