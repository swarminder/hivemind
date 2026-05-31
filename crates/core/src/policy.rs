use crate::manifest::{PackageManifestV1, PermissionRequest};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyDecision {
    Allow,
    Deny,
    AskUser,
    AllowWithRestrictions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyDecisionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    pub decision: PolicyDecision,
    pub reasons: Vec<String>,
    #[serde(default)]
    pub restrictions: Value,
    #[serde(rename = "riskLevel")]
    pub risk_level: RiskLevel,
}

pub fn evaluate_package_policy(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
    runner_id: Option<String>,
) -> PolicyDecisionV1 {
    let mut decision = PolicyDecision::Allow;
    let mut risk_level = RiskLevel::Low;
    let mut reasons = Vec::new();
    let mut restrictions = json!({});

    for permission in &manifest.permissions {
        match permission.name.as_str() {
            "local.shell" | "local.docker" | "wallet.sign" => {
                decision = PolicyDecision::Deny;
                risk_level = RiskLevel::Blocked;
                reasons.push(format!(
                    "Permission {} is denied by default",
                    permission.name
                ));
            }
            "network.http" | "network.websocket" | "user.files.read" | "user.files.write"
            | "microphone.read" | "camera.read" | "wallet.connect" | "clipboard.read"
            | "clipboard.write" => {
                if decision != PolicyDecision::Deny {
                    decision = PolicyDecision::AskUser;
                    risk_level = RiskLevel::Medium;
                }
                reasons.push(format!(
                    "Permission {} requires explicit approval",
                    permission.name
                ));
            }
            _ if permission.required => {
                if decision != PolicyDecision::Deny {
                    decision = PolicyDecision::AllowWithRestrictions;
                    risk_level = RiskLevel::Medium;
                    restrictions = json!({"unknownRequiredPermissions": "blocked-until-reviewed"});
                }
                reasons.push(format!(
                    "Required permission {} is not recognized yet",
                    permission.name
                ));
            }
            _ => {}
        }
    }

    if reasons.is_empty() {
        reasons.push("Package requests no elevated permissions".to_string());
    }

    PolicyDecisionV1 {
        schema_version: "swarm-ai.policy-decision.v1".to_string(),
        package_id: manifest.package_id.clone(),
        package_ref: package_ref.into(),
        runner_id,
        decision,
        reasons,
        restrictions,
        risk_level,
    }
}

pub fn permission_names(permissions: &[PermissionRequest]) -> Vec<String> {
    permissions
        .iter()
        .map(|permission| permission.name.clone())
        .collect()
}
