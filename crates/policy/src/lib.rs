pub use hivemind_core::{PolicyDecision, PolicyDecisionV1, evaluate_package_policy};

use hivemind_core::{PackageManifestV1, PermissionRequest, policy::RiskLevel};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CodeExecutionMode {
    None,
    Sandboxed,
    UnsandboxedRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionCategory {
    Network,
    Storage,
    UserDevice,
    Wallet,
    LocalRuntime,
    Runner,
    Evidence,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionSeverity {
    Low,
    Medium,
    High,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PermissionDefinitionV1 {
    pub name: String,
    pub category: PermissionCategory,
    pub severity: PermissionSeverity,
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PermissionManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub permissions: Vec<PermissionRequest>,
    #[serde(rename = "riskLevel")]
    pub risk_level: RiskLevel,
    #[serde(rename = "codeExecution")]
    pub code_execution: CodeExecutionMode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SandboxRequirementV1 {
    pub environment: String,
    pub requirement: String,
    pub enforced: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyInspectionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "permissionManifest")]
    pub permission_manifest: PermissionManifestV1,
    #[serde(rename = "policyDecision")]
    pub policy_decision: PolicyDecisionV1,
    #[serde(rename = "permissionCatalog")]
    pub permission_catalog: Vec<PermissionDefinitionV1>,
    #[serde(rename = "sandboxRequirements")]
    pub sandbox_requirements: Vec<SandboxRequirementV1>,
    pub warnings: Vec<String>,
}

pub fn permission_manifest_from_package(manifest: &PackageManifestV1) -> PermissionManifestV1 {
    let code_execution = code_execution_mode(manifest);
    let risk_level = risk_level_for_permissions(&manifest.permissions, &code_execution);
    PermissionManifestV1 {
        schema_version: "swarm-ai.permissions.v1".to_string(),
        package_id: manifest.package_id.clone(),
        permissions: manifest.permissions.clone(),
        risk_level,
        code_execution,
    }
}

pub fn inspect_package_policy(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
    runner_id: Option<String>,
) -> PolicyInspectionV1 {
    let permission_manifest = permission_manifest_from_package(manifest);
    let policy_decision = evaluate_package_policy(manifest, package_ref, runner_id);
    let permission_catalog = permission_manifest
        .permissions
        .iter()
        .map(|permission| permission_definition(&permission.name))
        .collect::<Vec<_>>();
    let sandbox_requirements =
        sandbox_requirements(&permission_manifest, &policy_decision.restrictions);
    let warnings = inspection_warnings(&permission_manifest, &policy_decision);

    PolicyInspectionV1 {
        schema_version: "swarm-ai.policy-inspection.v1".to_string(),
        permission_manifest,
        policy_decision,
        permission_catalog,
        sandbox_requirements,
        warnings,
    }
}

pub fn permission_catalog() -> Vec<PermissionDefinitionV1> {
    [
        "network.http",
        "network.websocket",
        "swarm.read",
        "swarm.write",
        "user.files.read",
        "user.files.write",
        "microphone.read",
        "camera.read",
        "clipboard.read",
        "clipboard.write",
        "wallet.connect",
        "wallet.sign",
        "local.shell",
        "local.docker",
        "runner.gpu",
        "receipt.public-evidence",
        "private-cache.write",
    ]
    .into_iter()
    .map(permission_definition)
    .collect()
}

pub fn permission_definition(name: &str) -> PermissionDefinitionV1 {
    let (category, severity, default_action, description) = match name {
        "network.http" => (
            PermissionCategory::Network,
            PermissionSeverity::Medium,
            "ask-user-or-allowlist",
            "HTTP calls to declared hosts.",
        ),
        "network.websocket" => (
            PermissionCategory::Network,
            PermissionSeverity::Medium,
            "ask-user-or-allowlist",
            "WebSocket connections to declared hosts.",
        ),
        "swarm.read" => (
            PermissionCategory::Storage,
            PermissionSeverity::Low,
            "allow",
            "Read public Swarm data.",
        ),
        "swarm.write" => (
            PermissionCategory::Storage,
            PermissionSeverity::Medium,
            "ask-user",
            "Write data to Swarm.",
        ),
        "user.files.read" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Read user-selected local files.",
        ),
        "user.files.write" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Write user-approved local files.",
        ),
        "microphone.read" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Read microphone input.",
        ),
        "camera.read" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Read camera input.",
        ),
        "clipboard.read" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Read clipboard contents.",
        ),
        "clipboard.write" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Write clipboard contents.",
        ),
        "wallet.connect" => (
            PermissionCategory::Wallet,
            PermissionSeverity::Medium,
            "ask-user",
            "Connect to a wallet account.",
        ),
        "wallet.sign" => (
            PermissionCategory::Wallet,
            PermissionSeverity::Blocked,
            "deny-by-default",
            "Request wallet signatures.",
        ),
        "local.shell" => (
            PermissionCategory::LocalRuntime,
            PermissionSeverity::Blocked,
            "deny-by-default",
            "Run local shell commands.",
        ),
        "local.docker" => (
            PermissionCategory::LocalRuntime,
            PermissionSeverity::Blocked,
            "deny-by-default",
            "Run local containers.",
        ),
        "runner.gpu" => (
            PermissionCategory::Runner,
            PermissionSeverity::Low,
            "allow-if-runner-supports",
            "Use runner GPU resources.",
        ),
        "receipt.public-evidence" => (
            PermissionCategory::Evidence,
            PermissionSeverity::Medium,
            "ask-user",
            "Publish public execution evidence.",
        ),
        "private-cache.write" => (
            PermissionCategory::Storage,
            PermissionSeverity::Low,
            "allow-with-quota",
            "Write private package cache data.",
        ),
        _ => (
            PermissionCategory::Unknown,
            PermissionSeverity::Medium,
            "review-required",
            "Unknown permission name.",
        ),
    };

    PermissionDefinitionV1 {
        name: name.to_string(),
        category,
        severity,
        default_action: default_action.to_string(),
        description: description.to_string(),
    }
}

fn code_execution_mode(manifest: &PackageManifestV1) -> CodeExecutionMode {
    if manifest
        .permissions
        .iter()
        .any(|permission| matches!(permission.name.as_str(), "local.shell" | "local.docker"))
    {
        return CodeExecutionMode::UnsandboxedRequired;
    }

    if manifest.artifact_groups.iter().any(|group| {
        matches!(
            group.engine.as_str(),
            "python" | "node" | "wasmtime" | "llama.cpp" | "onnxruntime"
        ) || matches!(
            group.format.as_str(),
            "python" | "wasm" | "container" | "binary"
        )
    }) {
        CodeExecutionMode::Sandboxed
    } else {
        CodeExecutionMode::None
    }
}

fn risk_level_for_permissions(
    permissions: &[PermissionRequest],
    code_execution: &CodeExecutionMode,
) -> RiskLevel {
    if *code_execution == CodeExecutionMode::UnsandboxedRequired
        || permissions.iter().any(|permission| {
            matches!(
                permission.name.as_str(),
                "local.shell" | "local.docker" | "wallet.sign"
            )
        })
    {
        return RiskLevel::Blocked;
    }

    if permissions.iter().any(|permission| {
        matches!(
            permission.name.as_str(),
            "network.http"
                | "network.websocket"
                | "user.files.read"
                | "user.files.write"
                | "microphone.read"
                | "camera.read"
                | "wallet.connect"
                | "clipboard.read"
                | "clipboard.write"
                | "receipt.public-evidence"
                | "swarm.write"
        )
    }) {
        return RiskLevel::Medium;
    }

    match code_execution {
        CodeExecutionMode::Sandboxed => RiskLevel::Medium,
        CodeExecutionMode::None => RiskLevel::Low,
        CodeExecutionMode::UnsandboxedRequired => RiskLevel::Blocked,
    }
}

fn sandbox_requirements(
    manifest: &PermissionManifestV1,
    restrictions: &Value,
) -> Vec<SandboxRequirementV1> {
    let mut requirements = vec![
        requirement("browser", "run package code in worker/wasm sandbox", true),
        requirement(
            "local",
            "deny undeclared filesystem and process access",
            true,
        ),
        requirement(
            "remote",
            "isolate each job from runner host credentials",
            true,
        ),
    ];

    for permission in &manifest.permissions {
        match permission.name.as_str() {
            "network.http" | "network.websocket" => requirements.push(requirement(
                "all",
                "enforce declared network host allowlist",
                has_allowed_hosts(&permission.limits),
            )),
            "user.files.read" | "user.files.write" => requirements.push(requirement(
                "browser-local",
                "restrict file access to explicit user-selected files",
                permission
                    .limits
                    .get("userSelectedOnly")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            )),
            "wallet.connect" | "wallet.sign" => requirements.push(requirement(
                "browser",
                "require per-call wallet consent",
                true,
            )),
            "local.shell" | "local.docker" => requirements.push(requirement(
                "local",
                "block unsandboxed process execution outside developer mode",
                false,
            )),
            _ => {}
        }
    }

    if restrictions
        .get("unknownRequiredPermissions")
        .and_then(Value::as_str)
        .is_some()
    {
        requirements.push(requirement(
            "all",
            "block unknown required permissions until reviewed",
            true,
        ));
    }

    requirements
}

fn inspection_warnings(
    permission_manifest: &PermissionManifestV1,
    policy_decision: &PolicyDecisionV1,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if permission_manifest.permissions.is_empty() {
        warnings.push("Package declares no elevated permissions".to_string());
    }
    if permission_manifest.code_execution == CodeExecutionMode::Sandboxed {
        warnings.push("Package includes executable artifacts and requires sandboxing".to_string());
    }
    if policy_decision.decision == PolicyDecision::Deny {
        warnings.push("Default policy denies this package until reviewed".to_string());
    }
    warnings
}

fn has_allowed_hosts(limits: &Value) -> bool {
    limits
        .get("allowedHosts")
        .and_then(Value::as_array)
        .is_some_and(|hosts| !hosts.is_empty())
}

fn requirement(
    environment: impl Into<String>,
    requirement: impl Into<String>,
    enforced: bool,
) -> SandboxRequirementV1 {
    SandboxRequirementV1 {
        environment: environment.into(),
        requirement: requirement.into(),
        enforced,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ArtifactGroup, ArtifactMinimum, LicenseInfo, LicenseType, PackageKind, Publisher,
    };
    use serde_json::json;

    #[test]
    fn no_permissions_are_low_risk() {
        let manifest = package(Vec::new());

        let inspection = inspect_package_policy(&manifest, "bzz://pkg", Some("runner".to_string()));

        assert_eq!(inspection.permission_manifest.risk_level, RiskLevel::Low);
        assert_eq!(inspection.policy_decision.decision, PolicyDecision::Allow);
    }

    #[test]
    fn shell_permission_is_blocked() {
        let manifest = package(vec![PermissionRequest {
            name: "local.shell".to_string(),
            purpose: Some("run scripts".to_string()),
            required: true,
            limits: json!({}),
        }]);

        let inspection = inspect_package_policy(&manifest, "bzz://pkg", Some("runner".to_string()));

        assert_eq!(
            inspection.permission_manifest.risk_level,
            RiskLevel::Blocked
        );
        assert_eq!(inspection.policy_decision.decision, PolicyDecision::Deny);
    }

    fn package(permissions: Vec<PermissionRequest>) -> PackageManifestV1 {
        PackageManifestV1 {
            schema_version: "swarm-ai.package.v1".to_string(),
            package_id: "hivemind/policy-test".to_string(),
            kind: PackageKind::Model,
            name: "Policy Test".to_string(),
            version: "0.1.0".to_string(),
            publisher: Publisher {
                address: "0x0".to_string(),
                display_name: "Policy".to_string(),
                publisher_profile_ref: None,
            },
            capabilities: vec!["embedding".to_string()],
            artifact_groups: vec![ArtifactGroup {
                id: "local".to_string(),
                target: "local-mock".to_string(),
                engine: "rust-mock".to_string(),
                format: "json".to_string(),
                paths: vec!["model/config.json".to_string()],
                total_bytes: 1,
                sha256: "0".repeat(64),
                minimum: ArtifactMinimum {
                    memory_mb: Some(1),
                    webgpu: Some(false),
                    disk_mb: None,
                },
            }],
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            permissions,
            license: LicenseInfo {
                license_type: LicenseType::Open,
                name: Some("Apache-2.0".to_string()),
                url: None,
            },
        }
    }
}
