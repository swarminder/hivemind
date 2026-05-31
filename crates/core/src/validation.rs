use crate::manifest::{PackageManifestV1, PermissionRequest};
use schemars::JsonSchema;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationIssue {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(default)]
    pub manifest: Option<PackageManifestV1>,
}

pub fn validate_package_manifest_value(value: &Value) -> ValidationReport {
    match serde_json::from_value::<PackageManifestV1>(value.clone()) {
        Ok(manifest) => validate_package_manifest(manifest),
        Err(error) => ValidationReport {
            schema_version: "swarm-ai.validation-report.v1".to_string(),
            valid: false,
            issues: vec![ValidationIssue {
                path: "$".to_string(),
                message: format!("Manifest does not match PackageManifestV1: {error}"),
            }],
            warnings: Vec::new(),
            manifest: None,
        },
    }
}

pub fn validate_package_manifest(manifest: PackageManifestV1) -> ValidationReport {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if manifest.schema_version != "swarm-ai.package.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.package.v1",
        ));
    }

    if manifest.package_id.trim().is_empty() || !manifest.package_id.contains('/') {
        issues.push(issue(
            "$.packageId",
            "Package id must use publisher/name form",
        ));
    }

    if Version::parse(&manifest.version).is_err() {
        issues.push(issue(
            "$.version",
            "Package version must be semantic versioning",
        ));
    }

    if manifest.name.trim().is_empty() {
        issues.push(issue("$.name", "Package name is required"));
    }

    if manifest.publisher.address.trim().is_empty() {
        issues.push(issue(
            "$.publisher.address",
            "Publisher address is required",
        ));
    }

    if manifest.artifact_groups.is_empty() {
        issues.push(issue(
            "$.artifactGroups",
            "At least one artifact group is required",
        ));
    }

    let mut artifact_ids = HashSet::new();
    for (index, group) in manifest.artifact_groups.iter().enumerate() {
        let base = format!("$.artifactGroups[{index}]");
        if !artifact_ids.insert(group.id.clone()) {
            issues.push(issue(
                format!("{base}.id"),
                "Artifact group id must be unique inside the package",
            ));
        }

        if group.target.trim().is_empty() {
            issues.push(issue(
                format!("{base}.target"),
                "Artifact target is required",
            ));
        }

        if group.engine.trim().is_empty() {
            issues.push(issue(
                format!("{base}.engine"),
                "Artifact engine is required",
            ));
        }

        if group.format.trim().is_empty() {
            issues.push(issue(
                format!("{base}.format"),
                "Artifact format is required",
            ));
        }

        if group.total_bytes == 0 {
            warnings.push(issue(
                format!("{base}.totalBytes"),
                "Artifact size is zero; runners cannot warn users before download",
            ));
        }

        if !is_sha256_hex(&group.sha256) {
            issues.push(issue(
                format!("{base}.sha256"),
                "Artifact group sha256 must be a 64-character hex digest",
            ));
        }

        if group.paths.is_empty() {
            issues.push(issue(
                format!("{base}.paths"),
                "Artifact group must list at least one file path",
            ));
        }

        for (path_index, path) in group.paths.iter().enumerate() {
            if !is_relative_package_path(path) {
                issues.push(issue(
                    format!("{base}.paths[{path_index}]"),
                    "Path must be a relative package path without traversal",
                ));
            }
        }
    }

    if !manifest.input_schema.is_object() {
        warnings.push(issue(
            "$.inputSchema",
            "Input schema should be a JSON Schema object",
        ));
    }

    if !manifest.output_schema.is_object() {
        warnings.push(issue(
            "$.outputSchema",
            "Output schema should be a JSON Schema object",
        ));
    }

    validate_permissions(&manifest.permissions, &mut issues, &mut warnings);

    let valid = issues.is_empty();
    ValidationReport {
        schema_version: "swarm-ai.validation-report.v1".to_string(),
        valid,
        issues,
        warnings,
        manifest: Some(manifest),
    }
}

pub fn is_relative_package_path(path: &str) -> bool {
    if path.trim().is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains(':')
        || path.contains('\\')
    {
        return false;
    }

    !path.split('/').any(|part| part == ".." || part.is_empty())
}

fn validate_permissions(
    permissions: &[PermissionRequest],
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    let mut names = HashSet::new();
    for (index, permission) in permissions.iter().enumerate() {
        let base = format!("$.permissions[{index}]");
        if permission.name.trim().is_empty() {
            issues.push(issue(format!("{base}.name"), "Permission name is required"));
        }
        if !names.insert(permission.name.clone()) {
            warnings.push(issue(
                format!("{base}.name"),
                "Permission is declared more than once",
            ));
        }
    }
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{is_relative_package_path, validate_package_manifest_value};
    use serde_json::json;

    #[test]
    fn accepts_valid_minimal_manifest() {
        let manifest = json!({
            "schemaVersion": "swarm-ai.package.v1",
            "packageId": "demo/hello",
            "kind": "model",
            "name": "Hello",
            "version": "0.1.0",
            "publisher": {"address": "0x0000000000000000000000000000000000000000", "displayName": "Demo"},
            "capabilities": ["embedding"],
            "artifactGroups": [{
                "id": "browser-wasm-small",
                "target": "browser-wasm",
                "engine": "wasm-mock",
                "format": "json",
                "paths": ["model/browser/config.json"],
                "totalBytes": 128,
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "minimum": {"memoryMB": 128}
            }],
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "permissions": [],
            "license": {"type": "open", "name": "Apache-2.0"}
        });

        let report = validate_package_manifest_value(&manifest);
        assert!(report.valid, "{report:#?}");
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(!is_relative_package_path("../secrets.txt"));
        assert!(!is_relative_package_path("model\\weights.bin"));
        assert!(is_relative_package_path("model/browser/config.json"));
    }
}
