use crate::manifest::{ArtifactGroup, PackageManifestV1};

pub fn select_artifact_group<'a>(
    manifest: &'a PackageManifestV1,
    preferred_artifact_group: Option<&str>,
    supported_targets: &[String],
    supported_engines: &[String],
) -> Option<&'a ArtifactGroup> {
    if let Some(preferred) = preferred_artifact_group {
        if let Some(group) = manifest.artifact_groups.iter().find(|group| {
            group.id == preferred
                && supports(&group.target, supported_targets)
                && supports(&group.engine, supported_engines)
        }) {
            return Some(group);
        }
    }

    for target in supported_targets {
        for engine in supported_engines {
            if let Some(group) = manifest
                .artifact_groups
                .iter()
                .find(|group| &group.target == target && &group.engine == engine)
            {
                return Some(group);
            }
        }
    }

    None
}

fn supports(value: &str, supported: &[String]) -> bool {
    supported.iter().any(|candidate| candidate == value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactMinimum, LicenseInfo, LicenseType, PackageKind, Publisher};
    use serde_json::json;

    #[test]
    fn uses_runner_target_priority_after_preferred_group() {
        let manifest = manifest_with_groups(vec![
            group("browser", "browser-wasm", "wasm-mock"),
            group("local", "local-mock", "rust-mock"),
        ]);
        let targets = vec!["local-mock".to_string(), "browser-wasm".to_string()];
        let engines = vec!["rust-mock".to_string(), "wasm-mock".to_string()];

        let selected = select_artifact_group(&manifest, None, &targets, &engines);
        assert_eq!(selected.map(|group| group.id.as_str()), Some("local"));

        let selected = select_artifact_group(&manifest, Some("browser"), &targets, &engines);
        assert_eq!(selected.map(|group| group.id.as_str()), Some("browser"));
    }

    fn manifest_with_groups(artifact_groups: Vec<ArtifactGroup>) -> PackageManifestV1 {
        PackageManifestV1 {
            schema_version: "swarm-ai.package.v1".to_string(),
            package_id: "hivemind/test".to_string(),
            kind: PackageKind::Model,
            name: "Test".to_string(),
            version: "0.1.0".to_string(),
            publisher: Publisher {
                address: "0x0000000000000000000000000000000000000000".to_string(),
                display_name: "Hivemind".to_string(),
                publisher_profile_ref: None,
            },
            capabilities: vec!["embedding".to_string()],
            artifact_groups,
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            permissions: Vec::new(),
            license: LicenseInfo {
                license_type: LicenseType::Open,
                name: Some("Apache-2.0".to_string()),
                url: None,
            },
        }
    }

    fn group(id: &str, target: &str, engine: &str) -> ArtifactGroup {
        ArtifactGroup {
            id: id.to_string(),
            target: target.to_string(),
            engine: engine.to_string(),
            format: "json".to_string(),
            paths: vec!["model/config.json".to_string()],
            total_bytes: 1,
            sha256: "0".repeat(64),
            minimum: ArtifactMinimum {
                memory_mb: Some(1),
                webgpu: Some(false),
                disk_mb: None,
            },
        }
    }
}
