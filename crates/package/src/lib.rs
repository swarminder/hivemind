use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    ArtifactGroup, ArtifactMinimum, LicenseInfo, LicenseType, PackageKind, PackageManifestV1,
    Publisher, ValidationIssue, ValidationReport, canonicalize_json, hash_canonical_json,
    validate_package_manifest_value, validation::is_relative_package_path,
};
use hivemind_storage::StorageProvider;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const PACKAGE_VALIDATION_AUDIT_RECORD_SCHEMA_VERSION: &str =
    "hivemind.package_validation_audit_record.v1";
pub const PACKAGE_VALIDATION_AUDIT_STORE_SUMMARY_SCHEMA_VERSION: &str =
    "hivemind.package_validation_audit_store_summary.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PackageTemplateKind {
    EmbeddingModel,
    ChatModel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PackageInitOptionsV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub name: String,
    pub version: String,
    pub template: PackageTemplateKind,
    pub publisher: String,
    #[serde(rename = "publisherDisplayName")]
    pub publisher_display_name: String,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PackageInitFileV1 {
    pub path: String,
    #[serde(rename = "byteLength")]
    pub byte_length: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PackageInitResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "manifestPath")]
    pub manifest_path: String,
    pub files: Vec<PackageInitFileV1>,
    pub validation: ValidationReport,
}

#[derive(Debug, Clone)]
pub struct LocalPackage {
    pub root: PathBuf,
    pub manifest: PackageManifestV1,
    pub manifest_hash: String,
    pub package_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PackageValidationSourceKindV1 {
    LocalDirectory,
    StorageReference,
    InlineManifest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PackageValidationAuditRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "validationId")]
    pub validation_id: String,
    #[serde(rename = "sourceKind")]
    pub source_kind: PackageValidationSourceKindV1,
    pub source: String,
    #[serde(
        rename = "manifestHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub manifest_hash: Option<String>,
    #[serde(rename = "packageId", default, skip_serializing_if = "Option::is_none")]
    pub package_id: Option<String>,
    #[serde(
        rename = "packageVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_version: Option<String>,
    pub valid: bool,
    #[serde(rename = "issueCount")]
    pub issue_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    #[serde(
        rename = "manifestParseElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub manifest_parse_elapsed_ms: Option<u64>,
    #[serde(rename = "validationElapsedMs")]
    pub validation_elapsed_ms: u64,
    #[serde(rename = "totalElapsedMs")]
    pub total_elapsed_ms: u64,
    #[serde(rename = "recordedAt")]
    pub recorded_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PackageValidationAuditStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "validationCount")]
    pub validation_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "manifestParseSampleCount")]
    pub manifest_parse_sample_count: usize,
    #[serde(
        rename = "averageManifestParseElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_manifest_parse_elapsed_ms: Option<f64>,
    #[serde(
        rename = "maxManifestParseElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_manifest_parse_elapsed_ms: Option<u64>,
    #[serde(rename = "validationSampleCount")]
    pub validation_sample_count: usize,
    #[serde(
        rename = "averageValidationElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_validation_elapsed_ms: Option<f64>,
    #[serde(
        rename = "maxValidationElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_validation_elapsed_ms: Option<u64>,
    pub validations: Vec<PackageValidationAuditRecordV1>,
}

pub fn read_manifest_value(root: &Path) -> Result<Value> {
    let manifest_path = root.join("swarm-ai.json");
    let bytes = fs::read(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", manifest_path.display()))
}

pub fn load_package_from_dir(root: &Path) -> Result<LocalPackage> {
    let manifest_value = read_manifest_value(root)?;
    let canonical = canonicalize_json(&manifest_value);
    let manifest_hash = hash_canonical_json(&canonical);
    let manifest: PackageManifestV1 =
        serde_json::from_value(manifest_value).with_context(|| {
            format!(
                "{} is not PackageManifestV1",
                root.join("swarm-ai.json").display()
            )
        })?;
    let package_ref = format!("bzz://local-{}", &manifest_hash[..32]);

    Ok(LocalPackage {
        root: root.to_path_buf(),
        manifest,
        manifest_hash,
        package_ref,
    })
}

pub fn load_package_from_storage(
    package_ref: &str,
    storage: &impl StorageProvider,
) -> Result<LocalPackage> {
    let response = storage
        .download_file(package_ref, "swarm-ai.json")
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let manifest_value: Value = serde_json::from_slice(&response.bytes)
        .with_context(|| format!("{package_ref}/swarm-ai.json is not valid JSON"))?;
    let canonical = canonicalize_json(&manifest_value);
    let manifest_hash = hash_canonical_json(&canonical);
    let manifest: PackageManifestV1 = serde_json::from_value(manifest_value)
        .with_context(|| format!("{package_ref}/swarm-ai.json is not PackageManifestV1"))?;

    Ok(LocalPackage {
        root: PathBuf::new(),
        manifest,
        manifest_hash,
        package_ref: package_ref.to_string(),
    })
}

pub fn validate_package_ref(
    package_ref: &str,
    storage: &impl StorageProvider,
) -> Result<ValidationReport> {
    let response = storage
        .download_file(package_ref, "swarm-ai.json")
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let manifest_value: Value = serde_json::from_slice(&response.bytes)
        .with_context(|| format!("{package_ref}/swarm-ai.json is not valid JSON"))?;
    let mut report = validate_package_manifest_value(&manifest_value);

    if let Some(manifest) = report.manifest.clone() {
        for (group_index, group) in manifest.artifact_groups.iter().enumerate() {
            for (path_index, path) in group.paths.iter().enumerate() {
                if !is_relative_package_path(path) {
                    continue;
                }
                if let Err(error) = storage.download_file(package_ref, path) {
                    report.issues.push(ValidationIssue {
                        path: format!("$.artifactGroups[{group_index}].paths[{path_index}]"),
                        message: format!("Referenced file is not retrievable: {path}: {error}"),
                    });
                }
            }
        }
        report.valid = report.issues.is_empty();
    }

    Ok(report)
}

pub fn validate_package_dir_with_audit(
    root: &Path,
) -> Result<(ValidationReport, PackageValidationAuditRecordV1)> {
    let total_start = Instant::now();
    let parse_start = Instant::now();
    let manifest_value = read_manifest_value(root)?;
    let parse_elapsed_ms = elapsed_ms(parse_start);
    let manifest_hash = manifest_hash_from_value(&manifest_value);
    let validation_start = Instant::now();
    let mut report = validate_package_manifest_value(&manifest_value);
    if let Some(manifest) = report.manifest.clone() {
        append_path_validation(root, &manifest, &mut report);
    }
    let validation_elapsed_ms = elapsed_ms(validation_start);
    let record = package_validation_audit_record(
        &report,
        PackageValidationSourceKindV1::LocalDirectory,
        root.display().to_string(),
        Some(manifest_hash),
        Some(parse_elapsed_ms),
        validation_elapsed_ms,
        elapsed_ms(total_start),
    );
    Ok((report, record))
}

pub fn validate_package_ref_with_audit(
    package_ref: &str,
    storage: &impl StorageProvider,
) -> Result<(ValidationReport, PackageValidationAuditRecordV1)> {
    let total_start = Instant::now();
    let response = storage
        .download_file(package_ref, "swarm-ai.json")
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let parse_start = Instant::now();
    let manifest_value: Value = serde_json::from_slice(&response.bytes)
        .with_context(|| format!("{package_ref}/swarm-ai.json is not valid JSON"))?;
    let parse_elapsed_ms = elapsed_ms(parse_start);
    let manifest_hash = manifest_hash_from_value(&manifest_value);
    let validation_start = Instant::now();
    let mut report = validate_package_manifest_value(&manifest_value);

    if let Some(manifest) = report.manifest.clone() {
        for (group_index, group) in manifest.artifact_groups.iter().enumerate() {
            for (path_index, path) in group.paths.iter().enumerate() {
                if !is_relative_package_path(path) {
                    continue;
                }
                if let Err(error) = storage.download_file(package_ref, path) {
                    report.issues.push(ValidationIssue {
                        path: format!("$.artifactGroups[{group_index}].paths[{path_index}]"),
                        message: format!("Referenced file is not retrievable: {path}: {error}"),
                    });
                }
            }
        }
        report.valid = report.issues.is_empty();
    }
    let validation_elapsed_ms = elapsed_ms(validation_start);
    let record = package_validation_audit_record(
        &report,
        PackageValidationSourceKindV1::StorageReference,
        package_ref.to_string(),
        Some(manifest_hash),
        Some(parse_elapsed_ms),
        validation_elapsed_ms,
        elapsed_ms(total_start),
    );
    Ok((report, record))
}

pub fn validate_manifest_value_with_audit(
    value: &Value,
    source: impl Into<String>,
) -> (ValidationReport, PackageValidationAuditRecordV1) {
    let total_start = Instant::now();
    let validation_start = Instant::now();
    let report = validate_package_manifest_value(value);
    let validation_elapsed_ms = elapsed_ms(validation_start);
    let record = package_validation_audit_record(
        &report,
        PackageValidationSourceKindV1::InlineManifest,
        source.into(),
        Some(manifest_hash_from_value(value)),
        None,
        validation_elapsed_ms,
        elapsed_ms(total_start),
    );
    (report, record)
}

pub fn write_package_validation_audit_record(
    audit_dir: &Path,
    record: &PackageValidationAuditRecordV1,
) -> Result<PathBuf> {
    fs::create_dir_all(audit_dir).with_context(|| {
        format!(
            "failed to create package validation audit dir {}",
            audit_dir.display()
        )
    })?;
    let path = audit_dir.join(format!(
        "{}.json",
        safe_file_component(&record.validation_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(record)?).with_context(|| {
        format!(
            "failed to write package validation audit record {}",
            path.display()
        )
    })?;
    Ok(path)
}

pub fn read_package_validation_audit_record(path: &Path) -> Result<PackageValidationAuditRecordV1> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "failed to read package validation audit record {}",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse package validation audit record {}",
            path.display()
        )
    })
}

pub fn list_package_validation_audit(
    audit_dir: &Path,
) -> Result<PackageValidationAuditStoreSummaryV1> {
    let mut validations = Vec::new();
    if audit_dir.exists() {
        for entry in fs::read_dir(audit_dir)
            .with_context(|| format!("failed to read {}", audit_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                validations.push(read_package_validation_audit_record(&path)?);
            }
        }
    }
    validations.sort_by(|left, right| {
        left.recorded_at
            .cmp(&right.recorded_at)
            .then(left.validation_id.cmp(&right.validation_id))
    });
    let parse_values = validations
        .iter()
        .filter_map(|record| record.manifest_parse_elapsed_ms)
        .collect::<Vec<_>>();
    let validation_values = validations
        .iter()
        .map(|record| record.validation_elapsed_ms)
        .collect::<Vec<_>>();
    let valid_count = validations.iter().filter(|record| record.valid).count();
    Ok(PackageValidationAuditStoreSummaryV1 {
        schema_version: PACKAGE_VALIDATION_AUDIT_STORE_SUMMARY_SCHEMA_VERSION.to_string(),
        root: audit_dir.display().to_string(),
        validation_count: validations.len(),
        valid_count,
        invalid_count: validations.len().saturating_sub(valid_count),
        manifest_parse_sample_count: parse_values.len(),
        average_manifest_parse_elapsed_ms: average_u64(&parse_values),
        max_manifest_parse_elapsed_ms: parse_values.iter().copied().max(),
        validation_sample_count: validation_values.len(),
        average_validation_elapsed_ms: average_u64(&validation_values),
        max_validation_elapsed_ms: validation_values.iter().copied().max(),
        validations,
    })
}

pub fn default_init_options(
    package_id: impl Into<String>,
    name: Option<String>,
    template: PackageTemplateKind,
) -> PackageInitOptionsV1 {
    let package_id = package_id.into();
    PackageInitOptionsV1 {
        schema_version: "swarm-ai.package-init-options.v1".to_string(),
        name: name.unwrap_or_else(|| display_name_from_package_id(&package_id)),
        package_id,
        version: "0.1.0".to_string(),
        template,
        publisher: "0x0000000000000000000000000000000000000000".to_string(),
        publisher_display_name: "Hivemind Labs".to_string(),
        force: false,
    }
}

pub fn init_package_dir(
    root: &Path,
    options: &PackageInitOptionsV1,
) -> Result<PackageInitResultV1> {
    if root.exists() && !options.force && fs::read_dir(root)?.next().is_some() {
        anyhow::bail!(
            "{} already exists and is not empty; pass force to overwrite scaffold files",
            root.display()
        );
    }

    let scaffold = scaffold_files(options);
    for file in &scaffold {
        let path = root.join(&file.path);
        if path.exists() && !options.force {
            anyhow::bail!(
                "{} already exists; pass force to overwrite scaffold files",
                path.display()
            );
        }
    }

    fs::create_dir_all(root)?;
    let mut files = Vec::new();
    for file in scaffold {
        let path = root.join(&file.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &file.bytes)
            .with_context(|| format!("failed to write {}", path.display()))?;
        files.push(PackageInitFileV1 {
            path: file.path,
            byte_length: file.bytes.len(),
        });
    }

    let validation = validate_package_dir(root)?;
    Ok(PackageInitResultV1 {
        schema_version: "swarm-ai.package-init-result.v1".to_string(),
        root: root.display().to_string(),
        manifest_path: root.join("swarm-ai.json").display().to_string(),
        files,
        validation,
    })
}

pub fn validate_package_dir(root: &Path) -> Result<ValidationReport> {
    let manifest_value = read_manifest_value(root)?;
    let mut report = validate_package_manifest_value(&manifest_value);
    if let Some(manifest) = report.manifest.clone() {
        append_path_validation(root, &manifest, &mut report);
    }
    Ok(report)
}

pub fn append_path_validation(
    root: &Path,
    manifest: &PackageManifestV1,
    report: &mut ValidationReport,
) {
    for (group_index, group) in manifest.artifact_groups.iter().enumerate() {
        for (path_index, path) in group.paths.iter().enumerate() {
            if is_relative_package_path(path) && !root.join(path).exists() {
                report.issues.push(ValidationIssue {
                    path: format!("$.artifactGroups[{group_index}].paths[{path_index}]"),
                    message: format!("Referenced file does not exist: {path}"),
                });
            }
        }
    }
    report.valid = report.issues.is_empty();
}

struct ScaffoldFile {
    path: String,
    bytes: Vec<u8>,
}

fn scaffold_files(options: &PackageInitOptionsV1) -> Vec<ScaffoldFile> {
    let artifacts = template_artifacts(&options.template);
    let manifest = template_manifest(options, &artifacts);
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("manifest should serialize");
    let mut files = vec![ScaffoldFile {
        path: "swarm-ai.json".to_string(),
        bytes: manifest_bytes,
    }];
    files.extend(artifacts);
    files
}

fn template_manifest(
    options: &PackageInitOptionsV1,
    artifacts: &[ScaffoldFile],
) -> PackageManifestV1 {
    match options.template {
        PackageTemplateKind::EmbeddingModel => {
            let artifact_paths = vec![
                "model/browser/config.json".to_string(),
                "model/browser/tokenizer.json".to_string(),
            ];
            PackageManifestV1 {
                schema_version: "swarm-ai.package.v1".to_string(),
                package_id: options.package_id.clone(),
                kind: PackageKind::Model,
                name: options.name.clone(),
                version: options.version.clone(),
                publisher: publisher(options),
                capabilities: vec!["embedding".to_string(), "classification".to_string()],
                artifact_groups: vec![
                    artifact_group(
                        "browser-wasm-small",
                        "browser-wasm",
                        "wasm-mock",
                        &artifact_paths,
                        artifacts,
                    ),
                    artifact_group(
                        "local-rust-mock",
                        "local-mock",
                        "rust-mock",
                        &artifact_paths,
                        artifacts,
                    ),
                ],
                input_schema: json!({
                    "type": "object",
                    "required": ["text"],
                    "properties": {
                        "text": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "embedding": {
                            "type": "array",
                            "items": { "type": "number" }
                        }
                    }
                }),
                permissions: Vec::new(),
                license: open_license(),
            }
        }
        PackageTemplateKind::ChatModel => {
            let artifact_paths = vec!["model/config.json".to_string()];
            PackageManifestV1 {
                schema_version: "swarm-ai.package.v1".to_string(),
                package_id: options.package_id.clone(),
                kind: PackageKind::Model,
                name: options.name.clone(),
                version: options.version.clone(),
                publisher: publisher(options),
                capabilities: vec!["chat".to_string()],
                artifact_groups: vec![
                    artifact_group(
                        "local-rust-chat-mock",
                        "local-mock",
                        "rust-mock",
                        &artifact_paths,
                        artifacts,
                    ),
                    artifact_group(
                        "remote-vllm-chat-mock",
                        "cuda-vllm",
                        "vllm",
                        &artifact_paths,
                        artifacts,
                    ),
                ],
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "text": { "type": "string" },
                        "messages": {
                            "type": "array",
                            "items": { "type": "object" }
                        }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "object",
                            "properties": {
                                "role": { "type": "string" },
                                "content": { "type": "string" }
                            }
                        }
                    }
                }),
                permissions: Vec::new(),
                license: open_license(),
            }
        }
    }
}

fn template_artifacts(template: &PackageTemplateKind) -> Vec<ScaffoldFile> {
    match template {
        PackageTemplateKind::EmbeddingModel => vec![
            ScaffoldFile {
                path: "model/browser/config.json".to_string(),
                bytes: json!({
                    "model": "scaffold-embedding",
                    "dimensions": 4,
                    "runtime": "wasm-mock"
                })
                .to_string()
                .into_bytes(),
            },
            ScaffoldFile {
                path: "model/browser/tokenizer.json".to_string(),
                bytes: json!({
                    "type": "whitespace",
                    "lowercase": true
                })
                .to_string()
                .into_bytes(),
            },
            ScaffoldFile {
                path: "docs/model-card.txt".to_string(),
                bytes: b"Scaffolded embedding model package.\n".to_vec(),
            },
        ],
        PackageTemplateKind::ChatModel => vec![
            ScaffoldFile {
                path: "model/config.json".to_string(),
                bytes: json!({
                    "model": "scaffold-chat",
                    "runtime": "rust-mock",
                    "contextWindow": 2048
                })
                .to_string()
                .into_bytes(),
            },
            ScaffoldFile {
                path: "docs/model-card.txt".to_string(),
                bytes: b"Scaffolded chat model package.\n".to_vec(),
            },
        ],
    }
}

fn artifact_group(
    id: &str,
    target: &str,
    engine: &str,
    paths: &[String],
    artifacts: &[ScaffoldFile],
) -> ArtifactGroup {
    let selected: Vec<&ScaffoldFile> = paths
        .iter()
        .filter_map(|path| artifacts.iter().find(|file| &file.path == path))
        .collect();
    ArtifactGroup {
        id: id.to_string(),
        target: target.to_string(),
        engine: engine.to_string(),
        format: "json".to_string(),
        paths: paths.to_vec(),
        total_bytes: selected.iter().map(|file| file.bytes.len() as u64).sum(),
        sha256: artifact_group_hash(&selected),
        minimum: ArtifactMinimum {
            memory_mb: Some(128),
            webgpu: Some(false),
            disk_mb: None,
        },
    }
}

fn artifact_group_hash(files: &[&ScaffoldFile]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.path.as_bytes());
        hasher.update([0]);
        hasher.update(&file.bytes);
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

fn publisher(options: &PackageInitOptionsV1) -> Publisher {
    Publisher {
        address: options.publisher.clone(),
        display_name: options.publisher_display_name.clone(),
        publisher_profile_ref: None,
    }
}

fn open_license() -> LicenseInfo {
    LicenseInfo {
        license_type: LicenseType::Open,
        name: Some("Apache-2.0".to_string()),
        url: None,
    }
}

fn display_name_from_package_id(package_id: &str) -> String {
    let raw_name = package_id
        .split('/')
        .next_back()
        .filter(|value| !value.is_empty())
        .unwrap_or(package_id);
    raw_name
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn package_validation_audit_record(
    report: &ValidationReport,
    source_kind: PackageValidationSourceKindV1,
    source: String,
    manifest_hash: Option<String>,
    manifest_parse_elapsed_ms: Option<u64>,
    validation_elapsed_ms: u64,
    total_elapsed_ms: u64,
) -> PackageValidationAuditRecordV1 {
    let mut record = PackageValidationAuditRecordV1 {
        schema_version: PACKAGE_VALIDATION_AUDIT_RECORD_SCHEMA_VERSION.to_string(),
        validation_id: String::new(),
        source_kind,
        source,
        manifest_hash,
        package_id: report
            .manifest
            .as_ref()
            .map(|manifest| manifest.package_id.clone()),
        package_version: report
            .manifest
            .as_ref()
            .map(|manifest| manifest.version.clone()),
        valid: report.valid,
        issue_count: report.issues.len(),
        warning_count: report.warnings.len(),
        manifest_parse_elapsed_ms,
        validation_elapsed_ms,
        total_elapsed_ms,
        recorded_at: timestamp(),
    };
    record.validation_id = canonical_package_validation_audit_record_id(&record);
    record
}

pub fn canonical_package_validation_audit_record_id(
    record: &PackageValidationAuditRecordV1,
) -> String {
    let mut value =
        serde_json::to_value(record).expect("package validation audit record should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("validationId");
    }
    format!("package-validation-{}", &hash_canonical_json(&value)[..24])
}

fn manifest_hash_from_value(value: &Value) -> String {
    hash_canonical_json(&canonicalize_json(value))
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn average_u64(values: &[u64]) -> Option<f64> {
    (!values.is_empty()).then(|| {
        let total: u64 = values.iter().sum();
        total as f64 / values.len() as f64
    })
}

fn safe_file_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn initializes_valid_embedding_package() {
        let root = unique_temp_dir("hivemind-package-init-embedding-test");
        let options =
            default_init_options("demo/hello-init", None, PackageTemplateKind::EmbeddingModel);

        let result = init_package_dir(&root, &options).unwrap();
        let package = load_package_from_dir(&root).unwrap();

        assert!(result.validation.valid, "{:?}", result.validation.issues);
        assert!(root.join("swarm-ai.json").exists());
        assert!(root.join("model/browser/config.json").exists());
        assert!(root.join("model/browser/tokenizer.json").exists());
        assert_eq!(package.manifest.package_id, "demo/hello-init");
        assert_eq!(package.manifest.name, "Hello Init");
        assert_eq!(package.manifest.capabilities[0], "embedding");
        assert_eq!(package.manifest.artifact_groups.len(), 2);
        assert!(package.manifest.artifact_groups[0].sha256.len() == 64);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn initializes_valid_chat_package_and_blocks_accidental_overwrite() {
        let root = unique_temp_dir("hivemind-package-init-chat-test");
        let options = default_init_options("demo/chat-init", None, PackageTemplateKind::ChatModel);

        let first = init_package_dir(&root, &options).unwrap();
        let second = init_package_dir(&root, &options);
        let mut forced_options = options.clone();
        forced_options.force = true;
        let forced = init_package_dir(&root, &forced_options).unwrap();

        assert!(first.validation.valid, "{:?}", first.validation.issues);
        assert!(second.is_err());
        assert!(forced.validation.valid, "{:?}", forced.validation.issues);
        assert!(root.join("model/config.json").exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn package_validation_audit_store_summarizes_manifest_timings() {
        let root = unique_temp_dir("hivemind-package-validation-audit-test");
        let audit_dir = root.join("audit");
        let package_dir = root.join("package");
        let options =
            default_init_options("demo/audit-init", None, PackageTemplateKind::EmbeddingModel);
        init_package_dir(&package_dir, &options).unwrap();

        let (report, mut record) = validate_package_dir_with_audit(&package_dir).unwrap();
        assert!(report.valid, "{:?}", report.issues);
        assert!(record.validation_id.starts_with("package-validation-"));
        assert_eq!(
            record.source_kind,
            PackageValidationSourceKindV1::LocalDirectory
        );
        assert_eq!(record.package_id.as_deref(), Some("demo/audit-init"));
        assert!(record.manifest_hash.is_some());
        record.manifest_parse_elapsed_ms = Some(4);
        record.validation_elapsed_ms = 6;
        record.total_elapsed_ms = 10;
        record.validation_id = canonical_package_validation_audit_record_id(&record);

        let path = write_package_validation_audit_record(&audit_dir, &record).unwrap();
        let reread = read_package_validation_audit_record(&path).unwrap();
        assert_eq!(reread.validation_id, record.validation_id);

        let summary = list_package_validation_audit(&audit_dir).unwrap();
        assert_eq!(summary.validation_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.invalid_count, 0);
        assert_eq!(summary.manifest_parse_sample_count, 1);
        assert_eq!(summary.average_manifest_parse_elapsed_ms, Some(4.0));
        assert_eq!(summary.max_manifest_parse_elapsed_ms, Some(4));
        assert_eq!(summary.validation_sample_count, 1);
        assert_eq!(summary.average_validation_elapsed_ms, Some(6.0));
        assert_eq!(summary.max_validation_elapsed_ms, Some(6));

        let _ = fs::remove_dir_all(root);
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }
}
