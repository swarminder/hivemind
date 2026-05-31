use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerType {
    Browser,
    Local,
    RemoteGpu,
    Marketplace,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerLimits {
    #[serde(rename = "maxMemoryMB")]
    pub max_memory_mb: u64,
    #[serde(rename = "maxInputBytes")]
    pub max_input_bytes: u64,
    #[serde(rename = "maxConcurrentJobs")]
    pub max_concurrent_jobs: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerDescriptorV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "runnerType")]
    pub runner_type: RunnerType,
    pub targets: Vec<String>,
    pub engines: Vec<String>,
    pub capabilities: Vec<String>,
    pub limits: RunnerLimits,
    #[serde(rename = "queueDepth")]
    pub queue_depth: u32,
    #[serde(rename = "warmPackageRefs", default)]
    pub warm_package_refs: Vec<String>,
}

pub fn runner_supports_capability(runner: &RunnerDescriptorV1, capability: &str) -> bool {
    runner
        .capabilities
        .iter()
        .any(|declared| declared == capability)
}
