use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const API_SOURCE: &str = include_str!("api.rs");
const MAIN_SOURCE: &str = include_str!("main.rs");
const PROVIDER_SOURCE: &str = include_str!("provider.rs");
const GENERATOR_VERSION: &str = "hivemind-docs-v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteInventoryEntry {
    pub method: String,
    pub path: String,
    pub axum_path: String,
    pub handler: String,
    pub owner: String,
    pub readiness: String,
    pub auth: String,
    pub writes_audit: bool,
    pub may_spend_funds: bool,
    pub may_upload_data: bool,
    pub may_run_ai: bool,
    pub deprecated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SchemaInventoryEntry {
    pub command: String,
    pub rust_type: String,
    pub type_name: String,
    pub version: String,
    pub owner: String,
    pub stability: String,
    pub readiness: String,
    pub fixture_path: String,
    pub json_schema_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DocsGenerateSummary {
    #[serde(rename = "generatorVersion")]
    pub generator_version: &'static str,
    #[serde(rename = "outputDir")]
    pub output_dir: String,
    #[serde(rename = "apiRoutesPath")]
    pub api_routes_path: String,
    #[serde(rename = "schemasPath")]
    pub schemas_path: String,
    #[serde(rename = "routeCount")]
    pub route_count: usize,
    #[serde(rename = "uniqueRoutePathCount")]
    pub unique_route_path_count: usize,
    #[serde(rename = "schemaCount")]
    pub schema_count: usize,
    pub status: String,
}

pub fn generate_docs(output_dir: &Path) -> Result<DocsGenerateSummary> {
    let generated = GeneratedDocs::from_sources();
    fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    let api_routes_path = output_dir.join("api-routes.md");
    let schemas_path = output_dir.join("schemas.md");
    fs::write(&api_routes_path, generated.api_routes_markdown.as_bytes())
        .with_context(|| format!("failed to write {}", api_routes_path.display()))?;
    fs::write(&schemas_path, generated.schemas_markdown.as_bytes())
        .with_context(|| format!("failed to write {}", schemas_path.display()))?;

    Ok(generated.summary(output_dir, "generated"))
}

pub fn check_generated_docs(output_dir: &Path) -> Result<DocsGenerateSummary> {
    let generated = GeneratedDocs::from_sources();
    let api_routes_path = output_dir.join("api-routes.md");
    let schemas_path = output_dir.join("schemas.md");
    let mut stale = Vec::new();

    match fs::read_to_string(&api_routes_path) {
        Ok(existing) if existing == generated.api_routes_markdown => {}
        Ok(_) => stale.push(api_routes_path.display().to_string()),
        Err(_) => stale.push(api_routes_path.display().to_string()),
    }
    match fs::read_to_string(&schemas_path) {
        Ok(existing) if existing == generated.schemas_markdown => {}
        Ok(_) => stale.push(schemas_path.display().to_string()),
        Err(_) => stale.push(schemas_path.display().to_string()),
    }

    if !stale.is_empty() {
        bail!(
            "generated docs are missing or stale: {}. Run `cargo run -p hivemind-server -- docs generate`.",
            stale.join(", ")
        );
    }

    Ok(generated.summary(output_dir, "current"))
}

struct GeneratedDocs {
    routes: Vec<RouteInventoryEntry>,
    schemas: Vec<SchemaInventoryEntry>,
    api_routes_markdown: String,
    schemas_markdown: String,
}

impl GeneratedDocs {
    fn from_sources() -> Self {
        let routes = route_inventory_from_source(&format!("{API_SOURCE}\n{PROVIDER_SOURCE}"));
        let schemas = schema_inventory_from_source(MAIN_SOURCE);
        let api_routes_markdown = render_routes_markdown(&routes);
        let schemas_markdown = render_schemas_markdown(&schemas);
        Self {
            routes,
            schemas,
            api_routes_markdown,
            schemas_markdown,
        }
    }

    fn summary(&self, output_dir: &Path, status: impl Into<String>) -> DocsGenerateSummary {
        let unique_route_path_count = self
            .routes
            .iter()
            .map(|route| route.path.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        DocsGenerateSummary {
            generator_version: GENERATOR_VERSION,
            output_dir: output_dir.display().to_string(),
            api_routes_path: output_dir.join("api-routes.md").display().to_string(),
            schemas_path: output_dir.join("schemas.md").display().to_string(),
            route_count: self.routes.len(),
            unique_route_path_count,
            schema_count: self.schemas.len(),
            status: status.into(),
        }
    }
}

fn route_inventory_from_source(source: &str) -> Vec<RouteInventoryEntry> {
    let mut entries = BTreeSet::new();
    let mut cursor = 0;

    while let Some(relative) = source[cursor..].find(".route(") {
        let open_index = cursor + relative + ".route".len();
        let Some((arguments, end_index)) = balanced_content(source, open_index, '(', ')') else {
            break;
        };
        cursor = end_index;

        let Some((axum_path, path_end)) = parse_string_literal(arguments) else {
            continue;
        };
        if !axum_path.starts_with('/') {
            continue;
        }

        let handlers = extract_route_handlers(&arguments[path_end..]);
        for (method, handler) in handlers {
            let path = canonical_route_path(&axum_path);
            entries.insert(RouteInventoryEntry {
                writes_audit: route_writes_audit(&method, &path),
                may_spend_funds: route_may_spend_funds(&method, &path),
                may_upload_data: route_may_upload_data(&method, &path),
                may_run_ai: route_may_run_ai(&method, &path),
                method,
                path: path.clone(),
                axum_path: axum_path.clone(),
                owner: route_owner(&path).to_string(),
                readiness: route_readiness(&path).to_string(),
                auth: route_auth(&path).to_string(),
                deprecated: false,
                handler,
            });
        }
    }

    entries.into_iter().collect()
}

fn schema_inventory_from_source(source: &str) -> Vec<SchemaInventoryEntry> {
    let Some(function_start) = source.find("fn schema_command") else {
        return Vec::new();
    };
    let function_source = &source[function_start..];
    let Some(match_start) = function_source.find("match kind") else {
        return Vec::new();
    };
    let match_source = &function_source[match_start..];
    let Some(open_relative) = match_source.find('{') else {
        return Vec::new();
    };
    let Some((match_body, _)) = balanced_content(match_source, open_relative, '{', '}') else {
        return Vec::new();
    };

    let mut entries = BTreeMap::new();
    let mut cursor = 0;
    while let Some(relative) = match_body[cursor..].find('"') {
        let literal_start = cursor + relative;
        let Some((command, literal_end)) = parse_string_literal(&match_body[literal_start..])
        else {
            cursor = literal_start + 1;
            continue;
        };
        let after_literal = literal_start + literal_end;
        let after_trimmed = match_body[after_literal..].trim_start();
        if !after_trimmed.starts_with("=>") {
            cursor = after_literal;
            continue;
        }

        let arm_source = &after_trimmed[2..];
        let Some(schema_for_relative) = arm_source.find("schema_for!") else {
            cursor = after_literal;
            continue;
        };
        let schema_for_source = &arm_source[schema_for_relative..];
        let Some(open_relative) = schema_for_source.find('(') else {
            cursor = after_literal;
            continue;
        };
        let Some((type_source, _)) = balanced_content(schema_for_source, open_relative, '(', ')')
        else {
            cursor = after_literal;
            continue;
        };

        let rust_type = normalize_type_path(type_source);
        let type_name = rust_type
            .rsplit("::")
            .next()
            .unwrap_or(rust_type.as_str())
            .to_string();
        entries.insert(
            command.clone(),
            SchemaInventoryEntry {
                command: command.clone(),
                version: infer_schema_version(&command, &type_name),
                owner: schema_owner(&rust_type).to_string(),
                stability: schema_stability(&command, &type_name).to_string(),
                readiness: schema_readiness(&command, &rust_type).to_string(),
                fixture_path: "pending".to_string(),
                json_schema_path: format!("generated/json-schema/{}.schema.json", command),
                rust_type,
                type_name,
            },
        );
        cursor = after_literal;
    }

    entries.into_values().collect()
}

fn render_routes_markdown(routes: &[RouteInventoryEntry]) -> String {
    let unique_paths = routes
        .iter()
        .map(|route| route.path.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let mut output = String::new();
    output.push_str("# Generated API Routes\n\n");
    output.push_str(
        "This file is generated by `swarm-ai docs generate`. Do not edit it by hand.\n\n",
    );
    output.push_str(&format!("- Generator version: `{GENERATOR_VERSION}`\n"));
    output.push_str("- Source: `crates/server/src/api.rs`, `crates/server/src/provider.rs`\n");
    output.push_str(&format!("- Total route entries: `{}`\n", routes.len()));
    output.push_str(&format!("- Unique canonical paths: `{unique_paths}`\n"));
    output.push_str("- Readiness labels are conservative source-derived defaults: `local`, `gateway`, or `browser-test`.\n\n");
    output.push_str("| Method | Path | Axum Path | Handler | Owner | Readiness | Auth / Access | Audit | Spend Funds | Upload Data | Run AI | Deprecated |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for route in routes {
        output.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            escape_table(&route.method),
            escape_table(&route.path),
            escape_table(&route.axum_path),
            escape_table(&route.handler),
            escape_table(&route.owner),
            escape_table(&route.readiness),
            escape_table(&route.auth),
            bool_cell(route.writes_audit),
            bool_cell(route.may_spend_funds),
            bool_cell(route.may_upload_data),
            bool_cell(route.may_run_ai),
            bool_cell(route.deprecated),
        ));
    }
    output
}

fn render_schemas_markdown(schemas: &[SchemaInventoryEntry]) -> String {
    let mut output = String::new();
    output.push_str("# Generated Schema Inventory\n\n");
    output.push_str(
        "This file is generated by `swarm-ai docs generate`. Do not edit it by hand.\n\n",
    );
    output.push_str(&format!("- Generator version: `{GENERATOR_VERSION}`\n"));
    output.push_str("- Source: `crates/server/src/main.rs::schema_command`\n");
    output.push_str(&format!("- Total schema commands: `{}`\n", schemas.len()));
    output.push_str(
        "- Fixture paths are marked `pending` until executable public fixtures are added.\n\n",
    );
    output.push_str("| Command | Rust Type | Version | Owner | Stability | Readiness | Fixture | JSON Schema Path |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for schema in schemas {
        output.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} | {} | {} | `{}` |\n",
            escape_table(&schema.command),
            escape_table(&schema.rust_type),
            escape_table(&schema.version),
            escape_table(&schema.owner),
            escape_table(&schema.stability),
            escape_table(&schema.readiness),
            escape_table(&schema.fixture_path),
            escape_table(&schema.json_schema_path),
        ));
    }
    output
}

fn extract_route_handlers(source: &str) -> Vec<(String, String)> {
    const METHODS: [(&str, &str); 6] = [
        ("delete", "DELETE"),
        ("get", "GET"),
        ("patch", "PATCH"),
        ("post", "POST"),
        ("put", "PUT"),
        ("options", "OPTIONS"),
    ];

    let mut handlers = Vec::new();
    for (token, method) in METHODS {
        let mut cursor = 0;
        while let Some(relative) = source[cursor..].find(token) {
            let token_start = cursor + relative;
            let open_index = token_start + token.len();
            let open_is_paren = source
                .as_bytes()
                .get(open_index)
                .is_some_and(|byte| *byte == b'(');
            let boundary_before = token_start == 0
                || source
                    .as_bytes()
                    .get(token_start.saturating_sub(1))
                    .is_none_or(|byte| !is_identifier_byte(*byte));
            if open_is_paren && boundary_before {
                if let Some((handler, end_index)) = balanced_content(source, open_index, '(', ')') {
                    let handler = handler.trim().to_string();
                    if !handler.is_empty() {
                        handlers.push((token_start, method.to_string(), handler));
                    }
                    cursor = end_index;
                    continue;
                }
            }
            cursor = open_index;
        }
    }

    handlers.sort_by_key(|(position, _, _)| *position);
    handlers
        .into_iter()
        .map(|(_, method, handler)| (method, handler))
        .collect()
}

fn balanced_content(
    source: &str,
    open_index: usize,
    open: char,
    close: char,
) -> Option<(&str, usize)> {
    if !source[open_index..].starts_with(open) {
        return None;
    }

    let mut depth = 0usize;
    let mut content_start = None;
    let mut in_string = false;
    let mut escaped = false;

    for (relative, character) in source[open_index..].char_indices() {
        let index = open_index + relative;
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }

        if character == '"' {
            in_string = true;
        } else if character == open {
            if depth == 0 {
                content_start = Some(index + character.len_utf8());
            }
            depth += 1;
        } else if character == close {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                let start = content_start?;
                return Some((&source[start..index], index + character.len_utf8()));
            }
        }
    }

    None
}

fn parse_string_literal(source: &str) -> Option<(String, usize)> {
    let start = source.char_indices().find_map(|(index, character)| {
        (!character.is_whitespace()).then_some((index, character))
    })?;
    if start.1 != '"' {
        return None;
    }

    let mut output = String::new();
    let mut escaped = false;
    let content_start = start.0 + 1;
    for (relative, character) in source[content_start..].char_indices() {
        let index = content_start + relative;
        if escaped {
            output.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some((output, index + 1));
        } else {
            output.push(character);
        }
    }
    None
}

fn canonical_route_path(path: &str) -> String {
    let mut output = String::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'{' && bytes.get(index + 1).is_some_and(|byte| *byte == b'*') {
            output.push('{');
            index += 2;
            continue;
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

fn normalize_type_path(value: &str) -> String {
    value.split_whitespace().collect::<String>()
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn route_owner(path: &str) -> &'static str {
    if path == "/health" {
        return "hivemind-server";
    }
    let rest = path.strip_prefix("/v1/").unwrap_or(path);
    let first = rest.split('/').next().unwrap_or_default();
    match first {
        "access" => "hivemind-access",
        "ai" => "hivemind-core",
        "anthropic" | "gemini" | "huggingface" => "hivemind-provider-compat",
        "audio" | "batches" | "chat" | "embeddings" | "files" | "fine_tuning" | "images"
        | "models" | "moderations" | "responses" | "vector_stores" => "hivemind-openai-compat",
        "batch" => "hivemind-batch",
        "benchmarks" => "hivemind-benchmarks",
        "browser" => "hivemind-browser-runner",
        "browser-storage" | "storage" => "hivemind-storage",
        "browser-swarm" => "hivemind-weeb3-adapter",
        "compatibility" => "hivemind-sdk",
        "errors" => "hivemind-core",
        "evals" if path == "/v1/evals" || path.starts_with("/v1/evals/{") => {
            "hivemind-openai-compat"
        }
        "evals" => "hivemind-evals",
        "fine-tune" => "hivemind-fine-tune",
        "governance" => "hivemind-governance",
        "hivemind" | "swarm-ai" => "hivemind-server aliases",
        "marketplace" => "hivemind-marketplace",
        "media" => "hivemind-media",
        "miner" => "hivemind-miner",
        "moderation" => "hivemind-moderation",
        "observability" => "hivemind-observability",
        "packages" => "hivemind-package",
        "policy" => "hivemind-policy",
        "provider" => "hivemind-core",
        "publisher" => "hivemind-publisher",
        "realtime" => "hivemind-realtime",
        "receipts" => "hivemind-receipts",
        "registry" => "hivemind-registry",
        "remote" => "hivemind-remote-runner",
        "research" => "hivemind-research",
        "validator" => "hivemind-validator",
        "vector" => "hivemind-vector",
        "workflows" => "hivemind-workflow",
        _ => "hivemind-server",
    }
}

fn route_readiness(path: &str) -> &'static str {
    if path.contains("/provider/") {
        "lan-test"
    } else if path.contains("browser-storage") || path.contains("browser-swarm") {
        "browser-test"
    } else if path.contains("/storage/") {
        "gateway"
    } else {
        "local"
    }
}

fn route_auth(path: &str) -> &'static str {
    if path.contains("/provider/") {
        "provider bearer token or signed request envelope"
    } else if path.contains("/access/")
        || path.contains("/policy/")
        || path.contains("/marketplace/")
        || path.contains("/governance/")
    {
        "signed evidence or request policy"
    } else {
        "local-dev server boundary"
    }
}

fn route_writes_audit(method: &str, path: &str) -> bool {
    if !matches!(method, "POST" | "PUT" | "PATCH" | "DELETE") {
        return false;
    }
    path.contains("audit")
        || path.contains("verify")
        || path.contains("sign")
        || path.contains("upload")
        || path.contains("publish")
        || path.contains("jobs")
        || path.contains("receipts")
        || path.contains("marketplace")
        || path.contains("validator")
        || path.contains("benchmarks")
        || path.contains("research")
        || path.contains("/rag/")
        || path.contains("/provider/models/")
        || path.contains("/provider/sessions")
        || path.contains("governance")
        || path.contains("storage")
}

fn route_may_spend_funds(method: &str, path: &str) -> bool {
    if method != "POST" {
        return false;
    }
    path.contains("authorize-payment")
        || (path.contains("/provider/sessions") && !path.ends_with("/close"))
        || path.contains("/provider/chat")
        || path.contains("/provider/ledger")
        || path.contains("payment")
        || path.contains("escrow")
        || path.contains("settle")
        || path.contains("refund")
        || path.contains("slash")
}

fn route_may_upload_data(method: &str, path: &str) -> bool {
    if !matches!(method, "POST" | "PUT" | "PATCH") {
        return false;
    }
    path.contains("upload")
        || path.contains("publish")
        || path.contains("/files")
        || path.contains("/storage/")
        || path.contains("/rag/ingest")
        || path.contains("/browser-swarm/file")
        || path.contains("/browser-swarm/manifest")
}

fn route_may_run_ai(method: &str, path: &str) -> bool {
    if method != "POST" {
        return false;
    }
    path.contains("execute")
        || path.contains("completions")
        || path.contains("responses")
        || path.contains("embeddings")
        || path.contains("moderations")
        || path.contains("inference")
        || path.contains("generateContent")
        || path.contains("images")
        || path.contains("audio")
        || path.contains("realtime")
        || path.contains("fine_tuning")
        || path.contains("fine-tune")
        || path.contains("batch")
        || path.contains("evals")
        || path.contains("/rag/")
        || path.contains("/provider/chat")
        || (path.contains("/provider/models/") && !path.ends_with("/stop"))
        || path.contains("media")
}

fn schema_owner(type_path: &str) -> &'static str {
    if let Some(prefix) = type_path.split("::").next() {
        match prefix {
            "hivemind_access" => "hivemind-access",
            "hivemind_batch" => "hivemind-batch",
            "hivemind_benchmarks" => "hivemind-benchmarks",
            "hivemind_browser_runner" => "hivemind-browser-runner",
            "hivemind_core" => "hivemind-core",
            "hivemind_evals" => "hivemind-evals",
            "hivemind_fine_tune" => "hivemind-fine-tune",
            "hivemind_governance" => "hivemind-governance",
            "hivemind_identity" => "hivemind-identity",
            "hivemind_jobs" => "hivemind-jobs",
            "hivemind_local_runner" => "hivemind-local-runner",
            "hivemind_marketplace" => "hivemind-marketplace",
            "hivemind_media" => "hivemind-media",
            "hivemind_miner" => "hivemind-miner",
            "hivemind_moderation" => "hivemind-moderation",
            "hivemind_observability" => "hivemind-observability",
            "hivemind_openai_compat" => "hivemind-openai-compat",
            "hivemind_package" => "hivemind-package",
            "hivemind_policy" => "hivemind-policy",
            "hivemind_provider_compat" => "hivemind-provider-compat",
            "hivemind_publisher" => "hivemind-publisher",
            "hivemind_realtime" => "hivemind-realtime",
            "hivemind_receipts" => "hivemind-receipts",
            "hivemind_registry" => "hivemind-registry",
            "hivemind_remote_runner" => "hivemind-remote-runner",
            "hivemind_research" => "hivemind-research",
            "hivemind_router" => "hivemind-router",
            "hivemind_sdk" => "hivemind-sdk",
            "hivemind_storage" => "hivemind-storage",
            "hivemind_streams" => "hivemind-streams",
            "hivemind_validator" => "hivemind-validator",
            "hivemind_vector" => "hivemind-vector",
            "hivemind_weeb3_adapter" => "hivemind-weeb3-adapter",
            "hivemind_workflow" => "hivemind-workflow",
            _ => "hivemind-core",
        }
    } else {
        "hivemind-core"
    }
}

fn schema_readiness(command: &str, type_path: &str) -> &'static str {
    if command.contains("browser-storage")
        || command.contains("browser-swarm")
        || command.contains("browser-publish")
        || type_path.contains("BrowserStorage")
        || type_path.contains("BrowserSwarm")
        || type_path.contains("BrowserPublish")
    {
        "browser-test"
    } else {
        "local"
    }
}

fn infer_schema_version(command: &str, type_name: &str) -> String {
    if let Some(version) = version_from_type_name(type_name) {
        return version;
    }
    for part in command.rsplit('-') {
        if part.len() >= 2
            && part.starts_with('v')
            && part[1..]
                .chars()
                .all(|character| character.is_ascii_digit())
        {
            return part.to_string();
        }
    }
    "unknown".to_string()
}

fn version_from_type_name(type_name: &str) -> Option<String> {
    let chars: Vec<char> = type_name.chars().collect();
    for index in (0..chars.len()).rev() {
        if chars[index] == 'V' {
            let digits: String = chars[index + 1..]
                .iter()
                .take_while(|character| character.is_ascii_digit())
                .collect();
            if !digits.is_empty() {
                return Some(format!("v{digits}"));
            }
        }
    }
    None
}

fn schema_stability(command: &str, type_name: &str) -> &'static str {
    if command.contains("deprecated") || type_name.contains("Deprecated") {
        "deprecated"
    } else {
        "candidate"
    }
}

fn bool_cell(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn escape_table(value: &str) -> String {
    value.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_inventory_includes_known_openai_and_hivemind_routes() {
        let routes = route_inventory_from_source(API_SOURCE);
        assert!(routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/v1/chat/completions"
                && route.handler == "openai_chat_completions"
        }));
        assert!(routes.iter().any(|route| {
            route.method == "GET" && route.path == "/v1/hivemind/jobs/{job_id}/stream"
        }));
        assert!(routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/v1/swarm-ai/local-model-runner"
                && route.handler == "local_model_runner"
                && route.readiness == "local"
        }));
        assert!(routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/v1/hivemind/local-model-runner"
                && route.handler == "local_model_runner"
                && route.readiness == "local"
        }));
        assert!(routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/v1/rag/ingest"
                && route.handler == "rag_ingest"
                && route.readiness == "local"
                && route.writes_audit
                && route.may_upload_data
                && route.may_run_ai
        }));
        assert!(routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/v1/rag/search"
                && route.handler == "rag_search"
                && route.readiness == "local"
                && route.may_run_ai
        }));
        assert!(routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/v1/rag/ask"
                && route.handler == "rag_ask"
                && route.readiness == "local"
                && route.may_run_ai
        }));
    }

    #[test]
    fn schema_inventory_includes_current_public_contract_objects() {
        let schemas = schema_inventory_from_source(MAIN_SOURCE);
        assert!(schemas.iter().any(|schema| {
            schema.command == "browser-storage-capability-probe"
                && schema.rust_type == "hivemind_storage::BrowserStorageCapabilityProbeV1"
                && schema.readiness == "browser-test"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "browser-swarm-storage-provider-v6"
                && schema.rust_type == "hivemind_weeb3_adapter::BrowserSwarmStorageProviderV6"
                && schema.readiness == "browser-test"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "browser-publish-one-result"
                && schema.rust_type == "hivemind_weeb3_adapter::BrowserPublishOneResultV1"
                && schema.readiness == "browser-test"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "access-grant-v3"
                && schema.rust_type == "hivemind_core::AccessGrantV3"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "local-model-runner-descriptor"
                && schema.rust_type == "hivemind_local_runner::LocalModelRunnerDescriptorV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "local-model-inference-output"
                && schema.rust_type == "hivemind_local_runner::LocalModelInferenceOutputV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "ollama-local-model-config"
                && schema.rust_type == "hivemind_local_runner::OllamaLocalModelConfigV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "rag-ingest-request"
                && schema.rust_type == "hivemind_vector::RagIngestRequestV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "rag-index-snapshot"
                && schema.rust_type == "hivemind_vector::RagIndexSnapshotV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "rag-answer-result"
                && schema.rust_type == "hivemind_vector::RagAnswerResultV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "payment-authorization-v2"
                && schema.rust_type == "hivemind_marketplace::PaymentAuthorizationV2"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "escrow-record-v2"
                && schema.rust_type == "hivemind_marketplace::EscrowRecordV2"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "settlement-record-v2"
                && schema.rust_type == "hivemind_marketplace::SettlementRecordV2"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "dispute-record-v2"
                && schema.rust_type == "hivemind_marketplace::DisputeRecordV2"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "marketplace-audit-event"
                && schema.rust_type == "hivemind_marketplace::MarketplaceAuditEventV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "slashing-decision"
                && schema.rust_type == "hivemind_marketplace::SlashingDecisionV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "route-plan-v2"
                && schema.rust_type == "hivemind_router::RoutePlanV2"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "route-failure-analysis"
                && schema.rust_type == "hivemind_router::RouteFailureAnalysisV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "capacity-reservation"
                && schema.rust_type == "hivemind_router::CapacityReservationV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "retry-decision"
                && schema.rust_type == "hivemind_router::RetryDecisionV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "tool-invocation"
                && schema.rust_type == "hivemind_workflow::ToolInvocationV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "tool-result"
                && schema.rust_type == "hivemind_workflow::ToolResultV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "agent-run-state"
                && schema.rust_type == "hivemind_workflow::AgentRunStateV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "human-approval-request"
                && schema.rust_type == "hivemind_workflow::HumanApprovalRequestV1"
                && schema.readiness == "local"
        }));
        assert!(schemas.iter().any(|schema| {
            schema.command == "memory-write"
                && schema.rust_type == "hivemind_workflow::MemoryWriteV1"
                && schema.readiness == "local"
        }));
    }

    #[test]
    fn generated_docs_are_deterministic() {
        let first = GeneratedDocs::from_sources();
        let second = GeneratedDocs::from_sources();
        assert_eq!(first.api_routes_markdown, second.api_routes_markdown);
        assert_eq!(first.schemas_markdown, second.schemas_markdown);
    }
}
