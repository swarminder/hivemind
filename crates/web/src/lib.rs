use gloo_net::http::Request;
use hivemind_browser_runner::{
    assess_package, default_browser_capabilities, execute_manifest as execute_browser_manifest,
};
use hivemind_core::{
    ExecutionOptions, ExecutionPrivacy, ExecutionRequestV1, PackageManifestV1, RegistryEntryV1,
    RegistryQueryV1, RegistrySearchResponse, validate_package_manifest_value,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, HtmlTextAreaElement, InputEvent};
use yew::prelude::*;

#[derive(Debug, Clone, Deserialize)]
struct HealthResponse {
    status: String,
    #[serde(rename = "interfaceVersion")]
    interface_version: String,
    packages: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct BrowserSwarmStatusResponse {
    #[serde(rename = "activeProvider")]
    active_provider: String,
    cache: BrowserSwarmCacheResponse,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct BrowserSwarmCacheResponse {
    #[serde(rename = "entryCount")]
    entry_count: usize,
    #[serde(rename = "usedBytes")]
    used_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct MarketplaceListing {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    #[serde(rename = "listingId")]
    listing_id: String,
    #[serde(rename = "listingType")]
    listing_type: String,
    owner: String,
    #[serde(rename = "packageId")]
    package_id: String,
    #[serde(rename = "packageRef", default)]
    package_ref: Option<String>,
    title: String,
    pricing: MarketplacePricing,
    status: String,
    #[serde(rename = "requiresLicense")]
    requires_license: bool,
    #[serde(default)]
    signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct MarketplacePricing {
    mode: String,
    currency: String,
    #[serde(rename = "basePrice")]
    base_price: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct RunnerOffer {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    #[serde(rename = "offerId")]
    offer_id: String,
    #[serde(rename = "runnerId")]
    runner_id: String,
    #[serde(rename = "runnerType")]
    runner_type: String,
    #[serde(rename = "runnerDescriptorRef")]
    runner_descriptor_ref: String,
    #[serde(rename = "supportedPackageRefs")]
    supported_package_refs: Vec<String>,
    #[serde(rename = "supportedCapabilities")]
    supported_capabilities: Vec<String>,
    pricing: RunnerPricing,
    #[serde(rename = "serviceLevel")]
    service_level: RunnerServiceLevel,
    reputation: RunnerReputation,
    #[serde(default)]
    signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct RunnerPricing {
    #[serde(rename = "inputTokenPrice")]
    input_token_price: f64,
    #[serde(rename = "outputTokenPrice")]
    output_token_price: f64,
    currency: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct RunnerServiceLevel {
    #[serde(rename = "p95FirstTokenMs")]
    p95_first_token_ms: u64,
    #[serde(rename = "availabilityTarget")]
    availability_target: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct RunnerReputation {
    #[serde(rename = "validatorScore")]
    validator_score: f64,
    #[serde(rename = "completedJobs")]
    completed_jobs: u64,
}

#[wasm_bindgen(start)]
pub fn run() {
    yew::Renderer::<App>::new().render();
}

#[function_component(App)]
fn app() -> Html {
    let health = use_state(|| None::<HealthResponse>);
    let health_error = use_state(|| None::<String>);
    let browser_swarm = use_state(|| None::<BrowserSwarmStatusResponse>);
    let capability = use_state(|| "embedding".to_string());
    let search_status = use_state(|| "Ready".to_string());
    let results = use_state(Vec::<RegistryEntryV1>::new);
    let registry_detail = use_state(|| "Package details will appear here".to_string());
    let registry_shards = use_state(Vec::<Value>::new);
    let registry_shard_manifest = use_state(|| None::<Value>);
    let manifest_text = use_state(|| DEFAULT_MANIFEST.to_string());
    let validation_text = use_state(|| "Validation has not run".to_string());
    let run_input = use_state(|| "hello world".to_string());
    let run_output = use_state(|| "Run output will appear here".to_string());
    let marketplace_status = use_state(|| "Ready".to_string());
    let marketplace_listings = use_state(Vec::<MarketplaceListing>::new);
    let marketplace_offers = use_state(Vec::<RunnerOffer>::new);
    let marketplace_quote = use_state(|| None::<Value>);
    let marketplace_authorization = use_state(|| None::<Value>);
    let marketplace_settlement = use_state(|| None::<Value>);
    let marketplace_dispute = use_state(|| None::<Value>);
    let marketplace_resolution = use_state(|| None::<Value>);
    let marketplace_audit = use_state(|| None::<Value>);
    let marketplace_output = use_state(|| "Marketplace output will appear here".to_string());
    let execution_receipt = use_state(|| None::<Value>);
    let payer = use_state(|| "local-dev".to_string());
    let payee = use_state(|| "local-dev-runner".to_string());
    let resolver = use_state(|| "local-market".to_string());
    let dispute_reason = use_state(|| "output mismatch".to_string());

    {
        let health = health.clone();
        let health_error = health_error.clone();
        let browser_swarm = browser_swarm.clone();
        use_effect_with((), move |_| {
            spawn_local(async move {
                match Request::get("/health").send().await {
                    Ok(response) => match response.json::<HealthResponse>().await {
                        Ok(value) => health.set(Some(value)),
                        Err(error) => health_error.set(Some(error.to_string())),
                    },
                    Err(error) => health_error.set(Some(error.to_string())),
                }
                if let Ok(response) = Request::get("/v1/browser-swarm/status").send().await {
                    if let Ok(value) = response.json::<BrowserSwarmStatusResponse>().await {
                        browser_swarm.set(Some(value));
                    }
                }
            });
            || ()
        });
    }

    let on_capability_input = {
        let capability = capability.clone();
        Callback::from(move |event: InputEvent| {
            let input: HtmlInputElement = event.target_unchecked_into();
            capability.set(input.value());
        })
    };

    let on_manifest_input = {
        let manifest_text = manifest_text.clone();
        Callback::from(move |event: InputEvent| {
            let input: HtmlTextAreaElement = event.target_unchecked_into();
            manifest_text.set(input.value());
        })
    };

    let on_run_input = {
        let run_input = run_input.clone();
        Callback::from(move |event: InputEvent| {
            let input: HtmlInputElement = event.target_unchecked_into();
            run_input.set(input.value());
        })
    };

    let on_payer_input = {
        let payer = payer.clone();
        Callback::from(move |event: InputEvent| {
            let input: HtmlInputElement = event.target_unchecked_into();
            payer.set(input.value());
        })
    };

    let on_payee_input = {
        let payee = payee.clone();
        Callback::from(move |event: InputEvent| {
            let input: HtmlInputElement = event.target_unchecked_into();
            payee.set(input.value());
        })
    };

    let on_resolver_input = {
        let resolver = resolver.clone();
        Callback::from(move |event: InputEvent| {
            let input: HtmlInputElement = event.target_unchecked_into();
            resolver.set(input.value());
        })
    };

    let on_dispute_reason_input = {
        let dispute_reason = dispute_reason.clone();
        Callback::from(move |event: InputEvent| {
            let input: HtmlInputElement = event.target_unchecked_into();
            dispute_reason.set(input.value());
        })
    };

    let search = {
        let capability = capability.clone();
        let search_status = search_status.clone();
        let results = results.clone();
        Callback::from(move |_| {
            let capability = (*capability).clone();
            let search_status = search_status.clone();
            let results = results.clone();
            spawn_local(async move {
                search_status.set("Searching".to_string());
                let query = RegistryQueryV1 {
                    schema_version: "swarm-ai.registry.query.v1".to_string(),
                    kind: None,
                    capability: (!capability.trim().is_empty()).then_some(capability),
                    target: None,
                    engine: None,
                    license_type: None,
                    min_validator_score: None,
                    min_benchmark_score: None,
                    page_size: 20,
                    cursor: None,
                    requester: None,
                    requested_use: None,
                    runner_id: None,
                    access_grant: None,
                    access_revocation_list: None,
                };
                let request = Request::post("/v1/registry/search")
                    .header("Content-Type", "application/json")
                    .json(&query);
                let Ok(request) = request else {
                    search_status.set("Could not serialize query".to_string());
                    return;
                };
                match request.send().await {
                    Ok(response) => match response.json::<RegistrySearchResponse>().await {
                        Ok(payload) => {
                            search_status.set(format!("{} match(es)", payload.total_approx));
                            results.set(payload.entries);
                        }
                        Err(error) => search_status.set(error.to_string()),
                    },
                    Err(error) => search_status.set(error.to_string()),
                }
            });
        })
    };

    let load_registry_package = {
        let registry_detail = registry_detail.clone();
        Callback::from(move |package_id: String| {
            let registry_detail = registry_detail.clone();
            spawn_local(async move {
                registry_detail.set(format!("Loading {package_id}"));
                let request = json!({
                    "schemaVersion": "swarm-ai.registry.package-lookup.request.v1",
                    "packageId": package_id
                });
                let request_builder = Request::post("/v1/registry/package")
                    .header("Content-Type", "application/json")
                    .json(&request);
                let Ok(request_builder) = request_builder else {
                    registry_detail.set("Could not serialize package lookup".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => registry_detail.set(pretty_json(&value)),
                        Err(error) => registry_detail.set(error.to_string()),
                    },
                    Err(error) => registry_detail.set(error.to_string()),
                }
            });
        })
    };

    let load_registry_shards = {
        let search_status = search_status.clone();
        let registry_detail = registry_detail.clone();
        let registry_shards = registry_shards.clone();
        Callback::from(move |_| {
            let search_status = search_status.clone();
            let registry_detail = registry_detail.clone();
            let registry_shards = registry_shards.clone();
            spawn_local(async move {
                search_status.set("Loading shards".to_string());
                match fetch_registry_shards().await {
                    Ok(shards) => {
                        search_status.set(format!("{} shard(s)", shards.len()));
                        registry_detail.set(pretty_json(&json!({
                            "schemaVersion": "swarm-ai.registry.shard-load-result.v1",
                            "shardCount": shards.len(),
                            "shards": registry_shard_briefs(&shards)
                        })));
                        registry_shards.set(shards);
                    }
                    Err(error) => {
                        search_status.set("Shard load failed".to_string());
                        registry_detail.set(error);
                    }
                }
            });
        })
    };

    let load_registry_manifest = {
        let search_status = search_status.clone();
        let registry_detail = registry_detail.clone();
        let registry_shard_manifest = registry_shard_manifest.clone();
        Callback::from(move |_| {
            let search_status = search_status.clone();
            let registry_detail = registry_detail.clone();
            let registry_shard_manifest = registry_shard_manifest.clone();
            spawn_local(async move {
                search_status.set("Loading manifest".to_string());
                match fetch_registry_shard_manifest().await {
                    Ok(manifest) => {
                        let shard_count = manifest
                            .get("shardCount")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                        search_status.set(format!("{shard_count} manifest shard(s)"));
                        registry_detail.set(pretty_json(&manifest));
                        registry_shard_manifest.set(Some(manifest));
                    }
                    Err(error) => {
                        search_status.set("Manifest load failed".to_string());
                        registry_detail.set(error);
                    }
                }
            });
        })
    };

    let verify_registry_shards = {
        let search_status = search_status.clone();
        let registry_detail = registry_detail.clone();
        let registry_shards = registry_shards.clone();
        Callback::from(move |_| {
            let cached_shards = (*registry_shards).clone();
            let search_status = search_status.clone();
            let registry_detail = registry_detail.clone();
            let registry_shards = registry_shards.clone();
            spawn_local(async move {
                search_status.set("Verifying shards".to_string());
                let shards = if cached_shards.is_empty() {
                    match fetch_registry_shards().await {
                        Ok(shards) => {
                            registry_shards.set(shards.clone());
                            shards
                        }
                        Err(error) => {
                            search_status.set("Shard verify failed".to_string());
                            registry_detail.set(error);
                            return;
                        }
                    }
                } else {
                    cached_shards
                };
                let request = json!({
                    "schemaVersion": "swarm-ai.registry.shard-verification.request.v1",
                    "shardSource": "dashboard",
                    "shards": shards
                });
                let request_builder = Request::post("/v1/registry/shards/verify")
                    .header("Content-Type", "application/json")
                    .json(&request);
                let Ok(request_builder) = request_builder else {
                    search_status.set("Shard verify failed".to_string());
                    registry_detail
                        .set("Could not serialize shard verification request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let valid =
                                value.get("valid").and_then(Value::as_bool).unwrap_or(false);
                            let expected = value
                                .get("expectedShardCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let actual = value
                                .get("actualShardCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            search_status.set(if valid {
                                format!("{actual}/{expected} shard(s) verified")
                            } else {
                                format!("{actual}/{expected} shard(s) invalid")
                            });
                            registry_detail.set(pretty_json(&value));
                        }
                        Err(error) => {
                            search_status.set("Shard verify failed".to_string());
                            registry_detail.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        search_status.set("Shard verify failed".to_string());
                        registry_detail.set(error.to_string());
                    }
                }
            });
        })
    };

    let compare_registry_manifest = {
        let search_status = search_status.clone();
        let registry_detail = registry_detail.clone();
        let registry_shard_manifest = registry_shard_manifest.clone();
        Callback::from(move |_| {
            let cached_manifest = (*registry_shard_manifest).clone();
            let search_status = search_status.clone();
            let registry_detail = registry_detail.clone();
            let registry_shard_manifest = registry_shard_manifest.clone();
            spawn_local(async move {
                search_status.set("Comparing manifest".to_string());
                let manifest = if let Some(manifest) = cached_manifest {
                    manifest
                } else {
                    match fetch_registry_shard_manifest().await {
                        Ok(manifest) => {
                            registry_shard_manifest.set(Some(manifest.clone()));
                            manifest
                        }
                        Err(error) => {
                            search_status.set("Manifest compare failed".to_string());
                            registry_detail.set(error);
                            return;
                        }
                    }
                };
                let request = json!({
                    "schemaVersion": "swarm-ai.registry.shard-manifest-comparison.request.v1",
                    "shardSource": "dashboard",
                    "manifest": manifest
                });
                let request_builder = Request::post("/v1/registry/shards/manifest/compare")
                    .header("Content-Type", "application/json")
                    .json(&request);
                let Ok(request_builder) = request_builder else {
                    search_status.set("Manifest compare failed".to_string());
                    registry_detail
                        .set("Could not serialize manifest comparison request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let matches = value
                                .get("matches")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            let manifest_count = value
                                .get("manifestShardCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            search_status.set(if matches {
                                format!("{manifest_count} manifest shard(s) match")
                            } else {
                                format!("{manifest_count} manifest shard(s) differ")
                            });
                            registry_detail.set(pretty_json(&value));
                        }
                        Err(error) => {
                            search_status.set("Manifest compare failed".to_string());
                            registry_detail.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        search_status.set("Manifest compare failed".to_string());
                        registry_detail.set(error.to_string());
                    }
                }
            });
        })
    };

    let verify_registry_manifest = {
        let search_status = search_status.clone();
        let registry_detail = registry_detail.clone();
        let registry_shards = registry_shards.clone();
        let registry_shard_manifest = registry_shard_manifest.clone();
        Callback::from(move |_| {
            let cached_shards = (*registry_shards).clone();
            let cached_manifest = (*registry_shard_manifest).clone();
            let search_status = search_status.clone();
            let registry_detail = registry_detail.clone();
            let registry_shards = registry_shards.clone();
            let registry_shard_manifest = registry_shard_manifest.clone();
            spawn_local(async move {
                search_status.set("Verifying manifest".to_string());
                let manifest = if let Some(manifest) = cached_manifest {
                    manifest
                } else {
                    match fetch_registry_shard_manifest().await {
                        Ok(manifest) => {
                            registry_shard_manifest.set(Some(manifest.clone()));
                            manifest
                        }
                        Err(error) => {
                            search_status.set("Manifest verify failed".to_string());
                            registry_detail.set(error);
                            return;
                        }
                    }
                };
                let shards = if cached_shards.is_empty() {
                    match fetch_registry_shards().await {
                        Ok(shards) => {
                            registry_shards.set(shards.clone());
                            shards
                        }
                        Err(error) => {
                            search_status.set("Manifest verify failed".to_string());
                            registry_detail.set(error);
                            return;
                        }
                    }
                } else {
                    cached_shards
                };
                let request = json!({
                    "schemaVersion": "swarm-ai.registry.shard-manifest-verification.request.v1",
                    "shardSource": "dashboard",
                    "manifest": manifest,
                    "shards": shards
                });
                let request_builder = Request::post("/v1/registry/shards/manifest/verify")
                    .header("Content-Type", "application/json")
                    .json(&request);
                let Ok(request_builder) = request_builder else {
                    search_status.set("Manifest verify failed".to_string());
                    registry_detail
                        .set("Could not serialize manifest verification request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let valid =
                                value.get("valid").and_then(Value::as_bool).unwrap_or(false);
                            let manifest_count = value
                                .get("manifestShardCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let actual = value
                                .get("actualShardCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            search_status.set(if valid {
                                format!("{actual}/{manifest_count} manifest shard(s) verified")
                            } else {
                                format!("{actual}/{manifest_count} manifest shard(s) invalid")
                            });
                            registry_detail.set(pretty_json(&value));
                        }
                        Err(error) => {
                            search_status.set("Manifest verify failed".to_string());
                            registry_detail.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        search_status.set("Manifest verify failed".to_string());
                        registry_detail.set(error.to_string());
                    }
                }
            });
        })
    };

    let load_marketplace = {
        let marketplace_status = marketplace_status.clone();
        let marketplace_listings = marketplace_listings.clone();
        let marketplace_offers = marketplace_offers.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let marketplace_status = marketplace_status.clone();
            let marketplace_listings = marketplace_listings.clone();
            let marketplace_offers = marketplace_offers.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Loading".to_string());
                let listings = Request::get("/v1/marketplace/listings").send().await;
                let offers = Request::get("/v1/marketplace/offers").send().await;
                match (listings, offers) {
                    (Ok(listings), Ok(offers)) => {
                        let listings = listings.json::<Vec<MarketplaceListing>>().await;
                        let offers = offers.json::<Vec<RunnerOffer>>().await;
                        match (listings, offers) {
                            (Ok(listings), Ok(offers)) => {
                                marketplace_status.set(format!(
                                    "{} listing(s), {} offer(s)",
                                    listings.len(),
                                    offers.len()
                                ));
                                marketplace_listings.set(listings);
                                marketplace_offers.set(offers);
                                marketplace_output.set("Marketplace loaded".to_string());
                            }
                            (Err(error), _) | (_, Err(error)) => {
                                marketplace_status.set("Load failed".to_string());
                                marketplace_output.set(error.to_string());
                            }
                        }
                    }
                    (Err(error), _) | (_, Err(error)) => {
                        marketplace_status.set("Load failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let verify_marketplace_listing = {
        let marketplace_listings = marketplace_listings.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let Some(listing) = marketplace_listings.first().cloned() else {
                marketplace_status.set("No listing".to_string());
                marketplace_output.set("Load marketplace listings before verification".to_string());
                return;
            };
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Verifying listing".to_string());
                let request_builder = Request::post("/v1/marketplace/verify-listing")
                    .header("Content-Type", "application/json")
                    .json(&listing);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Listing verification failed".to_string());
                    marketplace_output.set("Could not serialize listing".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let valid =
                                value.get("valid").and_then(Value::as_bool).unwrap_or(false);
                            marketplace_status.set(if valid {
                                "Listing verified".to_string()
                            } else {
                                "Listing invalid".to_string()
                            });
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Listing verification failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Listing verification failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let verify_marketplace_offer = {
        let marketplace_offers = marketplace_offers.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let Some(offer) = marketplace_offers.first().cloned() else {
                marketplace_status.set("No offer".to_string());
                marketplace_output.set("Load marketplace offers before verification".to_string());
                return;
            };
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Verifying offer".to_string());
                let request_builder = Request::post("/v1/marketplace/verify-offer")
                    .header("Content-Type", "application/json")
                    .json(&offer);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Offer verification failed".to_string());
                    marketplace_output.set("Could not serialize offer".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let valid =
                                value.get("valid").and_then(Value::as_bool).unwrap_or(false);
                            marketplace_status.set(if valid {
                                "Offer verified".to_string()
                            } else {
                                "Offer invalid".to_string()
                            });
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Offer verification failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Offer verification failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let quote_marketplace = {
        let results = results.clone();
        let run_input = run_input.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_quote = marketplace_quote.clone();
        let marketplace_authorization = marketplace_authorization.clone();
        let marketplace_settlement = marketplace_settlement.clone();
        let marketplace_dispute = marketplace_dispute.clone();
        let marketplace_resolution = marketplace_resolution.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let Some(entry) = results.first().cloned() else {
                marketplace_status.set("No package".to_string());
                marketplace_output.set("Search for a package before quoting".to_string());
                return;
            };
            let Some(pointer) = entry.package_refs.first().cloned() else {
                marketplace_status.set("No package ref".to_string());
                marketplace_output.set("Selected package has no packageRef".to_string());
                return;
            };
            let request = ExecutionRequestV1 {
                schema_version: "swarm-ai.execution.request.v1".to_string(),
                request_id: "web-dev-request".to_string(),
                package_ref: pointer.package_ref,
                package_id: entry.package_id,
                package_version: entry.latest_version,
                preferred_artifact_group: None,
                task: "embedding".to_string(),
                input: json!({ "text": (*run_input).clone() }),
                options: ExecutionOptions::default(),
                privacy: ExecutionPrivacy::default(),
                access_grant: None,
                access_revocation_list: None,
            };
            let marketplace_status = marketplace_status.clone();
            let marketplace_quote = marketplace_quote.clone();
            let marketplace_authorization = marketplace_authorization.clone();
            let marketplace_settlement = marketplace_settlement.clone();
            let marketplace_dispute = marketplace_dispute.clone();
            let marketplace_resolution = marketplace_resolution.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Quoting".to_string());
                let request_builder = Request::post("/v1/marketplace/quote")
                    .header("Content-Type", "application/json")
                    .json(&request);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Quote failed".to_string());
                    marketplace_output.set("Could not serialize quote request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            marketplace_status.set("Quote ready".to_string());
                            marketplace_quote.set(Some(value.clone()));
                            marketplace_authorization.set(None);
                            marketplace_settlement.set(None);
                            marketplace_dispute.set(None);
                            marketplace_resolution.set(None);
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Quote failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Quote failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let shortlist_marketplace = {
        let results = results.clone();
        let run_input = run_input.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let Some(entry) = results.first().cloned() else {
                marketplace_status.set("No package".to_string());
                marketplace_output.set("Search for a package before shortlisting".to_string());
                return;
            };
            let Some(pointer) = entry.package_refs.first().cloned() else {
                marketplace_status.set("No package ref".to_string());
                marketplace_output.set("Selected package has no packageRef".to_string());
                return;
            };
            let token_estimate = (*run_input).split_whitespace().count().max(1) as u64;
            let body = json!({
                "schemaVersion": "swarm-ai.marketplace-shortlist-request.v1",
                "packageRef": pointer.package_ref,
                "task": "embedding",
                "estimatedInputTokens": token_estimate,
                "estimatedOutputTokens": token_estimate,
                "policyMode": "balanced",
                "maxResults": 5,
                "includeRejected": true
            });
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Shortlisting".to_string());
                let request_builder = Request::post("/v1/marketplace/shortlist")
                    .header("Content-Type", "application/json")
                    .json(&body);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Shortlist failed".to_string());
                    marketplace_output.set("Could not serialize shortlist request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let count = value
                                .get("rankings")
                                .and_then(Value::as_array)
                                .map(Vec::len)
                                .unwrap_or(0);
                            marketplace_status.set(format!("{count} ranked offer(s)"));
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Shortlist failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Shortlist failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let verify_marketplace_quote = {
        let marketplace_quote = marketplace_quote.clone();
        let marketplace_offers = marketplace_offers.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let Some(quote) = (*marketplace_quote).clone() else {
                marketplace_status.set("No quote".to_string());
                marketplace_output.set("Create a quote before verification".to_string());
                return;
            };
            let quote_offer_id = quote
                .get("offerId")
                .and_then(Value::as_str)
                .map(str::to_string);
            let matching_offer = marketplace_offers
                .iter()
                .find(|offer| Some(offer.offer_id.as_str()) == quote_offer_id.as_deref())
                .cloned();
            let body = if let Some(offer) = matching_offer {
                json!({
                    "quote": quote,
                    "offer": offer
                })
            } else {
                json!({
                    "quote": quote
                })
            };
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Verifying quote".to_string());
                let request_builder = Request::post("/v1/marketplace/verify-quote")
                    .header("Content-Type", "application/json")
                    .json(&body);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Quote verification failed".to_string());
                    marketplace_output.set("Could not serialize quote verification".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let valid =
                                value.get("valid").and_then(Value::as_bool).unwrap_or(false);
                            marketplace_status.set(if valid {
                                "Quote verified".to_string()
                            } else {
                                "Quote invalid".to_string()
                            });
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Quote verification failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Quote verification failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let authorize_marketplace_payment = {
        let marketplace_quote = marketplace_quote.clone();
        let marketplace_authorization = marketplace_authorization.clone();
        let marketplace_settlement = marketplace_settlement.clone();
        let marketplace_dispute = marketplace_dispute.clone();
        let marketplace_resolution = marketplace_resolution.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        let payer = payer.clone();
        let payee = payee.clone();
        Callback::from(move |_| {
            let Some(quote) = (*marketplace_quote).clone() else {
                marketplace_status.set("No quote".to_string());
                marketplace_output.set("Create a quote before authorizing payment".to_string());
                return;
            };
            let quote_id = quote
                .get("quoteId")
                .and_then(Value::as_str)
                .unwrap_or("web-quote");
            let body = json!({
                "quote": quote,
                "payer": (*payer).clone(),
                "payee": (*payee).clone(),
                "adapter": "local-dev",
                "paymentRef": format!("local://web-payment/{quote_id}")
            });
            let marketplace_authorization = marketplace_authorization.clone();
            let marketplace_settlement = marketplace_settlement.clone();
            let marketplace_dispute = marketplace_dispute.clone();
            let marketplace_resolution = marketplace_resolution.clone();
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Authorizing".to_string());
                let request_builder = Request::post("/v1/marketplace/authorize-payment")
                    .header("Content-Type", "application/json")
                    .json(&body);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Authorization failed".to_string());
                    marketplace_output.set("Could not serialize payment request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let authorization = value.get("authorization").cloned();
                            marketplace_authorization.set(authorization);
                            marketplace_settlement.set(None);
                            marketplace_dispute.set(None);
                            marketplace_resolution.set(None);
                            marketplace_status.set("Authorized".to_string());
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Authorization failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Authorization failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let verify_marketplace_payment = {
        let marketplace_quote = marketplace_quote.clone();
        let marketplace_authorization = marketplace_authorization.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let Some(quote) = (*marketplace_quote).clone() else {
                marketplace_status.set("No quote".to_string());
                marketplace_output.set("Create a quote before verifying payment".to_string());
                return;
            };
            let Some(authorization) = (*marketplace_authorization).clone() else {
                marketplace_status.set("No authorization".to_string());
                marketplace_output.set("Authorize payment before running verification".to_string());
                return;
            };
            let body = json!({
                "authorization": authorization,
                "quote": quote
            });
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Verifying".to_string());
                let request_builder = Request::post("/v1/marketplace/verify-payment")
                    .header("Content-Type", "application/json")
                    .json(&body);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Verification failed".to_string());
                    marketplace_output.set("Could not serialize verification request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let valid =
                                value.get("valid").and_then(Value::as_bool).unwrap_or(false);
                            marketplace_status.set(if valid {
                                "Payment verified".to_string()
                            } else {
                                "Payment invalid".to_string()
                            });
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Verification failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Verification failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let settle_marketplace = {
        let execution_receipt = execution_receipt.clone();
        let marketplace_quote = marketplace_quote.clone();
        let marketplace_authorization = marketplace_authorization.clone();
        let marketplace_settlement = marketplace_settlement.clone();
        let marketplace_dispute = marketplace_dispute.clone();
        let marketplace_resolution = marketplace_resolution.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        let payer = payer.clone();
        let payee = payee.clone();
        Callback::from(move |_| {
            let Some(receipt) = (*execution_receipt).clone() else {
                marketplace_status.set("No receipt".to_string());
                marketplace_output.set("Run API before creating a settlement".to_string());
                return;
            };
            let Some(quote) = (*marketplace_quote).clone() else {
                marketplace_status.set("No quote".to_string());
                marketplace_output.set("Create a quote before creating a settlement".to_string());
                return;
            };
            let receipt_id = receipt
                .get("receiptId")
                .and_then(Value::as_str)
                .unwrap_or("web-receipt");
            let body = json!({
                "receipt": receipt,
                "quote": quote,
                "paymentAuthorization": (*marketplace_authorization).clone(),
                "payer": (*payer).clone(),
                "payee": (*payee).clone(),
                "receiptRef": format!("local://web-receipt/{receipt_id}")
            });
            let marketplace_settlement = marketplace_settlement.clone();
            let marketplace_dispute = marketplace_dispute.clone();
            let marketplace_resolution = marketplace_resolution.clone();
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Settling".to_string());
                let request_builder = Request::post("/v1/marketplace/settle")
                    .header("Content-Type", "application/json")
                    .json(&body);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Settlement failed".to_string());
                    marketplace_output.set("Could not serialize settlement request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let settlement = value.get("settlement").cloned();
                            marketplace_settlement.set(settlement);
                            marketplace_dispute.set(None);
                            marketplace_resolution.set(None);
                            let valid = value
                                .get("verification")
                                .and_then(|verification| verification.get("valid"))
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            marketplace_status.set(if valid {
                                "Settlement ready".to_string()
                            } else {
                                "Settlement invalid".to_string()
                            });
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Settlement failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Settlement failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let verify_marketplace_settlement = {
        let marketplace_settlement = marketplace_settlement.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let Some(settlement) = (*marketplace_settlement).clone() else {
                marketplace_status.set("No settlement".to_string());
                marketplace_output.set("Create a settlement before verification".to_string());
                return;
            };
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Verifying settlement".to_string());
                let request_builder = Request::post("/v1/marketplace/verify-settlement")
                    .header("Content-Type", "application/json")
                    .json(&settlement);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Settlement verification failed".to_string());
                    marketplace_output.set("Could not serialize settlement".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let valid =
                                value.get("valid").and_then(Value::as_bool).unwrap_or(false);
                            marketplace_status.set(if valid {
                                "Settlement verified".to_string()
                            } else {
                                "Settlement invalid".to_string()
                            });
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Settlement verification failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Settlement verification failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let create_marketplace_dispute = {
        let execution_receipt = execution_receipt.clone();
        let marketplace_dispute = marketplace_dispute.clone();
        let marketplace_resolution = marketplace_resolution.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        let payer = payer.clone();
        let dispute_reason = dispute_reason.clone();
        Callback::from(move |_| {
            let Some(receipt) = (*execution_receipt).clone() else {
                marketplace_status.set("No receipt".to_string());
                marketplace_output.set("Run API before creating dispute evidence".to_string());
                return;
            };
            let body = json!({
                "receipt": receipt,
                "claimant": (*payer).clone(),
                "claimKind": "output-mismatch",
                "summary": (*dispute_reason).clone(),
                "evidenceRefs": []
            });
            let marketplace_dispute = marketplace_dispute.clone();
            let marketplace_resolution = marketplace_resolution.clone();
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Creating dispute".to_string());
                let request_builder = Request::post("/v1/receipts/dispute")
                    .header("Content-Type", "application/json")
                    .json(&body);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Dispute failed".to_string());
                    marketplace_output.set("Could not serialize dispute request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            marketplace_dispute.set(value.get("evidence").cloned());
                            marketplace_resolution.set(None);
                            let valid = value
                                .get("verification")
                                .and_then(|verification| verification.get("valid"))
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            marketplace_status.set(if valid {
                                "Dispute evidence ready".to_string()
                            } else {
                                "Dispute evidence invalid".to_string()
                            });
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Dispute failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Dispute failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let dispute_marketplace_settlement = {
        let marketplace_settlement = marketplace_settlement.clone();
        let marketplace_dispute = marketplace_dispute.clone();
        let marketplace_resolution = marketplace_resolution.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        let resolver = resolver.clone();
        let dispute_reason = dispute_reason.clone();
        Callback::from(move |_| {
            let Some(settlement) = (*marketplace_settlement).clone() else {
                marketplace_status.set("No settlement".to_string());
                marketplace_output.set("Create a settlement before opening a dispute".to_string());
                return;
            };
            let Some(dispute) = (*marketplace_dispute).clone() else {
                marketplace_status.set("No dispute".to_string());
                marketplace_output
                    .set("Create dispute evidence before opening a dispute".to_string());
                return;
            };
            let body = json!({
                "settlement": settlement,
                "dispute": dispute,
                "resolvedBy": (*resolver).clone(),
                "reason": (*dispute_reason).clone()
            });
            let marketplace_settlement = marketplace_settlement.clone();
            let marketplace_resolution = marketplace_resolution.clone();
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Opening dispute".to_string());
                let request_builder = Request::post("/v1/marketplace/dispute-settlement")
                    .header("Content-Type", "application/json")
                    .json(&body);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Dispute open failed".to_string());
                    marketplace_output.set("Could not serialize dispute settlement".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            if let Some(updated) = value.get("updatedSettlement").cloned() {
                                marketplace_settlement.set(Some(updated));
                            }
                            marketplace_resolution.set(value.get("resolution").cloned());
                            let valid = value
                                .get("verification")
                                .and_then(|verification| verification.get("valid"))
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            marketplace_status.set(if valid {
                                "Settlement disputed".to_string()
                            } else {
                                "Dispute invalid".to_string()
                            });
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Dispute open failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Dispute open failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let refund_marketplace_settlement = {
        let marketplace_settlement = marketplace_settlement.clone();
        let marketplace_dispute = marketplace_dispute.clone();
        let marketplace_resolution = marketplace_resolution.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        let resolver = resolver.clone();
        Callback::from(move |_| {
            let Some(settlement) = (*marketplace_settlement).clone() else {
                marketplace_status.set("No settlement".to_string());
                marketplace_output.set("Open a dispute before approving a refund".to_string());
                return;
            };
            let Some(dispute) = (*marketplace_dispute).clone() else {
                marketplace_status.set("No dispute".to_string());
                marketplace_output
                    .set("Create dispute evidence before approving a refund".to_string());
                return;
            };
            let body = json!({
                "settlement": settlement,
                "dispute": dispute,
                "resolvedBy": (*resolver).clone(),
                "reason": "refund approved"
            });
            let marketplace_settlement = marketplace_settlement.clone();
            let marketplace_resolution = marketplace_resolution.clone();
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Refunding".to_string());
                let request_builder = Request::post("/v1/marketplace/refund-settlement")
                    .header("Content-Type", "application/json")
                    .json(&body);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Refund failed".to_string());
                    marketplace_output.set("Could not serialize refund request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            if let Some(updated) = value.get("updatedSettlement").cloned() {
                                marketplace_settlement.set(Some(updated));
                            }
                            marketplace_resolution.set(value.get("resolution").cloned());
                            let valid = value
                                .get("verification")
                                .and_then(|verification| verification.get("valid"))
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            marketplace_status.set(if valid {
                                "Settlement refunded".to_string()
                            } else {
                                "Refund invalid".to_string()
                            });
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Refund failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Refund failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let reject_marketplace_dispute = {
        let marketplace_settlement = marketplace_settlement.clone();
        let marketplace_dispute = marketplace_dispute.clone();
        let marketplace_resolution = marketplace_resolution.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        let resolver = resolver.clone();
        Callback::from(move |_| {
            let Some(settlement) = (*marketplace_settlement).clone() else {
                marketplace_status.set("No settlement".to_string());
                marketplace_output.set("Open a dispute before rejecting it".to_string());
                return;
            };
            let Some(dispute) = (*marketplace_dispute).clone() else {
                marketplace_status.set("No dispute".to_string());
                marketplace_output
                    .set("Create dispute evidence before rejecting a dispute".to_string());
                return;
            };
            let body = json!({
                "settlement": settlement,
                "dispute": dispute,
                "resolvedBy": (*resolver).clone(),
                "reason": "dispute rejected"
            });
            let marketplace_settlement = marketplace_settlement.clone();
            let marketplace_resolution = marketplace_resolution.clone();
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Rejecting dispute".to_string());
                let request_builder = Request::post("/v1/marketplace/reject-dispute")
                    .header("Content-Type", "application/json")
                    .json(&body);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Reject failed".to_string());
                    marketplace_output.set("Could not serialize reject request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            if let Some(updated) = value.get("updatedSettlement").cloned() {
                                marketplace_settlement.set(Some(updated));
                            }
                            marketplace_resolution.set(value.get("resolution").cloned());
                            let valid = value
                                .get("verification")
                                .and_then(|verification| verification.get("valid"))
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            marketplace_status.set(if valid {
                                "Dispute rejected".to_string()
                            } else {
                                "Reject invalid".to_string()
                            });
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Reject failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Reject failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let verify_marketplace_resolution = {
        let marketplace_resolution = marketplace_resolution.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let Some(resolution) = (*marketplace_resolution).clone() else {
                marketplace_status.set("No resolution".to_string());
                marketplace_output
                    .set("Open a dispute or refund before resolution verification".to_string());
                return;
            };
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Verifying resolution".to_string());
                let request_builder = Request::post("/v1/marketplace/verify-resolution")
                    .header("Content-Type", "application/json")
                    .json(&resolution);
                let Ok(request_builder) = request_builder else {
                    marketplace_status.set("Resolution verification failed".to_string());
                    marketplace_output.set("Could not serialize resolution".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let valid =
                                value.get("valid").and_then(Value::as_bool).unwrap_or(false);
                            marketplace_status.set(if valid {
                                "Resolution verified".to_string()
                            } else {
                                "Resolution invalid".to_string()
                            });
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Resolution verification failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Resolution verification failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let load_marketplace_audit = {
        let marketplace_audit = marketplace_audit.clone();
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let marketplace_audit = marketplace_audit.clone();
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Loading audit".to_string());
                match Request::get("/v1/marketplace/audit").send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let settlements = value
                                .get("settlementCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let resolutions = value
                                .get("resolutionCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            marketplace_status.set(format!(
                                "{settlements} settlement(s), {resolutions} resolution(s)"
                            ));
                            marketplace_audit.set(Some(value.clone()));
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Audit load failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Audit load failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let load_dispute_audit = {
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Loading disputes".to_string());
                match Request::get("/v1/receipts/disputes").send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let disputes = value
                                .get("disputeCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let valid =
                                value.get("validCount").and_then(Value::as_u64).unwrap_or(0);
                            marketplace_status
                                .set(format!("{valid}/{disputes} dispute evidence record(s)"));
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Dispute audit failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Dispute audit failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let load_marketplace_payments = {
        let marketplace_status = marketplace_status.clone();
        let marketplace_output = marketplace_output.clone();
        Callback::from(move |_| {
            let marketplace_status = marketplace_status.clone();
            let marketplace_output = marketplace_output.clone();
            spawn_local(async move {
                marketplace_status.set("Loading payments".to_string());
                match Request::get("/v1/marketplace/payments").send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let authorizations = value
                                .get("authorizationCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let valid =
                                value.get("validCount").and_then(Value::as_u64).unwrap_or(0);
                            marketplace_status
                                .set(format!("{valid}/{authorizations} payment authorization(s)"));
                            marketplace_output.set(pretty_json(&value));
                        }
                        Err(error) => {
                            marketplace_status.set("Payment audit failed".to_string());
                            marketplace_output.set(error.to_string());
                        }
                    },
                    Err(error) => {
                        marketplace_status.set("Payment audit failed".to_string());
                        marketplace_output.set(error.to_string());
                    }
                }
            });
        })
    };

    let validate = {
        let manifest_text = manifest_text.clone();
        let validation_text = validation_text.clone();
        Callback::from(
            move |_| match serde_json::from_str::<Value>(&manifest_text) {
                Ok(value) => {
                    let report = validate_package_manifest_value(&value);
                    let text = serde_json::to_string_pretty(&report)
                        .unwrap_or_else(|error| error.to_string());
                    validation_text.set(text);
                }
                Err(error) => validation_text.set(format!("JSON parse error: {error}")),
            },
        )
    };

    let load_publication_records = {
        let validation_text = validation_text.clone();
        Callback::from(move |_| {
            let validation_text = validation_text.clone();
            spawn_local(async move {
                validation_text.set("Loading publication records".to_string());
                match Request::get("/v1/publisher/publications").send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let publications = value
                                .get("publicationCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let valid =
                                value.get("validCount").and_then(Value::as_u64).unwrap_or(0);
                            validation_text.set(format!(
                                "{valid}/{publications} publication record(s)\n{}",
                                pretty_json(&value)
                            ));
                        }
                        Err(error) => validation_text.set(error.to_string()),
                    },
                    Err(error) => validation_text.set(error.to_string()),
                }
            });
        })
    };

    let load_feed_pointers = {
        let validation_text = validation_text.clone();
        Callback::from(move |_| {
            let validation_text = validation_text.clone();
            spawn_local(async move {
                validation_text.set("Loading publisher feeds".to_string());
                match Request::get("/v1/publisher/feeds").send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let feeds = value.get("feedCount").and_then(Value::as_u64).unwrap_or(0);
                            let valid =
                                value.get("validCount").and_then(Value::as_u64).unwrap_or(0);
                            validation_text.set(format!(
                                "{valid}/{feeds} publisher feed pointer(s)\n{}",
                                pretty_json(&value)
                            ));
                        }
                        Err(error) => validation_text.set(error.to_string()),
                    },
                    Err(error) => validation_text.set(error.to_string()),
                }
            });
        })
    };

    let load_validation_reports = {
        let validation_text = validation_text.clone();
        Callback::from(move |_| {
            let validation_text = validation_text.clone();
            spawn_local(async move {
                validation_text.set("Loading validation reports".to_string());
                match Request::get("/v1/validator/reports").send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let reports = value
                                .get("reportCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let valid =
                                value.get("validCount").and_then(Value::as_u64).unwrap_or(0);
                            validation_text.set(format!(
                                "{valid}/{reports} validation report(s)\n{}",
                                pretty_json(&value)
                            ));
                        }
                        Err(error) => validation_text.set(error.to_string()),
                    },
                    Err(error) => validation_text.set(error.to_string()),
                }
            });
        })
    };

    let load_evaluation_results = {
        let validation_text = validation_text.clone();
        Callback::from(move |_| {
            let validation_text = validation_text.clone();
            spawn_local(async move {
                validation_text.set("Loading benchmark evaluations".to_string());
                match Request::get("/v1/benchmarks/evaluations").send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let evaluations = value
                                .get("evaluationCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            let valid =
                                value.get("validCount").and_then(Value::as_u64).unwrap_or(0);
                            validation_text.set(format!(
                                "{valid}/{evaluations} benchmark evaluation(s)\n{}",
                                pretty_json(&value)
                            ));
                        }
                        Err(error) => validation_text.set(error.to_string()),
                    },
                    Err(error) => validation_text.set(error.to_string()),
                }
            });
        })
    };

    let load_access_audit = {
        let validation_text = validation_text.clone();
        Callback::from(move |_| {
            let validation_text = validation_text.clone();
            spawn_local(async move {
                validation_text.set("Loading access audit".to_string());
                let grants = Request::get("/v1/access/grants").send().await;
                let revocations = Request::get("/v1/access/revocations").send().await;
                match (grants, revocations) {
                    (Ok(grants_response), Ok(revocations_response)) => {
                        match (
                            grants_response.json::<Value>().await,
                            revocations_response.json::<Value>().await,
                        ) {
                            (Ok(grants), Ok(revocations)) => {
                                let grant_count = grants
                                    .get("grantCount")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0);
                                let valid_grants = grants
                                    .get("validCount")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0);
                                let revocation_count = revocations
                                    .get("revocationCount")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0);
                                let valid_revocations = revocations
                                    .get("validCount")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0);
                                validation_text.set(format!(
                                    "{valid_grants}/{grant_count} access grant(s), {valid_revocations}/{revocation_count} revocation(s)\n{}\n{}",
                                    pretty_json(&grants),
                                    pretty_json(&revocations)
                                ));
                            }
                            (Err(error), _) | (_, Err(error)) => {
                                validation_text.set(error.to_string());
                            }
                        }
                    }
                    (Err(error), _) | (_, Err(error)) => {
                        validation_text.set(error.to_string());
                    }
                }
            });
        })
    };

    let load_storage_cache = {
        let validation_text = validation_text.clone();
        Callback::from(move |_| {
            let validation_text = validation_text.clone();
            spawn_local(async move {
                validation_text.set("Loading storage cache".to_string());
                let status = Request::get("/v1/storage/status").send().await;
                let cache = Request::get("/v1/storage/cache").send().await;
                match (status, cache) {
                    (Ok(status_response), Ok(cache_response)) => {
                        match (
                            status_response.json::<Value>().await,
                            cache_response.json::<Value>().await,
                        ) {
                            (Ok(status), Ok(cache)) => {
                                let objects = cache
                                    .get("objectCount")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0);
                                let manifests = cache
                                    .get("manifestCount")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0);
                                let bytes = cache
                                    .get("totalObjectBytes")
                                    .and_then(Value::as_u64)
                                    .unwrap_or(0);
                                validation_text.set(format!(
                                    "{objects} object(s), {manifests} manifest(s), {bytes} cached byte(s)\n{}\n{}",
                                    pretty_json(&status),
                                    pretty_json(&cache)
                                ));
                            }
                            (Err(error), _) | (_, Err(error)) => {
                                validation_text.set(error.to_string());
                            }
                        }
                    }
                    (Err(error), _) | (_, Err(error)) => {
                        validation_text.set(error.to_string());
                    }
                }
            });
        })
    };

    let run = {
        let results = results.clone();
        let run_input = run_input.clone();
        let run_output = run_output.clone();
        let execution_receipt = execution_receipt.clone();
        Callback::from(move |_| {
            let Some(entry) = results.first().cloned() else {
                run_output.set("Search returned no runnable package".to_string());
                return;
            };
            let Some(pointer) = entry.package_refs.first().cloned() else {
                run_output.set("Selected package has no packageRef".to_string());
                return;
            };
            let preferred = entry
                .targets
                .iter()
                .position(|target| target == "local-mock" || target == "browser-wasm")
                .and_then(|_| Some("local-rust-mock".to_string()));
            let request = ExecutionRequestV1 {
                schema_version: "swarm-ai.execution.request.v1".to_string(),
                request_id: "web-dev-request".to_string(),
                package_ref: pointer.package_ref,
                package_id: entry.package_id,
                package_version: entry.latest_version,
                preferred_artifact_group: preferred,
                task: "embedding".to_string(),
                input: json!({ "text": (*run_input).clone() }),
                options: ExecutionOptions::default(),
                privacy: ExecutionPrivacy::default(),
                access_grant: None,
                access_revocation_list: None,
            };
            let run_output = run_output.clone();
            let execution_receipt = execution_receipt.clone();
            spawn_local(async move {
                let request_builder = Request::post("/v1/swarm-ai/execute")
                    .header("Content-Type", "application/json")
                    .json(&request);
                let Ok(request_builder) = request_builder else {
                    run_output.set("Could not serialize execution request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => {
                            let receipt = value
                                .get("metadata")
                                .and_then(|metadata| metadata.get("receipt"))
                                .cloned();
                            execution_receipt.set(receipt);
                            run_output.set(
                                serde_json::to_string_pretty(&value)
                                    .unwrap_or_else(|error| error.to_string()),
                            );
                        }
                        Err(error) => run_output.set(error.to_string()),
                    },
                    Err(error) => run_output.set(error.to_string()),
                }
            });
        })
    };

    let route = {
        let results = results.clone();
        let run_input = run_input.clone();
        let run_output = run_output.clone();
        Callback::from(move |_| {
            let Some(entry) = results.first().cloned() else {
                run_output.set("Search returned no routable package".to_string());
                return;
            };
            let Some(pointer) = entry.package_refs.first().cloned() else {
                run_output.set("Selected package has no packageRef".to_string());
                return;
            };
            let request = ExecutionRequestV1 {
                schema_version: "swarm-ai.execution.request.v1".to_string(),
                request_id: "web-route-request".to_string(),
                package_ref: pointer.package_ref,
                package_id: entry.package_id,
                package_version: entry.latest_version,
                preferred_artifact_group: None,
                task: "embedding".to_string(),
                input: json!({ "text": (*run_input).clone() }),
                options: ExecutionOptions::default(),
                privacy: ExecutionPrivacy::default(),
                access_grant: None,
                access_revocation_list: None,
            };
            let run_output = run_output.clone();
            spawn_local(async move {
                let request_builder = Request::post("/v1/swarm-ai/route-report")
                    .header("Content-Type", "application/json")
                    .json(&request);
                let Ok(request_builder) = request_builder else {
                    run_output.set("Could not serialize route request".to_string());
                    return;
                };
                match request_builder.send().await {
                    Ok(response) => match response.json::<Value>().await {
                        Ok(value) => run_output.set(
                            serde_json::to_string_pretty(&value)
                                .unwrap_or_else(|error| error.to_string()),
                        ),
                        Err(error) => run_output.set(error.to_string()),
                    },
                    Err(error) => run_output.set(error.to_string()),
                }
            });
        })
    };

    let run_browser = {
        let manifest_text = manifest_text.clone();
        let run_input = run_input.clone();
        let run_output = run_output.clone();
        let execution_receipt = execution_receipt.clone();
        Callback::from(
            move |_| match serde_json::from_str::<PackageManifestV1>(&manifest_text) {
                Ok(manifest) => {
                    let capabilities = default_browser_capabilities();
                    let assessment = assess_package(&manifest, &capabilities, None);
                    if !assessment.can_run {
                        let text = serde_json::to_string_pretty(&assessment)
                            .unwrap_or_else(|error| error.to_string());
                        run_output.set(text);
                        return;
                    }
                    let package_ref = format!("local://web-manifest/{}", manifest.package_id);
                    let request = ExecutionRequestV1 {
                        schema_version: "swarm-ai.execution.request.v1".to_string(),
                        request_id: "web-browser-request".to_string(),
                        package_ref: package_ref.clone(),
                        package_id: manifest.package_id.clone(),
                        package_version: manifest.version.clone(),
                        preferred_artifact_group: assessment.artifact_group.clone(),
                        task: "embedding".to_string(),
                        input: json!({ "text": (*run_input).clone() }),
                        options: ExecutionOptions::default(),
                        privacy: ExecutionPrivacy::default(),
                        access_grant: None,
                        access_revocation_list: None,
                    };
                    let response =
                        execute_browser_manifest(&manifest, package_ref, request, &capabilities);
                    execution_receipt.set(response.metadata.get("receipt").cloned());
                    let text = serde_json::to_string_pretty(&json!({
                        "assessment": assessment,
                        "response": response
                    }))
                    .unwrap_or_else(|error| error.to_string());
                    run_output.set(text);
                }
                Err(error) => run_output.set(format!("Manifest JSON parse error: {error}")),
            },
        )
    };

    let health_label = health
        .as_ref()
        .map(|value| {
            let browser_swarm_label = browser_swarm
                .as_ref()
                .map(|status| {
                    let warning_count = status.warnings.len();
                    format!(
                        " | storage {} | cache {} item(s), {} byte(s) | {} warning(s)",
                        status.active_provider,
                        status.cache.entry_count,
                        status.cache.used_bytes,
                        warning_count
                    )
                })
                .unwrap_or_default();
            format!(
                "{} | interface {} | {} package(s)",
                value.status, value.interface_version, value.packages
            ) + &browser_swarm_label
        })
        .or_else(|| {
            health_error
                .as_ref()
                .map(|error| format!("API error: {error}"))
        })
        .unwrap_or_else(|| "Connecting".to_string());

    html! {
        <main class="app-shell">
            <header class="topbar">
                <div>
                    <h1>{"Hivemind"}</h1>
                    <p>{health_label}</p>
                </div>
                <button type="button" onclick={search.clone()}>{"Search"}</button>
            </header>

            <section class="workspace">
                <section class="panel registry-panel">
                    <div class="panel-header">
                        <h2>{"Registry"}</h2>
                        <div class="registry-actions">
                            <span>{(*search_status).clone()}</span>
                            <button type="button" onclick={load_registry_shards}>{"Shards"}</button>
                            <button type="button" onclick={load_registry_manifest}>{"Manifest"}</button>
                            <button type="button" onclick={compare_registry_manifest}>{"Compare Manifest"}</button>
                            <button type="button" onclick={verify_registry_shards}>{"Verify Shards"}</button>
                            <button type="button" onclick={verify_registry_manifest}>{"Verify Manifest"}</button>
                        </div>
                    </div>
                    <label class="field">
                        <span>{"Capability"}</span>
                        <input value={(*capability).clone()} oninput={on_capability_input} />
                    </label>
                    <div class="package-list">
                        { for results.iter().map(|entry| package_row(entry, &load_registry_package)) }
                    </div>
                    <pre class="output registry-output">{(*registry_detail).clone()}</pre>
                </section>

                <section class="panel validator-panel">
                    <div class="panel-header">
                        <h2>{"Manifest"}</h2>
                        <div class="button-row">
                            <button type="button" onclick={validate}>{"Validate"}</button>
                            <button type="button" onclick={load_publication_records}>{"Publications"}</button>
                            <button type="button" onclick={load_feed_pointers}>{"Feeds"}</button>
                            <button type="button" onclick={load_validation_reports}>{"Reports"}</button>
                            <button type="button" onclick={load_evaluation_results}>{"Evaluations"}</button>
                            <button type="button" onclick={load_access_audit}>{"Access"}</button>
                            <button type="button" onclick={load_storage_cache}>{"Storage"}</button>
                        </div>
                    </div>
                    <textarea value={(*manifest_text).clone()} oninput={on_manifest_input} />
                    <pre class="output">{(*validation_text).clone()}</pre>
                </section>

                <section class="panel runner-panel">
                    <div class="panel-header">
                        <h2>{"Runner"}</h2>
                        <div class="button-row">
                            <button type="button" onclick={route}>{"Route"}</button>
                            <button type="button" onclick={run}>{"Run API"}</button>
                            <button type="button" onclick={run_browser}>{"Run Browser"}</button>
                        </div>
                    </div>
                    <label class="field">
                        <span>{"Input"}</span>
                        <input value={(*run_input).clone()} oninput={on_run_input} />
                    </label>
                    <pre class="output runner-output">{(*run_output).clone()}</pre>
                </section>

                <section class="panel marketplace-panel">
                    <div class="panel-header">
                        <h2>{"Marketplace"}</h2>
                        <span>{(*marketplace_status).clone()}</span>
                    </div>
                    <div class="button-row market-actions">
                        <button type="button" onclick={load_marketplace}>{"Load"}</button>
                        <button type="button" onclick={verify_marketplace_listing}>{"Verify Listing"}</button>
                        <button type="button" onclick={verify_marketplace_offer}>{"Verify Offer"}</button>
                        <button type="button" onclick={shortlist_marketplace}>{"Shortlist"}</button>
                        <button type="button" onclick={quote_marketplace}>{"Quote"}</button>
                        <button type="button" onclick={verify_marketplace_quote}>{"Verify Quote"}</button>
                        <button type="button" onclick={authorize_marketplace_payment}>{"Authorize"}</button>
                        <button type="button" onclick={verify_marketplace_payment}>{"Verify"}</button>
                        <button type="button" onclick={settle_marketplace}>{"Settle"}</button>
                        <button type="button" onclick={verify_marketplace_settlement}>{"Verify Settlement"}</button>
                        <button type="button" onclick={create_marketplace_dispute}>{"Dispute Evidence"}</button>
                        <button type="button" onclick={dispute_marketplace_settlement}>{"Open Dispute"}</button>
                        <button type="button" onclick={refund_marketplace_settlement}>{"Refund"}</button>
                        <button type="button" onclick={reject_marketplace_dispute}>{"Reject Dispute"}</button>
                        <button type="button" onclick={verify_marketplace_resolution}>{"Verify Resolution"}</button>
                        <button type="button" onclick={load_marketplace_audit}>{"Audit"}</button>
                        <button type="button" onclick={load_dispute_audit}>{"Disputes"}</button>
                        <button type="button" onclick={load_marketplace_payments}>{"Payments"}</button>
                    </div>
                    <div class="market-fields">
                        <label class="field">
                            <span>{"Payer"}</span>
                            <input value={(*payer).clone()} oninput={on_payer_input} />
                        </label>
                        <label class="field">
                            <span>{"Payee"}</span>
                            <input value={(*payee).clone()} oninput={on_payee_input} />
                        </label>
                        <label class="field">
                            <span>{"Resolver"}</span>
                            <input value={(*resolver).clone()} oninput={on_resolver_input} />
                        </label>
                        <label class="field">
                            <span>{"Dispute Reason"}</span>
                            <input value={(*dispute_reason).clone()} oninput={on_dispute_reason_input} />
                        </label>
                    </div>
                    {
                        if let Some(audit) = (*marketplace_audit).as_ref() {
                            marketplace_audit_summary(audit)
                        } else {
                            html! {}
                        }
                    }
                    <div class="market-grid">
                        <section>
                            <h3>{"Listings"}</h3>
                            <div class="market-list">
                                { for marketplace_listings.iter().map(marketplace_listing_row) }
                            </div>
                        </section>
                        <section>
                            <h3>{"Offers"}</h3>
                            <div class="market-list">
                                { for marketplace_offers.iter().map(runner_offer_row) }
                            </div>
                        </section>
                    </div>
                    <pre class="output market-output">{(*marketplace_output).clone()}</pre>
                </section>
            </section>
        </main>
    }
}

fn pretty_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|error| error.to_string())
}

async fn fetch_registry_shards() -> Result<Vec<Value>, String> {
    Request::get("/v1/registry/shards")
        .send()
        .await
        .map_err(|error| error.to_string())?
        .json::<Vec<Value>>()
        .await
        .map_err(|error| error.to_string())
}

async fn fetch_registry_shard_manifest() -> Result<Value, String> {
    Request::get("/v1/registry/shards/manifest")
        .send()
        .await
        .map_err(|error| error.to_string())?
        .json::<Value>()
        .await
        .map_err(|error| error.to_string())
}

fn registry_shard_briefs(shards: &[Value]) -> Vec<Value> {
    shards
        .iter()
        .map(|shard| {
            json!({
                "shardId": shard.get("shardId").cloned().unwrap_or(Value::Null),
                "shardKind": shard.get("shardKind").cloned().unwrap_or(Value::Null),
                "shardKey": shard.get("shardKey").cloned().unwrap_or(Value::Null),
                "entryCount": shard.get("entryCount").cloned().unwrap_or(Value::Null)
            })
        })
        .collect()
}

fn signature_label(signature: &Option<String>) -> &'static str {
    match signature.as_deref() {
        Some(value) if value.starts_with("ed25519:v1:") => "ed25519",
        Some(value) if value.starts_with("dev-") => "local-dev",
        Some(_) => "signed",
        None => "unsigned",
    }
}

fn marketplace_audit_summary(audit: &Value) -> Html {
    let settlement_count = audit
        .get("settlementCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let valid_settlement_count = audit
        .get("validSettlementCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let resolution_count = audit
        .get("resolutionCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let valid_resolution_count = audit
        .get("validResolutionCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let latest_settlement = latest_audit_id(audit, "settlements", "settlementId");
    let latest_resolution = latest_audit_id(audit, "resolutions", "resolutionId");

    html! {
        <div class="audit-strip">
            <span>{format!("{valid_settlement_count}/{settlement_count} settlements")}</span>
            <span>{format!("{valid_resolution_count}/{resolution_count} resolutions")}</span>
            <span>{format!("latest settlement {latest_settlement}")}</span>
            <span>{format!("latest resolution {latest_resolution}")}</span>
        </div>
    }
}

fn latest_audit_id(audit: &Value, collection: &str, id_field: &str) -> String {
    audit
        .get(collection)
        .and_then(Value::as_array)
        .and_then(|items| items.last())
        .and_then(|entry| entry.get(id_field))
        .and_then(Value::as_str)
        .unwrap_or("none")
        .to_string()
}

fn package_row(entry: &RegistryEntryV1, load_registry_package: &Callback<String>) -> Html {
    let package_id = entry.package_id.clone();
    let onclick = {
        let load_registry_package = load_registry_package.clone();
        Callback::from(move |_| load_registry_package.emit(package_id.clone()))
    };
    let latest_ref = entry
        .package_refs
        .first()
        .map(|pointer| pointer.package_ref.clone())
        .unwrap_or_else(|| "missing-ref".to_string());
    let validator_score = entry
        .trust
        .validator_score
        .map(|score| format!("{score:.2}"))
        .unwrap_or_else(|| "n/a".to_string());
    let benchmark_score = entry
        .benchmark_scores
        .iter()
        .max_by(|left, right| {
            left.overall
                .partial_cmp(&right.overall)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|summary| format!("{} {:.2}", summary.benchmark_id, summary.overall))
        .unwrap_or_else(|| "not run".to_string());
    let signature = if entry.trust.signature_verified {
        "signed"
    } else {
        "unverified"
    };
    let risk = format!("{:?}", entry.policy_summary.risk_level).to_lowercase();
    let policy = format!("{:?}", entry.policy_summary.decision).to_lowercase();
    let permissions = if entry.permissions.is_empty() {
        "none".to_string()
    } else {
        entry
            .permissions
            .iter()
            .map(|permission| permission.name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    html! {
        <article class="package-row">
            <div class="package-row-top">
                <div>
                    <strong>{entry.name.clone()}</strong>
                    <small>{format!("{} | {}", entry.package_id, latest_ref)}</small>
                    <small>{format!("risk {} | policy {} | permissions {}", risk, policy, permissions)}</small>
                    <small>{format!("trust {} | validator {} | benchmark {}", signature, validator_score, benchmark_score)}</small>
                </div>
                <button type="button" onclick={onclick}>{"Details"}</button>
            </div>
            <div class="chips">
                { for entry.capabilities.iter().map(|capability| html! { <span>{capability}</span> }) }
            </div>
        </article>
    }
}

fn marketplace_listing_row(listing: &MarketplaceListing) -> Html {
    let reference = listing
        .package_ref
        .clone()
        .unwrap_or_else(|| "missing-ref".to_string());
    let license = if listing.requires_license {
        "licensed"
    } else {
        "open"
    };
    html! {
        <article class="market-row">
            <strong>{listing.title.clone()}</strong>
            <small>{format!("{} | {}", listing.package_id, reference)}</small>
            <small>{format!("{} | {} | {} | owner {}", listing.listing_type, listing.status, license, listing.owner)}</small>
            <small>{format!("{} {:.4} {}", listing.pricing.mode, listing.pricing.base_price, listing.pricing.currency)}</small>
            <small>{format!("signature {}", signature_label(&listing.signature))}</small>
        </article>
    }
}

fn runner_offer_row(offer: &RunnerOffer) -> Html {
    let supported = offer.supported_package_refs.len();
    let capabilities = if offer.supported_capabilities.is_empty() {
        "none".to_string()
    } else {
        offer.supported_capabilities.join(", ")
    };
    html! {
        <article class="market-row">
            <strong>{offer.runner_id.clone()}</strong>
            <small>{format!("{} | {} | {} package(s)", offer.offer_id, offer.runner_type, supported)}</small>
            <small>{format!("capabilities {}", capabilities)}</small>
            <small>{format!("price {:.4}/{:.4} {}", offer.pricing.input_token_price, offer.pricing.output_token_price, offer.pricing.currency)}</small>
            <small>{format!("p95 {} ms | availability {:.2} | validator {:.2} | jobs {}", offer.service_level.p95_first_token_ms, offer.service_level.availability_target, offer.reputation.validator_score, offer.reputation.completed_jobs)}</small>
            <small>{format!("signature {}", signature_label(&offer.signature))}</small>
        </article>
    }
}

const DEFAULT_MANIFEST: &str = r#"{
  "schemaVersion": "swarm-ai.package.v1",
  "packageId": "hivemind/browser-draft",
  "kind": "model",
  "name": "Browser Draft",
  "version": "0.1.0",
  "publisher": {
    "address": "0x0000000000000000000000000000000000000000",
    "displayName": "Hivemind Labs"
  },
  "capabilities": ["embedding"],
  "artifactGroups": [{
    "id": "browser-wasm-small",
    "target": "browser-wasm",
    "engine": "wasm-mock",
    "format": "json",
    "paths": ["model/browser/config.json"],
    "totalBytes": 512,
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "minimum": {"memoryMB": 128, "webgpu": false}
  }],
  "inputSchema": {"type": "object"},
  "outputSchema": {"type": "object"},
  "permissions": [],
  "license": {"type": "open", "name": "Apache-2.0"}
}"#;
