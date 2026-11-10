//! Server-owned Genesis model access. UC subjects are resolved through the
//! canonical external-identity mapping; no model credential enters the CLI.
use super::*;
use crate::auth::uc::UcNativeProvider;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

const GENESIS_CATALOG_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);
const GENESIS_PUBLIC_CATALOG_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

fn catalog_timeout() -> (StatusCode, Json<ErrorResponse>) {
    error_response_coded(
        StatusCode::GATEWAY_TIMEOUT,
        "Model access took too long. Please try again.",
        "genesis_timeout",
    )
}

fn catalog_http_failure(status: StatusCode) -> (StatusCode, Json<ErrorResponse>) {
    match status {
        StatusCode::GATEWAY_TIMEOUT | StatusCode::REQUEST_TIMEOUT => catalog_timeout(),
        // This is Astra's server-held PAT, not the user's UC session. Returning
        // 401 here would incorrectly tell the client to discard a valid login.
        StatusCode::UNAUTHORIZED => error_response_coded(
            StatusCode::SERVICE_UNAVAILABLE,
            "Model access could not be authorized. Please contact support.",
            "genesis_credential_rejected",
        ),
        StatusCode::FORBIDDEN => error_response_coded(
            StatusCode::FORBIDDEN,
            "Your account cannot access these models. Please check your model access with an administrator.",
            "genesis_access_denied",
        ),
        _ => unavailable(),
    }
}

#[derive(Deserialize)]
struct GenesisModel {
    id: String,
    name: String,
    #[serde(rename = "type")]
    model_type: String,
    status: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    context_window: i32,
    #[serde(default)]
    max_output_tokens: i32,
}

#[derive(Deserialize)]
struct GenesisPage {
    items: Vec<GenesisModel>,
    next_page_token: String,
}

#[derive(Deserialize)]
struct GenesisPublicModel {
    id: String,
    name: String,
    #[serde(rename = "type")]
    model_type: String,
    #[serde(default)]
    reasoning_efforts: Vec<String>,
}

#[derive(Deserialize)]
struct GenesisPublicPage {
    items: Vec<GenesisPublicModel>,
    #[serde(default)]
    next_page_token: String,
}

pub(super) struct GenesisCatalog {
    pub items: Vec<ModelListItem>,
    pub default_offering_id: Option<String>,
    source_models: HashMap<String, (String, String)>,
    reasoning_efforts: HashMap<String, Vec<String>>,
    api_key: String,
}

#[derive(Deserialize)]
struct MoiChatModelPolicy {
    default_model: String,
    models: Vec<String>,
}

fn policy_unavailable() -> (StatusCode, Json<ErrorResponse>) {
    error_response_coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "MOI agent chat model policy is not ready",
        "moi_model_policy_unavailable",
    )
}

fn unavailable() -> (StatusCode, Json<ErrorResponse>) {
    error_response_coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "Genesis model access is not ready",
        "genesis_not_ready",
    )
}

fn transport_failure(
    stage: &'static str,
    error: reqwest::Error,
) -> (StatusCode, Json<ErrorResponse>) {
    let timed_out = error.is_timeout();
    tracing::warn!(component = "genesis", operation = "model_catalog", stage, timed_out, error = %error.without_url(), "model access dependency request failed");
    if timed_out {
        catalog_timeout()
    } else if stage == "product_policy" {
        policy_unavailable()
    } else {
        unavailable()
    }
}

pub(super) fn offering_id(issuer: &str, subject: &str, id: &str) -> String {
    let mut hash = Sha256::new();
    for part in [issuer, subject, id] {
        hash.update(part.as_bytes());
        hash.update([0]);
    }
    // Full SHA-256 in base64url fits Astra's 64-byte Offering identity limit.
    format!("genesis-{}", URL_SAFE_NO_PAD.encode(hash.finalize()))
}

impl DatabaseModelService {
    pub fn with_uc_native(mut self, provider: Option<UcNativeProvider>) -> Self {
        self.uc_provider = provider;
        self
    }

    pub(super) async fn uc_subject(
        &self,
        user_id: &str,
    ) -> Result<Option<String>, (StatusCode, Json<ErrorResponse>)> {
        let Some(provider) = &self.uc_provider else {
            return Ok(None);
        };
        let pool = self.get_pool().await.map_err(internal_error)?;
        query_scalar("SELECT external_subject FROM auth_external_identities WHERE astra_user_id = ? AND provider_id = ? LIMIT 1")
            .bind(user_id).bind(format!("uc:{}", provider.settings.issuer))
            .fetch_optional(&pool).await.map_err(internal_error)
    }

    pub(super) async fn genesis_catalog(
        &self,
        subject: &str,
    ) -> Result<GenesisCatalog, (StatusCode, Json<ErrorResponse>)> {
        // One budget covers PAT, product policy and all catalog pages. Do not
        // multiply the allowed wait by the number of pages or retry stale grants.
        let lookup = async {
            // Public metadata is optional and must not grant model access or
            // make an ordinary model-default request depend on another API.
            let public = async {
                Ok::<_, (StatusCode, Json<ErrorResponse>)>(
                    tokio::time::timeout(
                        GENESIS_PUBLIC_CATALOG_BUDGET,
                        self.genesis_public_models(),
                    )
                    .await
                    .ok()
                    .flatten(),
                )
            };
            let (mut catalog, public) =
                tokio::try_join!(self.genesis_catalog_inner(subject), public)?;
            if let Some(public) = public {
                for item in &mut catalog.items {
                    let Some((source_id, source_type)) =
                        catalog.source_models.get(&item.offering_id)
                    else {
                        continue;
                    };
                    let Some(model) = public.get(source_id).filter(|model| {
                        model.name == item.name && model.model_type == *source_type
                    }) else {
                        continue;
                    };
                    // The existing picker offers low/high/max together, so
                    // advertise it only when all three are declared.
                    if ["low", "high", "max"]
                        .iter()
                        .all(|level| model.reasoning_efforts.iter().any(|value| value == level))
                    {
                        item.thinking_capability = Some(ThinkingCapability::EffortOnly);
                        item.thinking_protocol = Some(ThinkingProtocol::ReasoningEffort);
                        catalog
                            .reasoning_efforts
                            .insert(item.offering_id.clone(), model.reasoning_efforts.clone());
                    }
                }
            }
            Ok(catalog)
        };
        tokio::time::timeout(GENESIS_CATALOG_BUDGET, lookup)
            .await
            .map_err(|_| {
                tracing::warn!(
                    component = "genesis",
                    operation = "model_catalog",
                    code = "genesis_timeout",
                    "model catalog lookup exceeded its deadline"
                );
                catalog_timeout()
            })?
    }

    async fn genesis_public_models(&self) -> Option<HashMap<String, GenesisPublicModel>> {
        let provider = self.uc_provider.as_ref()?;
        let mut cursor = String::new();
        let mut seen = BTreeSet::new();
        let mut models = HashMap::new();
        for _ in 0..100 {
            let response = provider
                .client
                .get(format!(
                    "{}/api/v1/taas/public/models",
                    provider.settings.genesis_url
                ))
                .query(&[("page_size", "100"), ("page_token", cursor.as_str())])
                .send()
                .await
                .ok()?;
            let page: GenesisPublicPage = UcNativeProvider::json_bounded(response, 1024 * 1024)
                .await
                .ok()?;
            for model in page.items {
                if model.id.is_empty() || models.insert(model.id.clone(), model).is_some() {
                    return None;
                }
            }
            if page.next_page_token.is_empty() {
                return Some(models);
            }
            if !seen.insert(page.next_page_token.clone()) {
                return None;
            }
            cursor = page.next_page_token;
        }
        None
    }

    async fn genesis_catalog_inner(
        &self,
        subject: &str,
    ) -> Result<GenesisCatalog, (StatusCode, Json<ErrorResponse>)> {
        let provider = self.uc_provider.as_ref().ok_or_else(unavailable)?;
        let mut url = crate::auth::uc::validate_uc_url(&provider.settings.adapter_url)
            .map_err(|_| unavailable())?;
        url.path_segments_mut().map_err(|_| unavailable())?.extend([
            "api",
            "v1",
            "uc",
            "internal",
            "accounts",
            subject,
            "aistudio-pat",
        ]);
        #[derive(Deserialize)]
        struct RuntimePAT {
            api_key: String,
        }
        let response = provider
            .client
            .get(url)
            .bearer_auth(provider.service_bearer().await?)
            .send()
            .await
            .map_err(|error| transport_failure("runtime_pat", error))?;
        let pat: RuntimePAT = UcNativeProvider::json(response)
            .await
            .map_err(|_| unavailable())?;
        if pat.api_key.is_empty() {
            return Err(unavailable());
        }
        // MOI owns product selection; Genesis owns account eligibility. The
        // runtime PAT remains server-side and uses MOI's existing PAT transport.
        // No workspace is needed to read this account-level product policy.
        #[derive(Deserialize)]
        struct PolicyEnvelope {
            code: String,
            data: MoiChatModelPolicy,
        }
        let response = provider
            .client
            .get(format!(
                "{}/aistudio/model-policy",
                provider.settings.moi_api_url
            ))
            .header("X-API-Key", &pat.api_key)
            .send()
            .await
            .map_err(|error| transport_failure("product_policy", error))?;
        let envelope: PolicyEnvelope = UcNativeProvider::json_bounded(response, 1024 * 1024)
            .await
            .map_err(|_| policy_unavailable())?;
        let policy = envelope.data;
        let allowed: BTreeSet<_> = policy.models.iter().cloned().collect();
        if envelope.code != "OK"
            || allowed.len() != policy.models.len()
            || allowed.contains("")
            || !allowed.contains(&policy.default_model)
        {
            return Err(policy_unavailable());
        }
        let mut cursor = String::new();
        let mut seen = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut items = Vec::new();
        let mut source_models = HashMap::new();
        // Genesis owns visibility and status; use its existing user-PAT API,
        // including pagination, rather than a second local model allowlist.
        for _ in 0..100 {
            let response = provider
                .client
                .get(format!(
                    "{}/api/v1/taas/llm/model-offerings",
                    provider.settings.genesis_url
                ))
                .bearer_auth(&pat.api_key)
                // Override the UC client's 10s default. The outer deadline is
                // authoritative, including preparation and all prior pages;
                // this does NOT reserve another 20s for each page.
                .timeout(GENESIS_CATALOG_BUDGET)
                .query(&[
                    ("type", "chat"),
                    ("status", "enabled"),
                    ("page_size", "100"),
                    ("page_token", cursor.as_str()),
                ])
                .send()
                .await
                .map_err(|error| transport_failure("model_offerings", error))?;
            if !response.status().is_success() {
                tracing::warn!(component = "genesis", operation = "model_catalog", stage = "model_offerings", status = %response.status(), "model access dependency rejected catalog request");
                return Err(catalog_http_failure(response.status()));
            }
            let page: GenesisPage = UcNativeProvider::json_bounded(response, 1024 * 1024)
                .await
                .map_err(|_| unavailable())?;
            for model in page.items {
                // Only product-selected candidates become runtime Offerings.
                // Unrelated Genesis metadata must not block this product catalog.
                if !allowed.contains(&model.name) {
                    continue;
                }
                if !matches!(model.model_type.as_str(), "chat_text" | "chat_multimodal")
                    || model.status != "enabled"
                {
                    return Err(unavailable());
                }
                if model.id.is_empty()
                    || model.name.is_empty()
                    || model.context_window <= 0
                    || !ids.insert(model.id.clone())
                {
                    return Err(unavailable());
                }
                let id = offering_id(&provider.settings.issuer, subject, &model.id);
                source_models.insert(id.clone(), (model.id, model.model_type));
                items.push(ModelListItem {
                    thinking_protocol: None,
                    offering_id: id,
                    access_id: "genesis".into(),
                    access_kind: ModelAccessKind::AstraCloud,
                    access_label: "Genesis".into(),
                    execution_placement: ModelExecutionPlacement::Server,
                    name: model.name,
                    provider: "openai".into(),
                    description: Some(model.description),
                    is_active: true,
                    context_window: model.context_window,
                    max_completion_tokens: (model.max_output_tokens > 0)
                        .then_some(model.max_output_tokens),
                    architecture: None,
                    thinking_capability: None,
                    pricing: None,
                });
            }
            if page.next_page_token.is_empty() {
                let default_offering_id = items
                    .iter()
                    .find(|item| item.name == policy.default_model)
                    .map(|item| item.offering_id.clone());
                sort_model_list_items(&mut items);
                return Ok(GenesisCatalog {
                    items,
                    default_offering_id,
                    source_models,
                    reasoning_efforts: HashMap::new(),
                    api_key: pat.api_key,
                });
            }
            if !seen.insert(page.next_page_token.clone()) {
                return Err(unavailable());
            }
            cursor = page.next_page_token;
        }
        Err(unavailable())
    }

    pub(super) async fn admit_genesis(
        &self,
        subject: &str,
        selected: &str,
    ) -> Result<AdmittedModelExecution, (StatusCode, Json<ErrorResponse>)> {
        let catalog = self.genesis_catalog(subject).await?;
        self.admit_genesis_from_catalog(&catalog, selected)
    }

    pub(super) fn admit_genesis_from_catalog(
        &self,
        catalog: &GenesisCatalog,
        selected: &str,
    ) -> Result<AdmittedModelExecution, (StatusCode, Json<ErrorResponse>)> {
        let item = catalog
            .items
            .iter()
            .find(|item| item.offering_id == selected)
            .ok_or_else(|| {
                model_offering_resolution_error_response(ModelOfferingResolutionError::NotFound {
                    offering_id: selected.into(),
                })
            })?;
        let provider = self.uc_provider.as_ref().ok_or_else(unavailable)?;
        Ok(AdmittedModelExecution {
            price_snapshot: None,
            offering_id: item.offering_id.clone(),
            source_identity: Some(crate::models::ResolvedModelSourceIdentity {
                provider: "openai".into(),
                access_label: ModelAccessKind::AstraCloud.source_label().to_string(),
            }),
            access_kind: ModelAccessKind::AstraCloud,
            execution_placement: ModelExecutionPlacement::Server,
            model_name: item.name.clone(),
            wire_model_name: None,
            api_key: catalog.api_key.clone(),
            base_url: format!("{}/v1", provider.settings.genesis_url),
            provider: "openai".into(),
            cache_capability: None,
            thinking_capability: item.thinking_capability,
            reasoning_efforts: catalog.reasoning_efforts.get(&item.offering_id).cloned(),
            fixed_temperature: None,
            thinking_protocol: item.thinking_protocol,
            request_body_overrides: None,
            context_window: Some(item.context_window as u32),
            max_completion_tokens: item.max_completion_tokens.map(|v| v as u32),
            header_overrides: HashMap::new(),
            completions_url_override: None,
            request_timeout_ms: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_core::config::UcNativeSettings;
    use axum::{
        Router,
        extract::{Path, Query, State},
        http::HeaderMap,
        routing::{get, post},
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone, Default)]
    struct Fixture {
        requests: Arc<AtomicUsize>,
        unavailable: Arc<Mutex<Option<&'static str>>>,
        policy: Arc<Mutex<serde_json::Value>>,
        policy_status: Arc<Mutex<StatusCode>>,
        delay: Arc<Mutex<std::time::Duration>>,
        preparation_delay: Arc<Mutex<std::time::Duration>>,
        catalog_status: Arc<Mutex<StatusCode>>,
        reasoning_efforts: Arc<Mutex<Option<serde_json::Value>>>,
        public_failure: Arc<Mutex<Option<&'static str>>>,
    }

    struct Server(tokio::task::JoinHandle<()>);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn fixture() -> (DatabaseModelService, Fixture, Server) {
        let state = Fixture {
            policy: Arc::new(Mutex::new(serde_json::json!({
                "code": "OK",
                "data": {"default_model": "genesis-model-1", "models": ["genesis-model-1", "genesis-model-2"]}
            }))),
            ..Fixture::default()
        };
        let app = Router::new()
            .route("/realms/moi/protocol/openid-connect/token", post(|headers: HeaderMap| async move {
                assert!(headers["authorization"].to_str().unwrap().starts_with("Basic "));
                Json(serde_json::json!({"access_token":"synthetic-service", "token_type":"Bearer", "expires_in":300}))
            }))
            .route("/api/v1/uc/internal/accounts/{subject}/aistudio-pat", get(|State(state): State<Fixture>, Path(subject): Path<String>, headers: HeaderMap| async move {
                let delay = *state.preparation_delay.lock().unwrap();
                tokio::time::sleep(delay).await;
                assert_eq!(headers["authorization"], "Bearer synthetic-service");
                assert!(!headers.contains_key("x-api-key"));
                Json(serde_json::json!({"api_key":format!("synthetic-pat-{subject}")}))
            }))
            .route("/newmoi/aistudio/model-policy", get(|State(state): State<Fixture>, headers: HeaderMap| async move {
                assert!(headers["x-api-key"].to_str().unwrap().starts_with("synthetic-pat-"));
                assert!(!headers.contains_key("authorization"));
                assert!(!headers.contains_key("x-workspace-id"));
                (*state.policy_status.lock().unwrap(), Json(state.policy.lock().unwrap().clone()))
            }))
            .route("/api/v1/taas/llm/model-offerings", get(|State(state): State<Fixture>, headers: HeaderMap, Query(query): Query<HashMap<String,String>>| async move {
                state.requests.fetch_add(1, Ordering::SeqCst);
                let delay = *state.delay.lock().unwrap();
                tokio::time::sleep(delay).await;
                assert!(!headers.contains_key("x-api-key"));
                assert!(headers["authorization"].to_str().unwrap().starts_with("Bearer synthetic-pat-"));
                assert_eq!(query.get("type").unwrap(), "chat");
                assert_eq!(query.get("status").unwrap(), "enabled");
                let failure = *state.unavailable.lock().unwrap();
                let status = *state.catalog_status.lock().unwrap();
                if !status.is_success() {
                    return (status, Json(serde_json::json!({"error":{"code":"model_catalog_unavailable", "message":"synthetic-private-diagnostic"}})));
                }
                let first = query.get("page_token").unwrap().is_empty();
                let (id, cursor) = if first { ("model-1", "next") } else { ("model-2", "") };
                let item = serde_json::json!({"id":id,"name":format!("genesis-{id}"),"type": if first {"chat_text"} else {"chat_multimodal"}, "status":if failure == Some("disabled") {"disabled"} else {"enabled"}, "context_window":if failure == Some("context") || (first && failure == Some("first_context")) {0} else {32000}, "max_output_tokens":4096});
                let items = if failure == Some("removed") { vec![] } else { vec![item] };
                (StatusCode::OK, Json(serde_json::json!({"items":items, "next_page_token": if failure == Some("cycle") { "next" } else { cursor }})))
            }))
            .route("/api/v1/taas/public/models", get(|State(state): State<Fixture>, headers: HeaderMap, Query(query): Query<HashMap<String,String>>| async move {
                assert!(!headers.contains_key("authorization"));
                assert!(!headers.contains_key("x-api-key"));
                let failure = *state.public_failure.lock().unwrap();
                if failure == Some("slow") {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
                if failure == Some("unavailable") {
                    return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({})));
                }
                let first = query.get("page_token").unwrap().is_empty();
                let (id, cursor) = if first { ("model-1", "next") } else { ("model-2", "") };
                let id = if !first && failure == Some("duplicate") { "model-1" } else { id };
                let name = if first && failure == Some("mismatch") { "different-model".to_owned() } else { format!("genesis-{id}") };
                let model_type = if first && failure == Some("type") { "embedding_text" } else if first { "chat_text" } else { "chat_multimodal" };
                let mut item = serde_json::json!({"id":id,"name":name,"type":model_type});
                if let Some(efforts) = state.reasoning_efforts.lock().unwrap().clone() {
                    item["reasoning_efforts"] = efforts;
                }
                let items = if first && failure == Some("missing") { vec![] } else { vec![item] };
                (StatusCode::OK, Json(serde_json::json!({"items":items, "next_page_token":cursor})))
            })).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = Server(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let provider = UcNativeProvider::new(UcNativeSettings {
            builtin_memory: false,
            issuer: format!("{origin}/realms/moi"),
            adapter_url: origin.clone(),
            moi_api_url: format!("{origin}/newmoi"),
            genesis_url: origin,
            client_secret: "synthetic-service-secret".into(),
        })
        .unwrap();
        let service = DatabaseModelService::new(
            MatrixOneSettings::default(),
            Arc::new(FernetTokenEncryptor::new("synthetic-test-key").unwrap()),
        )
        .with_uc_native(Some(provider));
        (service, state, server)
    }

    #[tokio::test]
    async fn genesis_reasoning_capability_requires_declared_levels() {
        let (service, state, _server) = fixture().await;
        let missing = service.genesis_catalog("account-A").await.unwrap();
        assert!(
            missing
                .items
                .iter()
                .all(|item| item.thinking_capability.is_none())
        );
        *state.reasoning_efforts.lock().unwrap() = Some(serde_json::json!(["low", "high"]));
        let partial = service.genesis_catalog("account-A").await.unwrap();
        assert!(
            partial
                .items
                .iter()
                .all(|item| item.thinking_capability.is_none())
        );
        *state.reasoning_efforts.lock().unwrap() = Some(serde_json::json!(["low", "high", "max"]));
        let catalog = service.genesis_catalog("account-A").await.unwrap();
        let item = &catalog.items[0];
        assert_eq!(
            item.thinking_capability,
            Some(ThinkingCapability::EffortOnly)
        );
        assert_eq!(
            item.thinking_protocol,
            Some(ThinkingProtocol::ReasoningEffort)
        );
        let execution = service
            .admit_genesis_from_catalog(&catalog, &item.offering_id)
            .unwrap();
        assert_eq!(
            execution.reasoning_efforts,
            Some(vec!["low".into(), "high".into(), "max".into()])
        );
        assert_eq!(execution.thinking_capability, item.thinking_capability);
        assert_eq!(execution.thinking_protocol, item.thinking_protocol);
    }

    #[tokio::test]
    async fn public_reasoning_metadata_cannot_expand_entitlements_and_is_optional() {
        let (service, state, _server) = fixture().await;
        *state.reasoning_efforts.lock().unwrap() = Some(serde_json::json!(["low", "high", "max"]));
        *state.policy.lock().unwrap() = serde_json::json!({
            "code": "OK",
            "data": {"default_model": "genesis-model-1", "models": ["genesis-model-1"]}
        });
        let catalog = service.genesis_catalog("account-A").await.unwrap();
        assert_eq!(catalog.items.len(), 1);
        assert_eq!(catalog.items[0].name, "genesis-model-1");
        assert_eq!(
            catalog.items[0].thinking_capability,
            Some(ThinkingCapability::EffortOnly)
        );

        for failure in ["mismatch", "type", "missing", "duplicate", "unavailable"] {
            *state.public_failure.lock().unwrap() = Some(failure);
            let catalog = service.genesis_catalog("account-A").await.unwrap();
            assert_eq!(catalog.items.len(), 1);
            assert_eq!(catalog.items[0].name, "genesis-model-1");
            assert!(catalog.items[0].thinking_capability.is_none());
            assert!(catalog.reasoning_efforts.is_empty());
        }
    }

    #[tokio::test]
    async fn slow_public_reasoning_metadata_does_not_block_the_account_catalog() {
        let (service, state, _server) = fixture().await;
        *state.public_failure.lock().unwrap() = Some("slow");
        *state.reasoning_efforts.lock().unwrap() = Some(serde_json::json!(["low", "high", "max"]));
        let started = std::time::Instant::now();
        let catalog = service.genesis_catalog("account-A").await.unwrap();
        assert_eq!(catalog.items.len(), 2);
        assert!(catalog.reasoning_efforts.is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(8));
    }

    #[tokio::test]
    async fn genesis_catalog_slow_pages_share_one_deadline() {
        let (service, state, _server) = fixture().await;
        *state.delay.lock().unwrap() = std::time::Duration::from_secs(11);
        let started = std::time::Instant::now();
        let result = service.genesis_catalog("account-A").await;
        let (status, body) = match result {
            Err(error) => error,
            Ok(_) => panic!("slow pagination must exceed the aggregate deadline"),
        };
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(body.0.error_code.as_deref(), Some("genesis_timeout"));
        assert!(started.elapsed() < std::time::Duration::from_secs(25));
        assert_eq!(state.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn genesis_catalog_preparation_consumes_the_same_deadline() {
        let (service, state, _server) = fixture().await;
        *state.preparation_delay.lock().unwrap() = std::time::Duration::from_secs(4);
        *state.delay.lock().unwrap() = std::time::Duration::from_secs(9);
        let started = std::time::Instant::now();
        let (status, body) = service.genesis_catalog("account-A").await.err().unwrap();
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(body.0.error_code.as_deref(), Some("genesis_timeout"));
        assert!(started.elapsed() < std::time::Duration::from_secs(25));
        assert_eq!(state.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn genesis_catalog_http_failures_are_classified_without_upstream_body() {
        let (service, state, _server) = fixture().await;
        for (upstream, expected, code) in [
            (
                StatusCode::UNAUTHORIZED,
                StatusCode::SERVICE_UNAVAILABLE,
                "genesis_credential_rejected",
            ),
            (
                StatusCode::FORBIDDEN,
                StatusCode::FORBIDDEN,
                "genesis_access_denied",
            ),
            (
                StatusCode::GATEWAY_TIMEOUT,
                StatusCode::GATEWAY_TIMEOUT,
                "genesis_timeout",
            ),
            (
                StatusCode::REQUEST_TIMEOUT,
                StatusCode::GATEWAY_TIMEOUT,
                "genesis_timeout",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
                "genesis_not_ready",
            ),
        ] {
            *state.catalog_status.lock().unwrap() = upstream;
            let (status, body) = service.genesis_catalog("account-A").await.err().unwrap();
            assert_eq!(status, expected);
            assert_eq!(body.0.error_code.as_deref(), Some(code));
            assert!(
                !serde_json::to_string(&body.0)
                    .unwrap()
                    .contains("synthetic-private")
            );
        }
    }

    #[tokio::test]
    async fn genesis_catalog_is_paginated_account_bound_and_never_exports_credentials() {
        let (service, state, _server) = fixture().await;
        let a = service.genesis_catalog("account-A").await.unwrap();
        let b = service.genesis_catalog("account-B").await.unwrap();
        assert_eq!(a.items.len(), 2);
        assert_eq!(state.requests.load(Ordering::SeqCst), 4);
        assert_ne!(a.items[0].offering_id, b.items[0].offering_id);
        for item in &a.items {
            validate_model_offering_id(&item.offering_id).unwrap();
        }
        let projection = project_model_access_with_default(
            server_model_access_declarations(false, a.items.iter().map(|item| item.access_kind)),
            a.items
                .iter()
                .cloned()
                .map(ModelListItemResponse::from)
                .collect(),
            Some(ModelDefaultCandidate {
                offering_id: a.items[0].offering_id.clone(),
                source: ModelDefaultSource::Astra,
                scope: ModelDefaultScope::EffectiveCatalog,
            }),
            "2026-09-16T00:00:00Z".into(),
        )
        .unwrap();
        assert_eq!(
            projection.default_offering_id.as_ref(),
            Some(&a.items[0].offering_id)
        );
        let exported = serde_json::to_string(&a.items).unwrap();
        assert!(!exported.contains("synthetic-") && !exported.contains("api_key"));
        let admitted = service
            .admit_genesis("account-A", &a.items[0].offering_id)
            .await
            .unwrap();
        assert_eq!(admitted.api_key, "synthetic-pat-account-A");
        assert_eq!(admitted.access_kind, ModelAccessKind::AstraCloud);
        assert_eq!(
            admitted.execution_placement,
            ModelExecutionPlacement::Server
        );
        assert!(admitted.base_url.ends_with("/v1"));
        assert!(
            service
                .admit_genesis("account-B", &a.items[0].offering_id)
                .await
                .is_err()
        );
        *state.unavailable.lock().unwrap() = Some("removed");
        assert!(
            service
                .admit_genesis("account-A", &a.items[0].offering_id)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn genesis_catalog_rejects_disabled_invalid_and_cyclic_metadata() {
        let (service, state, _server) = fixture().await;
        for failure in ["disabled", "context", "cycle"] {
            *state.unavailable.lock().unwrap() = Some(failure);
            assert!(
                service.genesis_catalog("account-A").await.is_err(),
                "{failure}"
            );
        }
    }

    #[tokio::test]
    async fn unselected_invalid_metadata_does_not_block_later_selected_models() {
        let (service, state, _server) = fixture().await;
        let initial = service.genesis_catalog("account-A").await.unwrap();
        let excluded = initial.items[0].offering_id.clone();
        *state.unavailable.lock().unwrap() = Some("first_context");
        *state.policy.lock().unwrap() = serde_json::json!({
            "code": "OK", "data": {"models": ["genesis-model-2"], "default_model": "genesis-model-2"}
        });
        let catalog = service.genesis_catalog("account-A").await.unwrap();
        assert_eq!(catalog.items.len(), 1);
        assert_eq!(catalog.items[0].name, "genesis-model-2");
        assert_eq!(catalog.items[0].context_window, 32000);
        assert_eq!(
            catalog.default_offering_id.as_ref(),
            Some(&catalog.items[0].offering_id)
        );
        assert_eq!(state.requests.load(Ordering::SeqCst), 4);
        assert!(
            service
                .admit_genesis("account-A", &catalog.items[0].offering_id)
                .await
                .is_ok()
        );
        assert!(service.admit_genesis("account-A", &excluded).await.is_err());

        // Selecting the invalid model must still fail, even with a valid default.
        state.policy.lock().unwrap()["data"]["models"] =
            serde_json::json!(["genesis-model-1", "genesis-model-2"]);
        let error = service.genesis_catalog("account-A").await.err().unwrap();
        assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            serde_json::to_string(&error.1.0)
                .unwrap()
                .contains("genesis_not_ready")
        );
    }

    #[tokio::test]
    async fn moi_policy_controls_catalog_default_and_live_admission() {
        let (service, state, _server) = fixture().await;
        let initial = service.genesis_catalog("account-A").await.unwrap();
        assert_eq!(
            initial.default_offering_id,
            Some(initial.items[0].offering_id.clone())
        );
        let removed = initial.items[0].offering_id.clone();
        *state.policy.lock().unwrap() = serde_json::json!({
            "code": "OK", "data": {"models": ["genesis-model-2"], "default_model": "genesis-model-2"}
        });
        let changed = service.genesis_catalog("account-A").await.unwrap();
        assert_eq!(changed.items.len(), 1);
        assert_eq!(changed.items[0].name, "genesis-model-2");
        assert_eq!(
            changed.default_offering_id,
            Some(changed.items[0].offering_id.clone())
        );
        assert!(service.admit_genesis("account-A", &removed).await.is_err());
        assert!(
            service
                .admit_genesis("account-A", &changed.items[0].offering_id)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn moi_default_is_explicit_not_catalog_sort_order() {
        let (service, state, _server) = fixture().await;
        state.policy.lock().unwrap()["data"]["default_model"] = "genesis-model-2".into();
        let catalog = service.genesis_catalog("account-A").await.unwrap();
        assert_eq!(catalog.items.len(), 2);
        assert_eq!(
            catalog.default_offering_id,
            Some(catalog.items[1].offering_id.clone())
        );
    }

    #[tokio::test]
    async fn moi_policy_cannot_expand_genesis_entitlements_or_invent_a_default() {
        let (service, state, _server) = fixture().await;
        *state.policy.lock().unwrap() = serde_json::json!({
            "code": "OK", "data": {"models": ["genesis-model-2", "not-entitled"], "default_model": "not-entitled"}
        });
        let catalog = service.genesis_catalog("account-A").await.unwrap();
        assert_eq!(catalog.items.len(), 1);
        assert_eq!(catalog.items[0].name, "genesis-model-2");
        assert_eq!(catalog.default_offering_id, None);
        *state.unavailable.lock().unwrap() = Some("removed");
        let empty = service.genesis_catalog("account-A").await.unwrap();
        assert!(empty.items.is_empty());
        assert_eq!(empty.default_offering_id, None);
    }

    #[tokio::test]
    async fn moi_policy_failure_never_falls_back_to_the_full_genesis_catalog() {
        let (service, state, _server) = fixture().await;
        let selected = service.genesis_catalog("account-A").await.unwrap().items[0]
            .offering_id
            .clone();
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            *state.policy_status.lock().unwrap() = status;
            let error = service
                .admit_genesis("account-A", &selected)
                .await
                .err()
                .unwrap();
            assert_eq!(error.0, StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                serde_json::to_string(&error.1.0)
                    .unwrap()
                    .contains("moi_model_policy_unavailable")
            );
        }
        *state.policy_status.lock().unwrap() = StatusCode::OK;
        for policy in [
            serde_json::json!({"code": "ErrLLMServiceSlotNotConfigured", "data": null}),
            serde_json::json!({"code": "OK", "data": {"models": [], "default_model": ""}}),
            serde_json::json!({"code": "OK", "data": {"models": ["genesis-model-1"], "default_model": "outside"}}),
            serde_json::json!({"code": "OK", "data": {"models": [""], "default_model": ""}}),
            serde_json::json!({"code": "OK", "data": {"models": ["genesis-model-1"]}}),
            serde_json::json!({"code": "OK", "data": {"models": ["genesis-model-1", "genesis-model-1"], "default_model": "genesis-model-1"}}),
        ] {
            *state.policy.lock().unwrap() = policy;
            assert!(service.admit_genesis("account-A", &selected).await.is_err());
        }
    }
}
