//! Existing user-token controls remain separate from request-signed MOI forks.
use astra_core::{
    AppSettings, EdgeTokenAuthConfig, ErrorResponse, ProviderRequestAuthConfig, SharedPool,
};
use astra_runtime::{AppState, build_app, build_server_state};
use astra_services::{
    AcquireWriterOutcome, AuthLoginRequestData, AuthPrincipal, AuthPrincipalOrigin,
    AuthRefreshRequestData, AuthRegisterRequestData, AuthService, AuthTokenRecord, AuthUserRecord,
    DatabaseAuthService, DatabaseSessionContextCoordinator, DatabaseSessionForkCoordinator,
    DatabaseSessionService, ProviderRequestDescriptor, RequestAuthMechanism, ReserveTurnOutcome,
    SessionContextCoordinator, SessionCreateRequestData, SessionService,
};
use astra_turn_types::{
    ActorContextV1, ActorKindV1, AuthorityEpochsV1, CANONICAL_TURN_DELTA_SCHEMA_VERSION,
    CanonicalDeltaModeV1, CanonicalTurnDeltaV1, CoordinatorMutationV1, SessionCursorV1,
    SessionKeyV1, SessionSurfaceV1,
};
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Connection, MySqlConnection};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;

pub(super) const USER_TOKEN_KEY: &str = "moi-fork-legacy-credential-test-key";

pub(super) fn token(claims: Value) -> String {
    let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
    let mut signer = Hmac::<Sha256>::new_from_slice(USER_TOKEN_KEY.as_bytes()).unwrap();
    signer.update(claims.as_bytes());
    format!(
        "moi-user-token-v1.{claims}.{}",
        URL_SAFE_NO_PAD.encode(signer.finalize().into_bytes())
    )
}

fn bearer_headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
    headers
}

struct LegacyCase {
    name: &'static str,
    token: String,
    key: SessionKeyV1,
    cursor: SessionCursorV1,
}

impl LegacyCase {
    fn prepare_body(&self, intent: &str) -> String {
        json!({"idempotency_key":intent,"expected_parent_cursor":self.cursor,
            "reason":"existing credential at canonical commit before transcript publication"})
        .to_string()
    }

    fn request(&self, path: &str, body: String) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", self.token))
            .body(Body::from(body))
            .unwrap()
    }

    fn prepare_request(&self, intent: &str) -> Request<Body> {
        self.request(
            &format!("/sessions/{}/forks", self.key.session_id),
            self.prepare_body(intent),
        )
    }
}

async fn response(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).expect("control response JSON"),
    )
}

struct LegacyFixture {
    state: AppState,
    app: Router,
    auth: Arc<DatabaseAuthService>,
    sessions: Arc<DatabaseSessionService>,
    context: Arc<DatabaseSessionContextCoordinator>,
    forks: Arc<DatabaseSessionForkCoordinator>,
    pool: SharedPool,
    database: String,
    admin: MySqlConnection,
    revocation_task: tokio::task::JoinHandle<()>,
    revocation_calls: Arc<AtomicUsize>,
    revocation_errors: Arc<Mutex<Vec<String>>>,
    cases: Vec<LegacyCase>,
}

impl LegacyFixture {
    async fn new() -> Self {
        assert_eq!(std::env::var("ASTRA_TEST_DB_IT").as_deref(), Ok("1"));
        let now = chrono::Utc::now().timestamp();
        let runtime_token = token(
            json!({"sub":"fork-runtime-user","workspace_id":"legacy-workspace",
            "iss":"moi-core","iat":now,"exp":now+3600,"purpose":"runtime"}),
        );
        let edge_token = token(
            json!({"sub":"fork-edge-user","workspace_id":"legacy-workspace",
            "iss":"moi-backend","iat":now,"exp":now+3600,"purpose":"edge_registration",
            "edge_agent_id":"fork-compat-edge","jti":Uuid::new_v4().to_string()}),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let revocation = Router::new().route(
            "/check",
            post({
                let calls = calls.clone();
                let errors = errors.clone();
                let expected = edge_token.clone();
                move |Json(body): Json<Value>| {
                    let calls = calls.clone();
                    let errors = errors.clone();
                    let expected = expected.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let valid = body == json!({"token":expected});
                        if !valid {
                            errors.lock().unwrap().push(
                                "revocation request did not carry the real edge credential".into(),
                            );
                        }
                        Json(json!({"code":if valid {0} else {1},"data":{"ok":valid}}))
                    }
                }
            }),
        );
        let revocation_task = tokio::spawn(async move {
            axum::serve(listener, revocation).await.unwrap();
        });
        let mut settings = AppSettings::from_explicit_env().expect("explicit test settings");
        let database = format!("astra_test_moi_{}", Uuid::new_v4().simple());
        settings.matrixone.database = "mysql".into();
        let mut admin = MySqlConnection::connect(&settings.matrixone.database_url_with_password())
            .await
            .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE `{database}`")))
            .execute(&mut admin)
            .await
            .unwrap();
        eprintln!("MOI legacy fork auth fixture created: {database}");
        settings.matrixone.database = database.clone();
        settings.memoria.base_url = endpoint.clone();
        settings.external_providers.clear();
        settings.edge_token_auth = EdgeTokenAuthConfig {
            key: USER_TOKEN_KEY.into(),
            check_endpoint: format!("{endpoint}/check"),
        };
        let state = build_server_state(settings.clone())
            .await
            .expect("fresh real Astra state");
        let pool = state.shared_pool.as_ref().unwrap().clone();
        let auth = Arc::new(
            DatabaseAuthService::new(settings.matrixone.clone(), settings.jwt.clone())
                .with_pool(pool.clone())
                .with_edge_token_auth(settings.edge_token_auth.clone()),
        );
        let sessions =
            Arc::new(DatabaseSessionService::new(settings.matrixone).with_pool(pool.clone()));
        let context = Arc::new(DatabaseSessionContextCoordinator::new(pool.clone()));
        let forks = Arc::new(DatabaseSessionForkCoordinator::new(
            pool.clone(),
            context.clone(),
        ));
        let state = state
            .with_auth_service(auth.clone())
            .with_session_service(sessions.clone())
            .with_session_fork_coordinator(forks.clone());
        let app = build_app(state.clone());
        let mut cases = Vec::new();
        for (name, token, edge) in [
            ("runtime", runtime_token, false),
            ("edge-registration", edge_token, true),
        ] {
            let headers = bearer_headers(&token);
            let principal = auth
                .current_principal(&headers)
                .await
                .expect("real token verification");
            assert!(matches!(
                &principal.origin,
                AuthPrincipalOrigin::ProviderAuthorizedRequest(_)
            ));
            assert_eq!(principal.is_edge_registration(), edge);
            assert_eq!(auth.current_user(&headers).await.unwrap(), principal.user);
            let request = SessionCreateRequestData {
                agent_id: None,
                title: Some(format!("credential fork auth {name}")),
                metadata: None,
            };
            let session = sessions
                .create_session(principal.user.user_id.clone(), request)
                .await
                .expect("canonical session owner creates parent");
            let key = SessionKeyV1::owner_session(
                "server",
                &principal.user.user_id,
                &session.session_id,
                "main",
            );
            let actor = ActorContextV1::owner_user(
                &principal.user.user_id,
                format!("legacy-{name}"),
                ActorKindV1::Server,
                SessionSurfaceV1::Server,
                None,
                AuthorityEpochsV1::default(),
            );
            let lease = match context
                .acquire_writer(&key, None, &actor, Duration::from_secs(60), "legacy-writer")
                .await
                .expect("acquire canonical writer")
            {
                AcquireWriterOutcome::Acquired(lease) => lease,
                other => panic!("unexpected writer result {other:?}"),
            };
            let reservation = match context
                .reserve_turn(&lease, None, Duration::from_secs(30), "legacy-turn", None)
                .await
                .expect("reserve canonical turn")
            {
                ReserveTurnOutcome::Reserved(reservation) => reservation,
                other => panic!("unexpected reservation result {other:?}"),
            };
            // The canonical commit is valid before the separate Server lifecycle
            // publishes agent_runs/transcript evidence. Do not hand-edit any
            // marker or principal: only the original canonical owner writes here.
            let delta = CanonicalTurnDeltaV1 {
                schema_version: CANONICAL_TURN_DELTA_SCHEMA_VERSION,
                completed_turn: 1,
                journal_event_seq: 1,
                conversation_seq: 1,
                compaction_generation: 0,
                config_version_id: None,
                mode: CanonicalDeltaModeV1::Append,
                logical_segments: vec![vec![
                    json!({"role":"user","content":format!("legacy {name} question")}),
                    json!({"role":"assistant","content":format!("legacy {name} answer")}),
                ]],
            };
            let cursor = match context
                .commit_turn_and_release_writer(&reservation, delta, "legacy-commit")
                .await
                .expect("commit canonical head without Server projection")
            {
                CoordinatorMutationV1::Applied { cursor } => cursor,
                other => panic!("unexpected commit result {other:?}"),
            };
            cases.push(LegacyCase {
                name,
                token,
                key,
                cursor,
            });
        }
        let fixture = Self {
            state,
            app,
            auth,
            sessions,
            context,
            forks,
            pool,
            database,
            admin,
            revocation_task,
            revocation_calls: calls,
            revocation_errors: errors,
            cases,
        };
        fixture.assert_canonical_without_server_projection().await;
        fixture
    }

    async fn assert_canonical_without_server_projection(&self) {
        for case in &self.cases {
            self.sessions
                .get_session(case.key.session_id.clone(), case.key.owner_user_id.clone())
                .await
                .expect("parent remains owned and live");
            let head = self
                .context
                .load_head(&case.key)
                .await
                .unwrap()
                .expect("committed head");
            assert_eq!(head.cursor, case.cursor);
            assert!(head.total_canonical_bytes > 0);
        }
        for table in ["agent_runs", "agent_run_events", "session_transcript_items"] {
            let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT COUNT(*) FROM `{table}`"
            )))
            .fetch_one(self.pool.get())
            .await
            .unwrap();
            assert_eq!(
                count, 0,
                "fixture must not invent Server lifecycle evidence in {table}"
            );
        }
        assert!(
            self.revocation_calls.load(Ordering::SeqCst) > 0,
            "real loopback revocation was exercised"
        );
        assert!(self.revocation_errors.lock().unwrap().is_empty());
    }

    async fn assert_no_forks_or_pins(&self) {
        for case in &self.cases {
            assert!(self.forks.list(&case.key, 10).await.unwrap().is_empty());
        }
        let pins: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM conversation_manifest_pins")
            .fetch_one(self.pool.get())
            .await
            .unwrap();
        assert_eq!(pins, 0, "denied auth cannot pin or allocate a child");
        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_sessions")
            .fetch_one(self.pool.get())
            .await
            .unwrap();
        assert_eq!(sessions, 2, "denied auth cannot create a child Session");
        self.assert_canonical_without_server_projection().await;
    }

    async fn cleanup(mut self) {
        self.state.close_database_pools().await;
        self.revocation_task.abort();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE `{}`",
            self.database
        )))
        .execute(&mut self.admin)
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real disposable MatrixOne; existing moi-user-token fork admission"]
async fn legacy_runtime_and_edge_tokens_prepare_before_server_projection() {
    let fixture = LegacyFixture::new().await;
    for case in &fixture.cases {
        let mut forged: Value =
            serde_json::from_str(&case.prepare_body("foreign-history-root")).unwrap();
        forged["expected_parent_cursor"]["canonical_root_hash"] = json!("0".repeat(64));
        let path = format!("/sessions/{}/forks", case.key.session_id);
        let (status, error) = response(&fixture.app, case.request(&path, forged.to_string())).await;
        assert_eq!(status, StatusCode::CONFLICT, "{error}");
        assert_eq!(error["error_code"], "session_fork_conflict");
    }
    fixture.assert_no_forks_or_pins().await;
    let mut observed = Vec::new();
    for case in &fixture.cases {
        let result = response(
            &fixture.app,
            case.prepare_request("legacy-compatible-intent"),
        )
        .await;
        eprintln!("legacy {} prepare: {} {}", case.name, result.0, result.1);
        observed.push(result);
    }
    // Record both real mechanisms before asserting; an edge-only exemption
    // must not hide the runtime-token compatibility regression.
    let mut outcomes = Vec::new();
    for (case, (status, manifest)) in fixture.cases.iter().zip(observed) {
        let activation = if status == StatusCode::OK {
            let path = format!(
                "/sessions/{}/forks/{}/activate",
                case.key.session_id,
                manifest["fork_id"].as_str().unwrap()
            );
            Some(
                response(
                    &fixture.app,
                    case.request(
                        &path,
                        json!({"placement":"server","writer_ttl_seconds":30}).to_string(),
                    ),
                )
                .await,
            )
        } else {
            None
        };
        outcomes.push((
            case.name,
            serde_json::to_value(&case.cursor).unwrap(),
            status,
            manifest,
            activation,
        ));
    }
    fixture.assert_canonical_without_server_projection().await;
    fixture.cleanup().await;
    for (name, cursor, status, manifest, activation) in outcomes {
        assert_eq!(
            status,
            StatusCode::OK,
            "{name} previously admitted prepare: {manifest}"
        );
        assert_eq!(manifest["parent_head"]["cursor"], cursor);
        let (status, active) = activation.expect("successful prepare must be activated");
        assert_eq!(status, StatusCode::OK, "{name} continuation: {active}");
        assert_eq!(active["manifest"]["state"], "active");
        assert_eq!(
            active["writer_lease"]["key"],
            active["manifest"]["child_key"]
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real disposable MatrixOne; new provider fork controls require request signing"]
async fn legacy_runtime_and_edge_tokens_cannot_use_new_provider_fork_controls() {
    let fixture = LegacyFixture::new().await;
    let mut observed = Vec::new();
    for case in &fixture.cases {
        for (method, path, body) in [
            (
                "GET",
                format!(
                    "/sessions/{}/runs/{}/cursor",
                    case.key.session_id,
                    Uuid::new_v4()
                ),
                "",
            ),
            (
                "POST",
                format!(
                    "/sessions/{}/forks/{}/activate-for-continuation",
                    case.key.session_id,
                    Uuid::new_v4()
                ),
                "{}",
            ),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {}", case.token))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let (status, body) = response(&fixture.app, request).await;
            observed.push((case.name, status, body));
        }
    }
    fixture.assert_no_forks_or_pins().await;
    fixture.cleanup().await;
    for (name, status, body) in observed {
        assert_eq!(status, StatusCode::FORBIDDEN, "{name}: {body}");
    }
}

struct RequestOnlyProviderAuth {
    real: Arc<DatabaseAuthService>,
    request_calls: AtomicUsize,
}

#[async_trait]
impl AuthService for RequestOnlyProviderAuth {
    async fn register(
        &self,
        request: AuthRegisterRequestData,
    ) -> Result<AuthUserRecord, (StatusCode, Json<ErrorResponse>)> {
        self.real.register(request).await
    }
    async fn login(
        &self,
        request: AuthLoginRequestData,
    ) -> Result<AuthTokenRecord, (StatusCode, Json<ErrorResponse>)> {
        self.real.login(request).await
    }
    async fn refresh(
        &self,
        request: AuthRefreshRequestData,
    ) -> Result<AuthTokenRecord, (StatusCode, Json<ErrorResponse>)> {
        self.real.refresh(request).await
    }
    async fn logout(
        &self,
        request: AuthRefreshRequestData,
    ) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
        self.real.logout(request).await
    }
    async fn current_user(
        &self,
        _headers: &HeaderMap,
    ) -> Result<AuthUserRecord, (StatusCode, Json<ErrorResponse>)> {
        panic!("request-only verifier must not fall back to current_user")
    }
    async fn current_principal_for_request(
        &self,
        headers: &HeaderMap,
        request: ProviderRequestDescriptor,
    ) -> Result<AuthPrincipal, (StatusCode, Json<ErrorResponse>)> {
        self.request_calls.fetch_add(1, Ordering::SeqCst);
        self.real
            .current_principal_for_request(headers, request)
            .await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real disposable MatrixOne; request-only provider adapter remains conservative"]
async fn request_only_provider_default_cannot_bypass_scope_or_retry_legacy_auth() {
    let fixture = LegacyFixture::new().await;
    let auth = Arc::new(RequestOnlyProviderAuth {
        real: fixture.auth.clone(),
        request_calls: AtomicUsize::new(0),
    });
    let app = build_app(fixture.state.clone().with_auth_service(auth.clone()));
    for case in &fixture.cases {
        let (status, error) = response(
            &app,
            case.prepare_request("unknown-mechanism-must-be-scoped"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "unspecified provider mechanism: {error}"
        );
        assert_eq!(error["error_code"], "session_fork_forbidden");
    }
    assert_eq!(
        auth.request_calls.load(Ordering::SeqCst),
        2,
        "verify once per request"
    );
    fixture.assert_no_forks_or_pins().await;
    for case in &fixture.cases {
        let mut request = case.prepare_request("malformed-provider-headers");
        request
            .headers_mut()
            .insert("x-astra-provider", "moi".parse().unwrap());
        let (status, error) = response(&fixture.app, request).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "partial provider headers cannot fall back: {error}"
        );
    }
    assert_real_request_auth_provenance(&fixture).await;
    fixture.assert_no_forks_or_pins().await;
    fixture.cleanup().await;
}

// Exercise the real DB verifier's mechanism evidence and shared durable replay
// guard. The first valid HMAC must succeed; verifying twice would consume its
// nonce before this result could be returned.
async fn assert_real_request_auth_provenance(fixture: &LegacyFixture) {
    let body = "{}";
    let descriptor = ProviderRequestDescriptor {
        method: "POST".into(),
        path: format!("/sessions/{}/forks", fixture.cases[0].key.session_id),
        route: Some("/sessions/{session_id}/forks".into()),
        request_id: Some(Uuid::new_v4().to_string()),
        body_digest: Some(format!("sha256:{:x}", Sha256::digest(body.as_bytes()))),
    };
    for case in &fixture.cases {
        let result = fixture
            .auth
            .current_principal_for_request_with_provenance(
                &bearer_headers(&case.token),
                descriptor.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            result.mechanism,
            RequestAuthMechanism::KnownLegacy,
            "{} provenance",
            case.name
        );
        assert_eq!(result.principal.user.user_id, case.key.owner_user_id);
    }
    let auth = fixture
        .auth
        .as_ref()
        .clone()
        .with_provider_request_auth(vec![ProviderRequestAuthConfig {
            provider: "moi".into(),
            auth_type: "hmac".into(),
            key: USER_TOKEN_KEY.into(),
        }]);
    let now = chrono::Utc::now().timestamp();
    let claims = json!({"provider":"moi","sub":"fork-hmac-user","scope":"legacy-workspace",
        "method":descriptor.method,"path":descriptor.path,"route":descriptor.route,
        "request_id":descriptor.request_id,"body_digest":descriptor.body_digest,
        "nonce":Uuid::new_v4().to_string(),"iat":now,"exp":now+300});
    let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
    let mut signer = Hmac::<Sha256>::new_from_slice(USER_TOKEN_KEY.as_bytes()).unwrap();
    signer.update(claims.as_bytes());
    let token = format!(
        "moi-provider-v1.{claims}.{}",
        URL_SAFE_NO_PAD.encode(signer.finalize().into_bytes())
    );
    let mut headers = bearer_headers(&token);
    headers.insert("x-astra-provider", "moi".parse().unwrap());
    headers.insert(
        "x-astra-provider-action",
        "authorize_request".parse().unwrap(),
    );
    let result = auth
        .current_principal_for_request_with_provenance(&headers, descriptor.clone())
        .await
        .expect("first valid HMAC verifies and consumes its nonce once");
    assert_eq!(result.mechanism, RequestAuthMechanism::RequestBoundHmac);
    assert!(matches!(
        result.principal.origin,
        AuthPrincipalOrigin::ProviderAuthorizedRequest(_)
    ));
    let replay = auth
        .current_principal_for_request(&headers, descriptor.clone())
        .await
        .unwrap_err();
    assert_eq!(
        replay.0,
        StatusCode::UNAUTHORIZED,
        "old and new methods share one replay guard"
    );
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM auth_provider_request_replay WHERE request_id = ?",
    )
    .bind(descriptor.request_id.as_ref().unwrap())
    .fetch_one(fixture.pool.get())
    .await
    .unwrap();
    assert_eq!(
        rows, 1,
        "exactly one durable authorization survives the replay rejection"
    );
    let stripped = auth
        .current_principal_for_request_with_provenance(&bearer_headers(&token), descriptor)
        .await
        .unwrap_err();
    assert_eq!(
        stripped.0,
        StatusCode::UNAUTHORIZED,
        "removing HMAC headers cannot turn it into a legacy credential"
    );
}
