use super::*;
use std::sync::atomic::Ordering;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn environment(server: &MockServer) -> Environment {
    let issuer = format!("{}/realms/test", server.uri());
    Environment {
        issuer: issuer.clone(),
        astra_url: server.uri(),
        moi_url: server.uri(),
        authorization_endpoint: format!("{}/authorize", server.uri()),
        token_endpoint: format!("{issuer}/protocol/openid-connect/token"),
        revocation_endpoint: format!("{issuer}/protocol/openid-connect/revoke"),
        jwks_uri: format!("{issuer}/protocol/openid-connect/certs"),
    }
}

fn grant(issuer: &str) -> DeviceAuthorization {
    DeviceAuthorization {
        device_code: "memory-only-grant".into(),
        user_code: "ABCD-EFGH".into(),
        verification_uri: format!("{issuer}/device"),
        expires_in: 600,
        interval: 1,
    }
}

#[test]
fn device_endpoints_cannot_change_origin_or_escape_the_fixed_protocol() {
    let issuer = "https://uc.example.test/api/v1/uc/realms/moi";
    assert!(issuer_endpoint(&format!("{issuer}/device"), issuer, "/device").is_ok());
    for target in [
        "https://other.example.test/api/v1/uc/realms/moi/device",
        "http://uc.example.test/api/v1/uc/realms/moi/device",
        "https://uc.example.test/api/v1/uc/realms/other/device",
        "https://uc.example.test/api/v1/uc/realms/moi/device?user_code=automatic",
        "https://uc.example.test/api/v1/uc/realms/moi/device#fragment",
        "https://user:password@uc.example.test/api/v1/uc/realms/moi/device",
    ] {
        assert!(issuer_endpoint(target, issuer, "/device").is_err());
    }
}

#[test]
fn invalid_device_codes_and_zero_lifetimes_are_rejected() {
    let issuer = "https://uc.example.test/realms/moi";
    assert!(grant(issuer).validate(issuer).is_ok());
    let mut value = grant(issuer);
    value.expires_in = 0;
    assert!(value.validate(issuer).is_err());
    for code in [
        "",
        "short",
        "ABCD\nEFGH",
        "\u{1b}[31mABCD",
        "https://other.example",
    ] {
        let mut value = grant(issuer);
        value.user_code = code.into();
        assert!(value.validate(issuer).is_err());
    }
    let mut value = grant(issuer);
    value.device_code = "x".repeat(4097);
    assert!(value.validate(issuer).is_err());
    value = grant(issuer);
    value.interval = 0;
    assert!(value.validate(issuer).is_err());
}

#[test]
fn longer_server_lifetimes_limit_waiting_without_claiming_expiry() {
    let issuer = "https://uc.example.test/realms/moi";
    for lifetime in [1, 600, 601, u64::MAX] {
        let mut value = grant(issuer);
        value.expires_in = lifetime;
        assert!(value.validate(issuer).is_ok());
        assert_eq!(value.wait_duration().as_secs(), lifetime.min(600));
        assert!(value.deadline_error().contains("Stopped waiting"));
        assert!(!value.deadline_error().contains("expired"));
    }
}

#[tokio::test]
async fn authorization_failures_distinguish_throttling_availability_and_rejection() {
    for (status, expected) in [
        (429, "Too many device sign-in requests"),
        (500, "temporarily unavailable"),
        (503, "temporarily unavailable"),
        (400, "was rejected"),
        (403, "was rejected"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(status).set_body_string("DO_NOT_RENDER_THIS"))
            .expect(1)
            .mount(&server)
            .await;
        let response = native::http_client()
            .unwrap()
            .post(server.uri())
            .send()
            .await
            .unwrap();
        let error = authorization_response(response, &environment(&server).issuer)
            .await
            .err()
            .unwrap();
        assert!(error.contains(expected));
        assert!(error.contains("no local session was changed"));
        assert!(!error.contains("DO_NOT_RENDER"));
    }
}

#[tokio::test]
async fn longer_authorization_response_is_accepted_and_wait_is_bounded() {
    let server = MockServer::start().await;
    let issuer = environment(&server).issuer;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "memory-only-grant", "user_code": "ABCD-EFGH",
            "verification_uri": format!("{issuer}/device"), "expires_in": 900
        })))
        .expect(1)
        .mount(&server)
        .await;
    let response = native::http_client()
        .unwrap()
        .post(server.uri())
        .send()
        .await
        .unwrap();
    let value = authorization_response(response, &issuer).await.unwrap();
    assert_eq!(value.expires_in, 900);
    assert_eq!(value.wait_duration(), Duration::from_secs(600));
}

#[test]
fn missing_poll_interval_uses_the_rfc_default() {
    let value: DeviceAuthorization = serde_json::from_value(serde_json::json!({
        "device_code": "not-persisted", "user_code": "ABCD-EFGH",
        "verification_uri": "https://uc.example.test/realms/moi/device", "expires_in": 600
    }))
    .unwrap();
    assert_eq!(value.interval, 5);
}

#[test]
fn slowdown_is_permanent_and_connection_backoff_is_bounded() {
    let mut policy = PollPolicy::new(5);
    policy.slow_down();
    assert_eq!(policy.interval, Duration::from_secs(10));
    policy.pending();
    assert_eq!(policy.delay, Duration::from_secs(10));
    policy.unavailable();
    assert_eq!(policy.delay, Duration::from_secs(20));
    policy.unavailable();
    assert_eq!(policy.delay, Duration::from_secs(40));
    policy.unavailable();
    assert_eq!(policy.delay, Duration::from_secs(60));
    policy.pending();
    assert_eq!(policy.delay, Duration::from_secs(10));
}

#[tokio::test]
async fn expiry_stops_before_another_poll_request() {
    let server = MockServer::start().await;
    let environment = environment(&server);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let result = poll(
        &native::http_client().unwrap(),
        &environment,
        &grant(&environment.issuer),
        "private-verifier",
        &mut super::super::LoginInterrupt::new().unwrap(),
        Instant::now() + Duration::from_millis(20),
    )
    .await;
    assert!(matches!(result, Err(error) if error.contains("Stopped waiting")));
}

#[tokio::test]
async fn local_wait_timeout_does_not_claim_the_server_grant_expired() {
    let server = MockServer::start().await;
    let environment = environment(&server);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let mut value = grant(&environment.issuer);
    value.expires_in = u64::MAX;
    value.interval = u64::MAX;
    let error = poll(
        &native::http_client().unwrap(),
        &environment,
        &value,
        "private-verifier",
        &mut super::super::LoginInterrupt::new().unwrap(),
        Instant::now() + Duration::from_millis(20),
    )
    .await
    .err()
    .unwrap();
    assert!(error.contains("Stopped waiting"));
}

#[tokio::test]
async fn slowdown_is_not_shortened_for_a_final_poll() {
    let server = MockServer::start().await;
    let environment = environment(&server);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "slow_down"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let deadline = Instant::now() + Duration::from_secs(2);
    let result = poll(
        &native::http_client().unwrap(),
        &environment,
        &grant(&environment.issuer),
        "private-verifier",
        &mut super::super::LoginInterrupt::new().unwrap(),
        deadline,
    )
    .await;
    assert!(matches!(result, Err(error) if error.contains("Stopped waiting")));
    assert!(Instant::now() >= deadline);
}

#[tokio::test]
async fn ambiguous_server_failures_are_not_replayed() {
    for response in [
        ResponseTemplate::new(429),
        ResponseTemplate::new(503),
        ResponseTemplate::new(400)
            .set_body_json(serde_json::json!({"error": "temporarily_unavailable"})),
    ] {
        let server = MockServer::start().await;
        let environment = environment(&server);
        Mock::given(method("POST"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let result = poll(
            &native::http_client().unwrap(),
            &environment,
            &grant(&environment.issuer),
            "private-verifier",
            &mut super::super::LoginInterrupt::new().unwrap(),
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        assert!(matches!(result, Err(error) if error == TOKEN_UNCONFIRMED));
    }
}

#[tokio::test]
async fn server_expiry_is_terminal_even_when_local_wait_would_be_longer() {
    let server = MockServer::start().await;
    let environment = environment(&server);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "expired_token"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut value = grant(&environment.issuer);
    value.expires_in = 900;
    let result = poll(
        &native::http_client().unwrap(),
        &environment,
        &value,
        "private-verifier",
        &mut super::super::LoginInterrupt::new().unwrap(),
        Instant::now() + Duration::from_secs(10),
    )
    .await;
    assert!(matches!(result, Err(error) if error == EXPIRED));
}

#[tokio::test]
async fn denial_does_not_expose_upstream_text_or_retry() {
    let server = MockServer::start().await;
    let environment = environment(&server);
    Mock::given(method("POST"))
        .and(path("/realms/test/protocol/openid-connect/token"))
        .and(body_string_contains("device_code=memory-only-grant"))
        .and(body_string_contains("code_verifier=private-verifier"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "access_denied", "error_description": "DO_NOT_RENDER_THIS"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let result = poll(
        &native::http_client().unwrap(),
        &environment,
        &grant(&environment.issuer),
        "private-verifier",
        &mut super::super::LoginInterrupt::new().unwrap(),
        Instant::now() + Duration::from_secs(10),
    )
    .await;
    assert!(
        matches!(result, Err(error) if error.contains("denied") && !error.contains("DO_NOT_RENDER"))
    );
}

#[tokio::test]
async fn a_successful_but_invalid_token_body_is_not_replayed() {
    let server = MockServer::start().await;
    let environment = environment(&server);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not JSON"))
        .expect(1)
        .mount(&server)
        .await;
    let result = poll(
        &native::http_client().unwrap(),
        &environment,
        &grant(&environment.issuer),
        "private-verifier",
        &mut super::super::LoginInterrupt::new().unwrap(),
        Instant::now() + Duration::from_secs(10),
    )
    .await;
    assert!(matches!(result, Err(error) if error == TOKEN_UNCONFIRMED));
}

#[tokio::test]
async fn successful_headers_before_deadline_allow_body_to_settle_after_deadline() {
    use axum::{Router, body::Body, routing::post};
    use futures_util::StreamExt;
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route("/token", post(move || {
        let observed = observed.clone();
        async move {
            observed.fetch_add(1, Ordering::SeqCst);
            let prefix = futures_util::stream::once(async { Ok::<_, Infallible>("{") });
            let suffix = futures_util::stream::once(async {
                tokio::time::sleep(Duration::from_millis(700)).await;
                Ok::<_, Infallible>(r#""access_token":"test-access","refresh_token":"test-refresh","expires_in":300,"token_type":"Bearer","id_token":"test-id"}"#)
            });
            Body::from_stream(prefix.chain(suffix))
        }
    }));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let environment = Environment {
        issuer: origin.clone(),
        astra_url: origin.clone(),
        moi_url: origin.clone(),
        authorization_endpoint: format!("{origin}/authorize"),
        token_endpoint: format!("{origin}/token"),
        revocation_endpoint: format!("{origin}/revoke"),
        jwks_uri: format!("{origin}/certs"),
    };
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut interrupt = super::super::LoginInterrupt::new().unwrap();
    let result = poll(
        &native::http_client().unwrap(),
        &environment,
        &grant(&environment.issuer),
        "private-verifier",
        &mut interrupt,
        deadline,
    )
    .await;
    server.abort();
    assert_eq!(result.unwrap().access_token, "test-access");
    assert!(Instant::now() > deadline);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn pending_then_success_submits_the_same_grant_and_verifier() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let server = MockServer::start().await;
    let environment = environment(&server);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    Mock::given(method("POST"))
        .and(body_string_contains("device_code=memory-only-grant"))
        .and(body_string_contains("code_verifier=private-verifier"))
        .respond_with(move |_: &wiremock::Request| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": "authorization_pending"
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "test-access", "refresh_token": "test-refresh",
                    "expires_in": 300, "token_type": "Bearer", "id_token": "test-id"
                }))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let tokens = poll(
        &native::http_client().unwrap(),
        &environment,
        &grant(&environment.issuer),
        "private-verifier",
        &mut super::super::LoginInterrupt::new().unwrap(),
        Instant::now() + Duration::from_secs(15),
    )
    .await
    .unwrap();
    assert_eq!(tokens.access_token, "test-access");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn delayed_wakeup_does_not_start_an_exchange_after_the_deadline() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/realms/test/protocol/openid-connect/token"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let environment = environment(&server);
    let deadline = Instant::now() + Duration::from_secs(2);
    let grant = grant(&environment.issuer);
    let client = native::http_client().unwrap();
    let mut interrupt = super::super::LoginInterrupt::new().unwrap();
    let request = poll(
        &client,
        &environment,
        &grant,
        "private-verifier",
        &mut interrupt,
        deadline,
    );
    tokio::pin!(request);
    // Poll once to ensure the interval timer is registered before time moves.
    assert!(matches!(
        futures_util::poll!(&mut request),
        std::task::Poll::Pending
    ));
    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(matches!(request.await, Err(error) if error.contains("Stopped waiting")));
}

#[tokio::test]
async fn optional_device_metadata_does_not_break_existing_browser_discovery() {
    for extra in [
        None,
        Some(serde_json::json!(false)),
        Some(serde_json::json!("https://other.example.test/device")),
    ] {
        let server = MockServer::start().await;
        let environment = environment(&server);
        let discovery = UcDiscovery {
            issuer: environment.issuer.clone(),
            client_id: "astra-cli".into(),
            moi_api_url: server.uri(),
            scope: "openid profile email astra:user aistudio:user".into(),
            resource: "astra-api".into(),
        };
        let mut metadata = serde_json::json!({
            "issuer": environment.issuer,
            "authorization_endpoint": environment.authorization_endpoint,
            "token_endpoint": environment.token_endpoint,
            "revocation_endpoint": environment.revocation_endpoint,
            "jwks_uri": environment.jwks_uri,
        });
        if let Some(extra) = extra {
            metadata["device_authorization_endpoint"] = extra;
        }
        Mock::given(path("/realms/test/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .expect(1)
            .mount(&server)
            .await;
        let api = astra_thin_client::ThinClient::new(&server.uri(), None).unwrap();
        let (_, _, device) = super::super::discover_environment(&api, &discovery)
            .await
            .unwrap();
        assert!(
            device.is_none_or(|value| value.as_str().is_none_or(|value| {
                issuer_endpoint(
                    value,
                    &discovery.issuer,
                    "/protocol/openid-connect/auth/device",
                )
                .is_err()
            }))
        );
    }
}
