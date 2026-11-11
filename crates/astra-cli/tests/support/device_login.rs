//! Real CLI process against synthetic UC/JWT/product endpoints. This does not
//! replace the separate real Keycloak and MOI deployment acceptance gate.
use astra_credentials::native::{Environment, NativeSession, NativeStore, unix_now};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Clone, Copy, PartialEq)]
enum Scenario {
    Success,
    BadNonce,
    PrepareFailure,
    CancelPending,
    CancelInFlight,
    DeadlineInFlight,
    WorkspaceCancel,
    CancelLock,
    LockTimeout,
}

async fn journey(scenario: Scenario) {
    static KEY: LazyLock<rsa::RsaPrivateKey> =
        LazyLock::new(|| rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap());
    let server = MockServer::start().await;
    let origin = server.uri();
    let issuer = format!("{origin}/realms/test");
    let environment = Environment {
        issuer: issuer.clone(),
        astra_url: origin.clone(),
        moi_url: origin.clone(),
        authorization_endpoint: format!("{origin}/authorize"),
        token_endpoint: format!("{issuer}/protocol/openid-connect/token"),
        revocation_endpoint: format!("{issuer}/protocol/openid-connect/revoke"),
        jwks_uri: format!("{issuer}/protocol/openid-connect/certs"),
    };
    let home = tempfile::tempdir().unwrap();
    let auth = home.path().join("auth");
    let store = NativeStore::with_directory(auth.clone());
    store.prepare_for_login().unwrap();
    store
        .publish(NativeSession {
            environment: environment.clone(),
            generation: String::new(),
            subject: "previous-user".into(),
            session_id: "old-session".into(),
            astra_user_id: "previous-astra".into(),
            moi_principal_id: "previous-moi".into(),
            catalog_user_id: "previous-catalog".into(),
            access_token: "old-access".into(),
            refresh_token: "old-refresh".into(),
            expires_at: unix_now().unwrap() + 3600,
            workspace_id: None,
            role_id: None,
            refresh_pending: false,
        })
        .unwrap();
    let before = std::fs::read(auth.join("auth.json")).unwrap();
    let form = Arc::new(Mutex::new(BTreeMap::<String, String>::new()));
    let revoked = Arc::new(Mutex::new(Vec::<String>::new()));
    let held_lock = Arc::new(Mutex::new(None::<std::fs::File>));
    let token_requested = Arc::new(tokio::sync::Notify::new());
    Mock::given(path("/auth/methods"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"uc": {
                "issuer": issuer, "client_id": "astra-cli", "moi_api_url": origin,
                "scope": "openid profile email astra:user aistudio:user", "resource": "astra-api"
            }})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/realms/test/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer, "authorization_endpoint": environment.authorization_endpoint,
            "token_endpoint": environment.token_endpoint, "revocation_endpoint": environment.revocation_endpoint,
            "jwks_uri": environment.jwks_uri,
            "device_authorization_endpoint": format!("{issuer}/protocol/openid-connect/auth/device")
        })))
        .expect(1).mount(&server).await;
    let request_form = form.clone();
    let grant_issuer = issuer.clone();
    Mock::given(method("POST"))
        .and(path("/realms/test/protocol/openid-connect/auth/device"))
        .respond_with(move |request: &wiremock::Request| {
            let parsed = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect::<BTreeMap<_, _>>();
            assert_eq!(parsed["client_id"], "astra-cli");
            assert_eq!(parsed["code_challenge_method"], "S256");
            assert!(!parsed["nonce"].is_empty());
            *request_form.lock().unwrap() = parsed;
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "synthetic-grant", "user_code": "ABCD-EFGH",
                "verification_uri": format!("{grant_issuer}/device"),
                "expires_in": if scenario == Scenario::DeadlineInFlight { 2 } else { 900 },
                "interval": 1
            }))
        })
        .expect(1)
        .mount(&server)
        .await;
    let token_form = form.clone();
    let token_issuer = issuer.clone();
    let requested = token_requested.clone();
    let der = KEY.to_pkcs1_der().unwrap();
    let encoding = jsonwebtoken::EncodingKey::from_rsa_der(der.as_bytes());
    Mock::given(method("POST"))
        .and(path("/realms/test/protocol/openid-connect/token"))
        .respond_with(move |request: &wiremock::Request| {
            let parsed = url::form_urlencoded::parse(&request.body).into_owned().collect::<BTreeMap<_, _>>();
            assert_eq!(parsed["device_code"], "synthetic-grant");
            assert_eq!(parsed["grant_type"], "urn:ietf:params:oauth:grant-type:device_code");
            let saved = token_form.lock().unwrap();
            assert_eq!(URL_SAFE_NO_PAD.encode(Sha256::digest(parsed["code_verifier"].as_bytes())), saved["code_challenge"]);
            requested.notify_one();
            if scenario == Scenario::CancelPending {
                return ResponseTemplate::new(400).set_body_json(serde_json::json!({"error": "authorization_pending"}));
            }
            let nonce = if scenario == Scenario::BadNonce { "wrong-nonce" } else { &saved["nonce"] };
            let now = unix_now().unwrap();
            let claims = serde_json::json!({"iss": token_issuer, "sub": "new-user", "aud": "astra-cli", "iat": now, "exp": now+300, "nonce": nonce});
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = Some("synthetic".into());
            let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access", "refresh_token": "new-refresh", "token_type": "Bearer", "expires_in": 300,
                "id_token": jsonwebtoken::encode(&header, &claims, &encoding).unwrap()
            }));
            if matches!(scenario, Scenario::CancelInFlight | Scenario::DeadlineInFlight) {
                response.set_delay(Duration::from_millis(1500))
            } else {
                response
            }
        }).expect(1).mount(&server).await;
    Mock::given(path("/realms/test/protocol/openid-connect/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"keys": [{
            "kty": "RSA", "alg": "RS256", "use": "sig", "kid": "synthetic",
            "n": URL_SAFE_NO_PAD.encode(KEY.n().to_bytes_be()), "e": URL_SAFE_NO_PAD.encode(KEY.e().to_bytes_be())
        }]}))).mount(&server).await;
    let moi_issuer = issuer.clone();
    let lock_for_bootstrap = held_lock.clone();
    let lock_path = auth.join("auth.lock");
    Mock::given(method("POST")).and(path("/auth/cli/bootstrap"))
        .and(header("authorization", "Bearer new-access"))
        .respond_with(move |_: &wiremock::Request| {
            if scenario == Scenario::PrepareFailure {
                return ResponseTemplate::new(503).set_body_json(serde_json::json!({"code":"unavailable", "msg":"Synthetic preparation failure"}));
            }
            if matches!(scenario, Scenario::CancelLock | Scenario::LockTimeout) {
                let lock = std::fs::OpenOptions::new().read(true).write(true).open(&lock_path).unwrap();
                FileExt::try_lock_exclusive(&lock).unwrap();
                *lock_for_bootstrap.lock().unwrap() = Some(lock);
            }
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"code":"OK", "data": {
                "issuer": moi_issuer, "subject":"new-user", "session_id":"new-session",
                "principal_id":"new-moi", "catalog_user_id":"new-catalog",
                "workspaces": if scenario == Scenario::WorkspaceCancel {
                    vec![serde_json::json!({"id":"workspace-1","name":"Workspace","status":"ACTIVE","access_status":"accepted"})]
                } else { Vec::new() },
                "workspace_initialization":{"status":"pending"}
            }}))
        }).mount(&server).await;
    Mock::given(method("POST")).and(path("/auth/uc/bootstrap"))
        .and(header("authorization", "Bearer new-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer, "subject":"new-user", "session_id":"new-session", "user_id":"new-astra"
        }))).mount(&server).await;
    let revocations = revoked.clone();
    Mock::given(method("POST"))
        .and(path("/realms/test/protocol/openid-connect/revoke"))
        .respond_with(move |request: &wiremock::Request| {
            let parsed = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect::<BTreeMap<_, _>>();
            revocations.lock().unwrap().push(parsed["token"].clone());
            ResponseTemplate::new(200)
        })
        .mount(&server)
        .await;

    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_astra"));
    command
        .current_dir(home.path())
        .env_clear()
        .env("HOME", home.path())
        .env("MOI_AUTH_DIR", &auth)
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_CACHE_HOME", home.path().join(".cache"))
        .env("XDG_DATA_HOME", home.path().join(".local/share"))
        .args(["--api-url", &origin, "login", "--device-code"])
        .env("TERM", "xterm-256color")
        .kill_on_drop(true);
    let mut master = if scenario == Scenario::WorkspaceCancel {
        let pty = nix::pty::openpty(None, None).unwrap();
        let slave = std::fs::File::from(pty.slave);
        command
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Some(std::fs::File::from(pty.master))
    } else {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        None
    };
    let mut child = command.spawn().unwrap();
    // Release the parent's slave descriptors so the PTY reader sees EOF when
    // the child exits.
    drop(command);
    let pid = nix::unistd::Pid::from_raw(child.id().unwrap() as i32);
    let lock_waiting = Arc::new(tokio::sync::Notify::new());
    let waiting = lock_waiting.clone();
    let prompt = Arc::new(tokio::sync::Notify::new());
    let saving = Arc::new(tokio::sync::Notify::new());
    let reader = if let Some(master) = &master {
        let mut terminal = master.try_clone().unwrap();
        let prompt = prompt.clone();
        let saving = saving.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut bytes = Vec::new();
            let mut chunk = [0; 1024];
            let mut saw_prompt = false;
            let mut saw_saving = false;
            while let Ok(count) = terminal.read(&mut chunk) {
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..count]);
                let text = String::from_utf8_lossy(&bytes);
                if !saw_prompt && text.contains("Select a MOI workspace") {
                    saw_prompt = true;
                    prompt.notify_one();
                }
                if !saw_saving && text.contains("Saving workspace selection") {
                    saw_saving = true;
                    saving.notify_one();
                }
            }
            String::from_utf8_lossy(&bytes).into_owned()
        })
    } else {
        let stderr = child.stderr.take().unwrap();
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            let mut output = String::new();
            while let Some(line) = lines.next_line().await.unwrap() {
                if line.contains("Waiting to save sign-in credentials") {
                    waiting.notify_one();
                }
                output.push_str(&line);
                output.push('\n');
            }
            output
        })
    };
    if scenario == Scenario::WorkspaceCancel {
        use std::io::Write;
        tokio::time::timeout(Duration::from_secs(15), prompt.notified())
            .await
            .unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(auth.join("auth.lock"))
            .unwrap();
        FileExt::try_lock_exclusive(&lock).unwrap();
        *held_lock.lock().unwrap() = Some(lock);
        master.as_mut().unwrap().write_all(b"\x1b[B\r").unwrap();
        tokio::time::timeout(Duration::from_secs(10), saving.notified())
            .await
            .unwrap();
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT).unwrap();
    }
    if matches!(
        scenario,
        Scenario::CancelPending | Scenario::CancelInFlight | Scenario::CancelLock
    ) {
        let ready = if matches!(scenario, Scenario::CancelPending | Scenario::CancelInFlight) {
            token_requested
        } else {
            lock_waiting
        };
        tokio::time::timeout(Duration::from_secs(15), ready.notified())
            .await
            .unwrap();
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT).unwrap();
    }
    let status = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("public login must exit even while the parent still holds auth.lock")
        .unwrap();
    let output = reader.await.unwrap();
    drop(held_lock.lock().unwrap().take());
    assert!(!output.contains("new-refresh") && !output.contains("old-refresh"));
    if matches!(
        scenario,
        Scenario::Success | Scenario::DeadlineInFlight | Scenario::WorkspaceCancel
    ) {
        assert!(status.success(), "{output}");
        let current = store.current().unwrap();
        assert_eq!(current.subject, "new-user");
        assert_eq!(current.session_id, "new-session");
        assert_eq!(current.moi_principal_id, "new-moi");
        assert_eq!(current.workspace_id, None);
        assert_eq!(*revoked.lock().unwrap(), vec!["old-refresh"]);
    } else {
        assert!(!status.success(), "{output}");
        assert_eq!(std::fs::read(auth.join("auth.json")).unwrap(), before);
        if scenario == Scenario::CancelPending {
            assert!(revoked.lock().unwrap().is_empty());
        } else {
            assert_eq!(*revoked.lock().unwrap(), vec!["new-refresh"]);
        }
        if scenario == Scenario::LockTimeout {
            assert!(output.contains("Timed out waiting to publish"));
        }
        if scenario == Scenario::CancelLock {
            assert!(
                output.contains("stopped before credential publication"),
                "{output}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_success_verifies_nonce_pkce_and_publishes() {
    journey(Scenario::Success).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_bad_nonce_preserves_previous_session() {
    journey(Scenario::BadNonce).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_prepare_failure_preserves_previous_session() {
    journey(Scenario::PrepareFailure).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_pending_can_be_interrupted() {
    journey(Scenario::CancelPending).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_inflight_cancel_revokes_received_token() {
    journey(Scenario::CancelInFlight).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_headers_after_deadline_still_settle() {
    journey(Scenario::DeadlineInFlight).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_workspace_lock_can_be_cancelled_after_login() {
    journey(Scenario::WorkspaceCancel).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_lock_wait_can_be_interrupted_without_late_commit() {
    journey(Scenario::CancelLock).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_login_public_lock_wait_has_a_deadline() {
    journey(Scenario::LockTimeout).await;
}
