use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn server() -> (AcpServer, Arc<std::sync::Mutex<Vec<Value>>>) {
    let output = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = output.clone();
    let writer = JsonWriter::start(move |line| {
        sink.lock()
            .unwrap()
            .push(serde_json::from_str(line).unwrap());
        Ok(())
    });
    let server = AcpServer::new(
        ServerContext {
            api: astra_thin_client::ThinClient::new("http://127.0.0.1:1", None).unwrap(),
            auth_profile: None,
            default_model: None,
            system_prompt: None,
            auto_approve: false,
        },
        writer,
    )
    .unwrap();
    (server, output)
}

async fn initialize(server: &mut AcpServer) {
    server
        .receive(
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1}})
                .to_string(),
        )
        .await
        .unwrap();
}

fn install_session(server: &mut AcpServer, id: &str) -> Arc<Mutex<AppState>> {
    let state = Arc::new(Mutex::new(AppState {
        thread_id: Some(id.into()),
        ..Default::default()
    }));
    server.sessions.insert(
        id.into(),
        Session {
            state: state.clone(),
            model: None,
            models: std::collections::HashSet::from(["test-offering".into()]),
            offering_id: None,
            mcp_servers: vec![],
        },
    );
    state
}

#[tokio::test]
async fn handshake_matches_openmausbot_v1_and_requires_initialization() {
    let (mut server, output) = server();
    server
        .receive(r#"{"jsonrpc":"2.0","id":"early","method":"session/new","params":{}}"#)
        .await
        .unwrap();
    initialize(&mut server).await;
    let output = output.lock().unwrap();
    assert_eq!(output[0]["error"]["code"], -32600);
    assert_eq!(output[1]["result"]["protocolVersion"], 1);
    assert_eq!(
        output[1]["result"]["agentCapabilities"]["loadSession"],
        true
    );
    assert_eq!(
        output[1]["result"]["agentCapabilities"]["promptCapabilities"]["image"],
        false
    );
    assert_eq!(output[1]["jsonrpc"], "2.0");
}

#[tokio::test]
async fn malformed_requests_and_notifications_do_not_admit_work() {
    let (mut server, output) = server();
    server.receive("{").await.unwrap();
    server
        .receive(r#"{"id":4,"method":"initialize"}"#)
        .await
        .unwrap();
    initialize(&mut server).await;
    server
        .receive(r#"{"jsonrpc":"2.0","method":"session/new","params":{}}"#)
        .await
        .unwrap();
    server
        .receive(r#"{"jsonrpc":"2.0","id":5,"method":"unknown"}"#)
        .await
        .unwrap();
    assert!(server.sessions.is_empty());
    let output = output.lock().unwrap();
    assert_eq!(output.len(), 4);
    assert_eq!(output[0]["error"]["code"], -32700);
    assert_eq!(output[1]["error"]["code"], -32600);
    assert_eq!(output[3]["error"]["code"], -32601);
}

#[test]
fn workspace_is_process_scoped_without_chdir() {
    let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
    assert!(validate_cwd(&json!({"cwd":cwd}), &cwd).is_ok());
    assert!(validate_cwd(&json!({"cwd":"."}), &cwd).is_err());
    assert!(validate_cwd(&json!({"cwd":"/"}), &cwd).is_err());
    assert_eq!(
        std::env::current_dir().unwrap().canonicalize().unwrap(),
        cwd
    );
}

#[test]
fn unsupported_prompt_blocks_fail_before_partial_text_is_used() {
    assert_eq!(
        prompt_text(&json!({"prompt":[{"type":"text","text":"one"},{"type":"text","text":"two"}]}))
            .unwrap(),
        "one\ntwo"
    );
    for prompt in [
        json!([]),
        json!([{"type":"text","text":" "}]),
        json!([{"type":"text","text":"one"},{"type":"image","data":"x"}]),
        json!([{"type":"text"}]),
    ] {
        assert!(prompt_text(&json!({"prompt":prompt})).is_err());
    }
}

#[test]
fn client_mcp_configuration_is_typed_and_secrets_are_not_in_errors() {
    let configs = parse_mcp_servers(&json!({"mcpServers":[
        {"name":"tools","command":"/bin/test","args":["--stdio"],"env":[{"name":"TEST_KEY","value":"secret-value"}]},
        {"type":"http","name":"http","url":"http://127.0.0.1:1234/mcp","headers":[{"name":"Authorization","value":"secret-value"}]},
        {"type":"sse","name":"sse","url":"http://127.0.0.1:1234/sse","headers":[]}
    ]})).unwrap();
    assert!(
        matches!(&configs[0].transport,astra_mcp::Transport::Stdio{command,env,..} if command == &vec!["/bin/test".to_string()] && env["TEST_KEY"] == "secret-value")
    );
    assert!(
        matches!(&configs[1].transport,astra_mcp::Transport::StreamableHttp{headers,..} if headers["Authorization"] == "secret-value")
    );
    assert!(matches!(
        &configs[2].transport,
        astra_mcp::Transport::Sse { .. }
    ));
    for servers in [
        json!([{ "name":"a","type":"invalid","secret":"secret-value"}]),
        json!([
            {"name":"same","command":"test","args":[],"env":[]},
            {"name":"same","command":"test","args":[],"env":[]}
        ]),
    ] {
        let error = parse_mcp_servers(&json!({"mcpServers":servers})).unwrap_err();
        assert!(!error.to_string().contains("secret-value"));
    }
    assert!(parse_mcp_servers(&json!({})).is_err());
}

#[tokio::test]
async fn approvals_are_one_shot_and_cancel_denies_pending_requests() {
    let (mut server, _) = server();
    let state = install_session(&mut server, "session");
    let cancel = Arc::new(CancellationToken::new());
    begin_turn(&mut *state.lock().await, None, "turn", cancel.clone(), None).unwrap();
    let (tx, rx) = oneshot::channel();
    register_pending_approval(&state, "approve", "turn", tx).await;
    server.permission_response(&json!({"id":"astra-permission/approve","result":{"outcome":{"outcome":"selected","optionId":"allow_once"}}})).await;
    assert!(matches!(rx.await.unwrap(), ApprovalResponse::AllowOnce));
    let (tx, rx) = oneshot::channel();
    register_pending_approval(&state, "invalid", "turn", tx).await;
    server.permission_response(&json!({"id":"astra-permission/invalid","result":{"outcome":{"outcome":"selected","optionId":"always"}}})).await;
    assert!(matches!(rx.await.unwrap(), ApprovalResponse::Deny));
    let (tx, rx) = oneshot::channel();
    register_pending_approval(&state, "cancel", "turn", tx).await;
    cancel_session(&state).await;
    assert!(cancel.is_cancelled());
    assert!(matches!(rx.await.unwrap(), ApprovalResponse::Deny));
    // A late allow cannot resurrect a cancelled approval.
    server.permission_response(&json!({"id":"astra-permission/cancel","result":{"outcome":{"outcome":"selected","optionId":"allow_once"}}})).await;
    assert!(state.lock().await.pending_approvals.is_empty());
}

#[tokio::test]
async fn cancellation_targets_only_the_selected_session() {
    let (mut server, output) = server();
    initialize(&mut server).await;
    let first = install_session(&mut server, "one");
    let second = install_session(&mut server, "two");
    let a = Arc::new(CancellationToken::new());
    let b = Arc::new(CancellationToken::new());
    begin_turn(&mut *first.lock().await, None, "a", a.clone(), None).unwrap();
    begin_turn(&mut *second.lock().await, None, "b", b.clone(), None).unwrap();
    server
        .receive(r#"{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"one"}}"#)
        .await
        .unwrap();
    assert!(a.is_cancelled());
    assert!(!b.is_cancelled());
    assert_eq!(
        output.lock().unwrap().len(),
        1,
        "notifications have no response"
    );
    server.shutdown().await;
    assert!(b.is_cancelled());
}

#[tokio::test]
async fn model_changes_are_validated_and_rejected_while_busy() {
    let (mut server, _) = server();
    initialize(&mut server).await;
    let state = install_session(&mut server, "session");
    assert!(
        server
            .dispatch(
                "session/set_model",
                &json!({"sessionId":"session","modelId":"test-offering"}),
                Some(json!(1))
            )
            .await
            .is_ok()
    );
    assert_eq!(
        server.sessions["session"].model.as_deref(),
        Some("test-offering")
    );
    assert_eq!(
        server.sessions["session"].offering_id.as_deref(),
        Some("test-offering")
    );
    assert!(
        server
            .dispatch(
                "session/set_model",
                &json!({"sessionId":"session","modelId":"invented"}),
                Some(json!(2))
            )
            .await
            .is_err()
    );
    begin_turn(
        &mut *state.lock().await,
        None,
        "turn",
        Arc::new(CancellationToken::new()),
        None,
    )
    .unwrap();
    assert!(
        server
            .dispatch(
                "session/set_model",
                &json!({"sessionId":"session","modelId":"agent-default"}),
                Some(json!(3))
            )
            .await
            .is_err()
    );
}

#[test]
fn output_deduplicates_final_text_and_finishes_after_settlement() {
    let mut output = TurnProjection::new("session");
    let delta =
        output.project(json!({"method":"item/agentMessage/delta","params":{"delta":"hello"}}));
    assert_eq!(delta[0]["params"]["update"]["content"]["text"], "hello");
    let suffix = output.project(json!({"method":"item/completed","params":{"item":{"type":"agentMessage","text":"hello world"}}}));
    assert_eq!(suffix[0]["params"]["update"]["content"]["text"], " world");
    assert!(output.project(json!({"method":"item/completed","params":{"item":{"type":"agentMessage","text":"hello world"}}})).is_empty());
    assert!(
        output
            .project(json!({"method":"turn/completed","params":{"status":"completed"}}))
            .is_empty()
    );
    assert_eq!(
        output.finish(json!(42), Ok(()), false)["result"]["stopReason"],
        "end_turn"
    );
}

#[test]
fn failed_and_uncertain_settlement_never_looks_successful() {
    let mut output = TurnProjection::new("session");
    output.project(json!({"method":"error","params":{"message":"provider failed"}}));
    output.project(json!({"method":"turn/completed","params":{"status":"failed"}}));
    assert_eq!(
        output.finish(json!(1), Ok(()), false)["error"]["data"]["message"],
        "provider failed"
    );
    let mut failure = AppServerFailure::turn_failed("commit unknown");
    failure.code = SESSION_COMMIT_UNKNOWN_CODE;
    failure.commit_unknown = true;
    let response = output.finish(json!(2), Err(failure), true);
    assert_eq!(response["error"]["data"]["commitUnknown"], true);
    assert!(response.get("result").is_none());
    assert_eq!(
        output.finish(json!(3), Ok(()), true)["result"]["stopReason"],
        "cancelled"
    );
}

#[test]
fn parallel_tool_calls_keep_their_runtime_identity_and_failure_status() {
    let mut output = TurnProjection::new("session");
    for id in ["call-a", "call-b"] {
        let updates = output.project(json!({"method":"item/started","params":{"item":{"type":"dynamicToolCall","id":id,"name":"Bash","input":{"description":"test"}}}}));
        assert_eq!(updates[0]["params"]["update"]["toolCallId"], id);
        assert_eq!(updates[0]["params"]["update"]["sessionUpdate"], "tool_call");
    }
    let updates = output.project(json!({"method":"item/completed","params":{"item":{"type":"dynamicToolCall","id":"call-b","name":"Bash","status":"failed"}}}));
    assert_eq!(updates[0]["params"]["update"]["toolCallId"], "call-b");
    assert_eq!(updates[0]["params"]["update"]["status"], "failed");
    let duplicate = output.project(json!({"method":"item/started","params":{"item":{"type":"dynamicToolCall","id":"call-a","name":"agent"}}}));
    assert_eq!(
        duplicate[0]["params"]["update"]["sessionUpdate"],
        "tool_call_update"
    );
    let rejected = output.project(json!({"method":"item/completed","params":{"item":{"type":"dynamicToolCall","id":"rejected","name":"Bash","status":"denied"}}}));
    assert_eq!(
        rejected[0]["params"]["update"]["sessionUpdate"],
        "tool_call"
    );
    assert_eq!(rejected[0]["params"]["update"]["status"], "failed");
}

#[test]
fn replay_excludes_system_and_tool_payloads() {
    let updates = projection::replay(
        "session",
        &[
            json!({"role":"system","content":"private instructions"}),
            json!({"role":"user","content":"question"}),
            json!({"role":"assistant","content":[{"type":"text","text":"answer"},{"type":"tool_use","input":"private"}]}),
            json!({"role":"tool","content":"private tool output"}),
        ],
    );
    assert_eq!(updates.len(), 2);
    assert_eq!(
        updates[0]["params"]["update"]["sessionUpdate"],
        "user_message_chunk"
    );
    assert_eq!(updates[1]["params"]["update"]["content"]["text"], "answer");
}

#[serial_test::serial]
#[tokio::test]
async fn new_session_uses_server_identity_and_authoritative_model_catalog() {
    use crate::cli::cli_config::cli_utils::{CredentialsFile, Profile, save_credentials};
    let _home = crate::test_utils::HomeGuard::temp();
    let _credentials = crate::tests::isolate_credentials();
    let mut creds = CredentialsFile::default();
    creds.profiles.insert(
        "default".into(),
        Profile {
            account_id: Some("test-owner".into()),
            access_token: Some("test-token".into()),
            ..Default::default()
        },
    );
    save_credentials(&creds).unwrap();
    let mock = MockServer::start().await;
    let id = uuid::Uuid::new_v4().to_string();
    let catalog: Vec<_> = ["offer-one", "offer-two"]
        .into_iter()
        .map(|id| astra_services::ModelListItemResponse {
            offering_id: id.into(),
            name: "Same display name".into(),
            provider: "openai".into(),
            access_id: "self-hosted".into(),
            access_kind: astra_services::models::ModelAccessKind::SelfHosted,
            access_label: "Self-hosted".into(),
            execution_placement: astra_services::models::ModelExecutionPlacement::Server,
            is_active: true,
            context_window: 128000,
            description: None,
            max_completion_tokens: None,
            architecture: None,
            thinking_capability: None,
            pricing: None,
            thinking_protocol: None,
        })
        .collect();
    Mock::given(method("POST"))
        .and(path("/sessions"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"session_id":id})))
        .expect(1)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"items":catalog,"limit":200,"total":2,"catalog_revision":"test","next_cursor":null}),
        ))
        .expect(1)
        .mount(&mock)
        .await;
    let (mut server, output) = server();
    server.ctx.api = astra_thin_client::ThinClient::new(&mock.uri(), None).unwrap();
    server.ctx.auth_profile = Some("default".into());
    initialize(&mut server).await;
    server.receive(&json!({"jsonrpc":"2.0","id":"new","method":"session/new","params":{"cwd":server.cwd,"mcpServers":[]}}).to_string()).await.unwrap();
    assert!(server.sessions.contains_key(&id));
    assert_eq!(output.lock().unwrap()[1]["result"]["sessionId"], id);
    assert_eq!(
        output.lock().unwrap()[1]["result"]["models"]["currentModelId"],
        "agent-default"
    );
    assert!(
        server.tasks.is_empty(),
        "model discovery must never start a model turn"
    );
    assert_eq!(
        output.lock().unwrap()[1]["result"]["models"]["availableModels"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    server
        .dispatch(
            "session/set_model",
            &json!({"sessionId":id,"modelId":"offer-two"}),
            Some(json!(3)),
        )
        .await
        .unwrap();
    let selected = session_runtime::resolve_server_model_selection_from_catalog(
        server.sessions[&id].model.as_deref().unwrap(),
        &catalog,
    )
    .unwrap();
    assert_eq!(selected.offering_id, "offer-two");
    server
        .dispatch(
            "session/set_model",
            &json!({"sessionId":id,"modelId":"agent-default"}),
            Some(json!(4)),
        )
        .await
        .unwrap();
    assert!(server.sessions[&id].model.is_none());
    assert!(server.sessions[&id].offering_id.is_none());
    mock.verify().await;
}

#[test]
fn resource_links_are_carried_as_references_without_eager_access() {
    let message = prompt_text(&json!({"prompt":[{"type":"resource_link","name":"source.rs","uri":"file:///workspace/source.rs"}]})).unwrap();
    assert!(message.contains("file:///workspace/source.rs"));
    assert!(
        prompt_text(&json!({"prompt":[{"type":"resource_link","name":"x","uri":"not-a-uri"}]}))
            .is_err()
    );
}

#[test]
fn replay_includes_canonical_tool_calls_and_results() {
    let updates = projection::replay(
        "session",
        &[
            json!({"role":"assistant","content":null,"tool_calls":[{"id":"call","function":{"name":"Read","arguments":"{\"path\":\"source.rs\"}"}}]}),
            json!({"role":"tool","tool_call_id":"call","content":"source text"}),
        ],
    );
    assert_eq!(updates.len(), 2);
    assert_eq!(
        updates[0]["params"]["update"]["rawInput"]["path"],
        "source.rs"
    );
    assert_eq!(updates[1]["params"]["update"]["rawOutput"], "source text");
}

#[serial_test::serial]
#[tokio::test]
async fn public_prompt_stays_pending_and_cancel_releases_runtime_lease() {
    use crate::cli::cli_config::cli_utils::{CredentialsFile, Profile, save_credentials};
    let _home = crate::test_utils::HomeGuard::temp();
    let _registry = crate::test_utils::ProcessEnvGuard::remove("ASTRA_EDGE_REGISTRY");
    let (_sessions, _guard) = crate::tests::isolated_sessions_dir();
    let _credentials = crate::tests::isolate_credentials();
    let mut creds = CredentialsFile::default();
    creds.profiles.insert(
        "default".into(),
        Profile {
            account_id: Some("test-owner".into()),
            access_token: Some("test-token".into()),
            ..Default::default()
        },
    );
    save_credentials(&creds).unwrap();
    let mock = MockServer::start().await;
    let seen = Arc::new(tokio::sync::Notify::new());
    let request_seen = seen.clone();
    Mock::given(method("POST"))
        .and(path("/agents/edge"))
        .respond_with(move |_: &wiremock::Request| {
            request_seen.notify_one();
            ResponseTemplate::new(200).set_delay(Duration::from_secs(10))
        })
        .expect(1)
        .mount(&mock)
        .await;
    let (mut server, output) = server();
    server.ctx.api = astra_thin_client::ThinClient::new(&mock.uri(), None).unwrap();
    initialize(&mut server).await;
    let id = format!("acp-cancel-{}", uuid::Uuid::new_v4());
    let state = install_session(&mut server, &id);
    server.receive(&json!({"jsonrpc":"2.0","id":"prompt","method":"session/prompt","params":{"sessionId":id,"prompt":[{"type":"text","text":"hello"}]}}).to_string()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), seen.notified())
        .await
        .unwrap();
    assert!(
        output.lock().unwrap().iter().all(|v| v["id"] != "prompt"),
        "no early prompt acknowledgement"
    );
    assert!(state.lock().await.active_turn.is_some());
    server.receive(&json!({"jsonrpc":"2.0","id":"duplicate","method":"session/prompt","params":{"sessionId":id,"prompt":[{"type":"text","text":"duplicate"}]}}).to_string()).await.unwrap();
    assert!(
        output
            .lock()
            .unwrap()
            .iter()
            .any(|v| v["id"] == "duplicate" && v["error"]["data"]["code"] == TURN_CONFLICT_CODE)
    );
    server
        .receive(
            &json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":id}})
                .to_string(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.tasks.join_next().await.is_some() {}
    })
    .await
    .unwrap();
    {
        let output = output.lock().unwrap();
        let responses: Vec<_> = output.iter().filter(|v| v["id"] == "prompt").collect();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["result"]["stopReason"], "cancelled");
    }
    assert!(state.lock().await.active_turn.is_none());
    assert!(astra_services::session_journal::SessionExecutionLease::try_acquire(&id).is_ok());
    mock.verify().await;
}
