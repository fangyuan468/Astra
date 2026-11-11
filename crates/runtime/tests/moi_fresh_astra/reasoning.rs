//! Additive MOI reasoning contract; historical recovery/chat keep their own pin.
//! Source: astra_runtime_reasoning.go and astra_protocol_astra_runtime_backend.go.
use super::*;
use astra_runtime::server::provider_test_support::{
    ProviderGateway, ProviderResponse, ProviderScript,
};

const MOI_REASONING_CONTRACT_COMMIT: &str = "2403ed2b49e450146465a09a931515c4b772d8f6";

// Replay the producer's JSON independently of Astra's request or admission types.
fn payload(moi: &MoiClient, effort: Option<&str>, control: Option<Value>) -> Value {
    let mut request = moi.payload("Exercise the MOI reasoning-level contract.");
    if let Some(effort) = effort {
        request["context"] = json!({"thinking":{"mode":"adaptive","effort":effort}});
    }
    if let Some(control) = control {
        request["capability_descriptors"]["model_gateway"]["metadata"]["reasoning_control"] =
            control;
    }
    request
}

async fn complete(app: &Router, payload: &Value) {
    let (status, body) = post(app, "/chat/stream", payload).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events = events(&body);
    normal_chat::assert_terminal(&events, "completed");
    assert_eq!(
        events.last().unwrap()["assistant_text"],
        "Reasoning contract completed.",
        "{body}"
    );
    assert_eq!(
        events
            .iter()
            .find(|event| event["type"] == "session_info")
            .unwrap()["session_id"],
        payload["session_id"],
        "reasoning changes must preserve the selected session"
    );
}

async fn request_bodies(provider: &ProviderGateway) -> Vec<Value> {
    provider
        .requests
        .lock()
        .await
        .iter()
        .map(|request| request.body.clone())
        .collect()
}

pub(super) async fn exercise(
    app: &Router,
    endpoint: &str,
    gateway_state: Arc<Mutex<GatewayState>>,
) {
    eprintln!("MOI reasoning contract: matrixflow@{MOI_REASONING_CONTRACT_COMMIT}");
    let answer = || {
        ProviderResponse::OpenAi(json!({
            "model":"moi-contract-model",
            "choices":[{"index":0,"message":{"role":"assistant","content":"Reasoning contract completed."},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110}
        }))
    };
    let provider = ProviderGateway::start(vec![ProviderScript::new(
        "MOI reasoning levels and session reuse after rejection",
        |request| {
            request.path == "/v1/chat/completions"
                && request.body["model"] == "moi-contract-model"
                && request.body["stream"] == true
        },
        vec![answer(), answer(), answer(), answer(), answer(), answer()],
    )])
    .await;
    *gateway_state.lock().unwrap() = GatewayState::default();
    let mut moi = MoiClient::new(
        false,
        endpoint.into(),
        "reasoning-protocol",
        gateway_state.clone(),
    );
    moi.repair_session(app).await;
    moi.repair_bindings(app).await;
    moi.history.clear();
    moi.discovery_snapshot = true;
    moi.authorization = "Bearer moi-reasoning-contract-grant".into();
    moi.model_endpoint = Some(format!("{}/v1/chat/completions", provider.base_url));
    {
        let mut gateway = gateway_state.lock().unwrap();
        gateway.authorization = moi.authorization.clone();
        gateway.bindings = moi.bindings.clone();
    }

    let control =
        json!({"protocol":"reasoning_effort","supported_efforts":["low","medium","high","max"]});
    for effort in ["low", "medium", "high", "max"] {
        complete(app, &payload(&moi, Some(effort), Some(control.clone()))).await;
        let requests = request_bodies(&provider).await;
        assert_eq!(requests.last().unwrap()["reasoning_effort"], effort);
    }
    // The same persisted session must not leak its previous explicit level into
    // an ordinary turn whose model gateway declares no reasoning capability.
    complete(app, &payload(&moi, None, None)).await;
    assert!(
        request_bodies(&provider)
            .await
            .last()
            .unwrap()
            .get("reasoning_effort")
            .is_none()
    );

    for (name, effort, control, domain_code) in [
        ("missing capability", "high", None, None),
        (
            "unadvertised level",
            "medium",
            Some(json!({"protocol":"reasoning_effort","supported_efforts":["low","high","max"]})),
            None,
        ),
        (
            "wrong protocol",
            "high",
            Some(json!({"protocol":"enable_thinking","supported_efforts":["high"]})),
            Some("provider_runtime_context_invalid"),
        ),
        (
            "empty inventory",
            "high",
            Some(json!({"protocol":"reasoning_effort","supported_efforts":[]})),
            Some("provider_runtime_context_invalid"),
        ),
        (
            "invalid level",
            "high",
            Some(json!({"protocol":"reasoning_effort","supported_efforts":["ultra"]})),
            Some("provider_runtime_context_invalid"),
        ),
        (
            "duplicate level",
            "high",
            Some(json!({"protocol":"reasoning_effort","supported_efforts":["high","high"]})),
            Some("provider_runtime_context_invalid"),
        ),
        (
            "malformed declaration",
            "high",
            Some(Value::Null),
            Some("provider_runtime_context_invalid"),
        ),
    ] {
        let before = request_bodies(&provider).await;
        let (status, body) = post(app, "/chat/stream", &payload(&moi, Some(effort), control)).await;
        assert_eq!(status, StatusCode::OK, "{name}: {body}");
        let events = events(&body);
        let error = events
            .iter()
            .find(|event| event["type"] == "error")
            .expect("pre-run rejection");
        assert_eq!(error["code"], "VALIDATION_ERROR", "{name}: {body}");
        assert_eq!(error["retryable"], false, "{name}: {body}");
        if let Some(code) = domain_code {
            assert_eq!(error["error_code"], code, "{name}: {body}");
        }
        assert!(
            events
                .iter()
                .all(|event| event["run_id"].as_str().is_none_or(str::is_empty)),
            "{name}: allocated a run: {body}"
        );
        assert!(
            !events.iter().any(|event| matches!(
                event["type"].as_str(),
                Some("text_delta" | "run_finished" | "turn_complete")
            )),
            "{name}: reported a successful run: {body}"
        );
        assert_eq!(
            request_bodies(&provider).await,
            before,
            "{name}: rejected request reached the model"
        );
    }
    complete(app, &payload(&moi, Some("high"), Some(control))).await;
    let requests = request_bodies(&provider).await;
    let efforts: Vec<_> = requests
        .iter()
        .map(|body| body["reasoning_effort"].clone())
        .collect();
    assert_eq!(
        efforts,
        vec![
            json!("low"),
            json!("medium"),
            json!("high"),
            json!("max"),
            Value::Null,
            json!("high")
        ],
        "model calls must preserve each selected level without duplicate inference"
    );
    provider.assert_complete();
    assert!(gateway_state.lock().unwrap().errors.is_empty());
}
