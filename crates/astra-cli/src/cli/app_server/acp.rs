//! ACP v1 is a transport over the existing app-server execution owner.
//! It does not introduce an agent loop, persistence format or permission engine.

use super::*;
use serde_json::json;
use std::path::PathBuf;

mod projection;
pub(super) use projection::TurnProjection;
#[cfg(test)]
mod tests;

struct Session {
    state: Arc<Mutex<AppState>>,
    model: Option<String>,
    models: std::collections::HashSet<String>,
    model_options: Vec<Value>,
    model_efforts: HashMap<String, Vec<String>>,
    effort: Option<String>,
    offering_id: Option<String>,
    mcp_servers: Vec<astra_mcp::McpServerConfig>,
}

impl Session {
    fn configured_effort(model: Option<&str>, available: Option<&Vec<String>>) -> Option<String> {
        let (_, config) = astra_turn_core::thinking_config::resolve_model_thinking_request(model?);
        match config {
            astra_turn_core::thinking_config::ThinkingConfig::Adaptive { effort }
                if available
                    .is_some_and(|levels| levels.iter().any(|value| value == effort.as_str())) =>
            {
                Some(effort.as_str().to_string())
            }
            _ => None,
        }
    }

    fn current_model_id(&self) -> &str {
        self.offering_id.as_deref().unwrap_or("agent-default")
    }

    fn config_options(&self) -> Vec<Value> {
        let mut options = vec![json!({
            "id":"model", "name":"Model", "category":"model", "type":"select",
            "currentValue":self.current_model_id(), "options":self.model_options
        })];
        if let Some(efforts) = self.model_efforts.get(self.current_model_id())
            && !efforts.is_empty()
        {
            let mut values = vec![json!({"value":"default", "name":"Model default"})];
            values.extend(
                efforts
                    .iter()
                    .map(|effort| json!({"value":effort,"name":effort})),
            );
            options.push(json!({
                "id":"effort", "name":"Reasoning effort", "category":"thought_level", "type":"select",
                "currentValue":self.effort.as_deref().unwrap_or("default"), "options":values
            }));
        }
        options
    }

    fn model_selector(&self) -> Option<String> {
        self.model.as_ref().map(|model| match &self.effort {
            Some(effort) => {
                let base = astra_turn_core::thinking_config::resolve_model_thinking(model).0;
                format!("{base}(thinking:{effort})")
            }
            None => model.clone(),
        })
    }
}

struct AcpServer {
    ctx: ServerContext,
    writer: JsonWriter,
    cwd: PathBuf,
    initialized: bool,
    sessions: HashMap<String, Session>,
    tasks: tokio::task::JoinSet<()>,
}

pub(crate) async fn run(
    api: &astra_thin_client::ThinClient,
    profile: Option<&str>,
    model: Option<&str>,
    system_prompt: Option<&str>,
    auto_approve: bool,
) -> Result<(), String> {
    if astra_services::session_journal::journal_content_redact_enabled() {
        return Err("ACP requires durable local continuation; journal content redaction is supported for one-shot chat".into());
    }
    let mut server = AcpServer::new(
        ServerContext {
            api: api.clone(),
            auth_profile: profile.map(str::to_string),
            default_model: model.map(str::to_string),
            system_prompt: system_prompt.map(str::to_string),
            auto_approve,
        },
        JsonWriter::default(),
    )?;
    // Keep blocking pipe reads off the async executor, including on a single worker.
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    std::thread::Builder::new()
        .name("astra-acp-input".into())
        .spawn(move || {
            for line in std::io::stdin().lock().lines() {
                if tx.blocking_send(line).is_err() {
                    break;
                }
            }
        })
        .map_err(|e| format!("ACP input unavailable: {e}"))?;
    let result = async {
        while let Some(line) = rx.recv().await {
            server.receive(&line.map_err(|e| e.to_string())?).await?;
        }
        Ok(())
    }
    .await;
    server.shutdown().await;
    result
}

impl AcpServer {
    fn new(ctx: ServerContext, writer: JsonWriter) -> Result<Self, String> {
        Ok(Self {
            ctx,
            writer,
            cwd: std::env::current_dir()
                .and_then(std::fs::canonicalize)
                .map_err(|_| "ACP launch directory is unavailable")?,
            initialized: false,
            sessions: HashMap::new(),
            tasks: tokio::task::JoinSet::new(),
        })
    }

    async fn receive(&mut self, line: &str) -> Result<(), String> {
        if line.trim().is_empty() {
            return Ok(());
        }
        while self.tasks.try_join_next().is_some() {}
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => {
                return self
                    .reply(Value::Null, Err(error(-32700, "Invalid JSON")))
                    .await;
            }
        };
        if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || !value.is_object() {
            return self
                .reply(
                    Value::Null,
                    Err(error(-32600, "Expected a JSON-RPC 2.0 object")),
                )
                .await;
        }
        if value.get("method").is_none()
            && (value.get("result").is_some() || value.get("error").is_some())
        {
            self.permission_response(&value).await;
            return Ok(());
        }
        let id = value.get("id").cloned();
        if id
            .as_ref()
            .is_some_and(|id| !id.is_null() && !id.is_string() && id.as_i64().is_none())
        {
            return self
                .reply(Value::Null, Err(error(-32600, "Invalid request id")))
                .await;
        }
        let method = value.get("method").and_then(Value::as_str).unwrap_or("");
        // Notifications cannot create sessions, start prompts or change configuration.
        if id.is_none() && method != "session/cancel" {
            return Ok(());
        }
        let params = value.get("params").cloned().unwrap_or(json!({}));
        let result = self.dispatch(method, &params, id.clone()).await;
        if let Some(id) = id {
            match result {
                Ok(None) => {} // session/prompt stays pending until durable settlement.
                other => {
                    self.reply(id, other.map(|v| v.unwrap_or(json!({}))))
                        .await?
                }
            }
        }
        Ok(())
    }

    async fn reply(&self, id: Value, result: Result<Value, Value>) -> Result<(), String> {
        let value = match result {
            Ok(result) => json!({"jsonrpc":"2.0", "id":id, "result":result}),
            Err(error) => json!({"jsonrpc":"2.0", "id":id, "error":error}),
        };
        write_json_line(&self.writer, value).await
    }

    async fn dispatch(
        &mut self,
        method: &str,
        params: &Value,
        id: Option<Value>,
    ) -> Result<Option<Value>, Value> {
        if method == "initialize" {
            if self.initialized {
                return Err(error(-32600, "Already initialized"));
            }
            if params
                .get("protocolVersion")
                .and_then(Value::as_u64)
                .is_none()
            {
                return Err(error(-32602, "protocolVersion is required"));
            }
            self.initialized = true;
            return Ok(Some(json!({
                "protocolVersion":1,
                "agentInfo":{"name":"astra", "title":"Astra", "version":env!("CARGO_PKG_VERSION")},
                "agentCapabilities":{
                    "loadSession":true,
                    "promptCapabilities":{"image":false,"audio":false,"embeddedContext":false},
                    "mcpCapabilities":{"http":true,"sse":true}
                },
                "authMethods":[]
            })));
        }
        if !self.initialized {
            return Err(error(-32600, "initialize must complete first"));
        }
        match method {
            "session/new" | "session/load" => self.bind(method, params).await.map(Some),
            "session/prompt" => {
                let session_id = required_string(params, "sessionId")?;
                let message = prompt_text(params)?;
                let session = self
                    .sessions
                    .get(session_id)
                    .ok_or_else(|| error(-32602, "Unknown sessionId"))?;
                let turn_id = uuid::Uuid::new_v4().to_string();
                let cancel = Arc::new(CancellationToken::new());
                let mut guard = session.state.lock().await;
                let (thread_id, developer_instructions) =
                    begin_turn(&mut guard, None, &turn_id, cancel.clone(), None)
                        .map_err(failure_error)?;
                drop(guard);
                let projection = Arc::new(std::sync::Mutex::new(TurnProjection::new(session_id)));
                let writer = JsonWriter(self.writer.0.clone(), Some(projection.clone()));
                let reply_writer = self.writer.clone();
                let ctx = self.ctx.clone();
                let state = session.state.clone();
                let request = TurnRequest {
                    state: state.clone(),
                    thread_id,
                    turn_id: turn_id.clone(),
                    message,
                    params: json!({"model":session.model_selector()}),
                    developer_instructions,
                    permission_mode: if self.ctx.auto_approve {
                        PermissionMode::Auto
                    } else {
                        PermissionMode::Prompt
                    },
                    cancel: cancel.clone(),
                    mcp_servers: Some(session.mcp_servers.clone()),
                    offering_id: session.offering_id.clone(),
                };
                let id = id.ok_or_else(|| error(-32600, "session/prompt requires a request id"))?;
                self.tasks.spawn(async move {
                    let result = run_turn(ctx, writer, request).await;
                    deny_pending_approvals_for_turn(&state, &turn_id).await;
                    // Release the admission guard before acknowledging the prompt. A client
                    // may immediately send the next prompt after it receives this response.
                    state.lock().await.active_turn = None;
                    let response = match projection.lock() {
                        Ok(mut output) => output.finish(id, result, cancel.is_cancelled()),
                        Err(_) => json!({"jsonrpc":"2.0","id":id,"error":error(-32603,"ACP output state poisoned")}),
                    };
                    let _ = write_json_line(&reply_writer, response).await;
                });
                Ok(None)
            }
            "session/cancel" => {
                let session_id = required_string(params, "sessionId")?;
                let session = self
                    .sessions
                    .get(session_id)
                    .ok_or_else(|| error(-32602, "Unknown sessionId"))?;
                cancel_session(&session.state).await;
                Ok(Some(json!({})))
            }
            "session/set_model" | "session/set_config_option" => {
                let session_id = required_string(params, "sessionId")?;
                let config_id = if method == "session/set_model" {
                    "model"
                } else {
                    required_string(params, "configId")?
                };
                let value = if method == "session/set_model" {
                    required_string(params, "modelId")?
                } else {
                    required_string(params, "value")?
                };
                let session = self
                    .sessions
                    .get_mut(session_id)
                    .ok_or_else(|| error(-32602, "Unknown sessionId"))?;
                if session.state.lock().await.active_turn.is_some() {
                    return Err(error(-32000, "Session is busy"));
                }
                match config_id {
                    "model" => {
                        if value != "agent-default" && !session.models.contains(value) {
                            return Err(error(
                                -32602,
                                "Model is not in this session's advertised catalog",
                            ));
                        }
                        let model_changed = value != session.current_model_id();
                        if model_changed {
                            if value == "agent-default" {
                                session.model = self.ctx.default_model.clone();
                                session.offering_id = None;
                                session.effort = Session::configured_effort(
                                    session.model.as_deref(),
                                    session.model_efforts.get("agent-default"),
                                );
                            } else {
                                session.model = Some(value.to_owned());
                                session.offering_id = Some(value.to_owned());
                                session.effort = None;
                            }
                        }
                    }
                    "effort" => {
                        let available = session
                            .model_efforts
                            .get(session.current_model_id())
                            .filter(|levels| !levels.is_empty())
                            .ok_or_else(|| {
                                error(-32602, "Reasoning effort is unavailable for this model")
                            })?;
                        if value != "default" && !available.iter().any(|level| level == value) {
                            return Err(error(
                                -32602,
                                "Reasoning effort is not available for this model",
                            ));
                        }
                        if value == "default"
                            && let Some(model) = session.model.as_mut()
                        {
                            *model =
                                astra_turn_core::thinking_config::resolve_model_thinking(model)
                                    .0
                                    .to_owned();
                        }
                        session.effort = (value != "default").then(|| value.to_owned());
                    }
                    _ => return Err(error(-32602, "Unknown configuration option")),
                }
                Ok(Some(if method == "session/set_model" {
                    json!({})
                } else {
                    json!({"configOptions":session.config_options()})
                }))
            }
            _ => Err(error(-32601, "Method not found")),
        }
    }

    async fn bind(&mut self, method: &str, params: &Value) -> Result<Value, Value> {
        validate_cwd(params, &self.cwd)?;
        let mcp_servers = parse_mcp_servers(params)?;
        let state = Arc::new(Mutex::new(AppState::default()));
        let token = get_profile_and_token(self.ctx.auth_profile.as_deref())
            .map_err(|_| error(-32000, "Run astra login in a terminal before starting ACP"))?
            .3;
        let session_id = if method == "session/load" {
            let id = required_string(params, "sessionId")?.to_owned();
            if let Some(existing) = self.sessions.get(&id)
                && existing.state.lock().await.active_turn.is_some()
            {
                return Err(error(-32000, "Session is busy"));
            }
            with_thread_binding_deadline(
                "session/load",
                SESSION_BIND_TIMEOUT,
                resume_server_thread(
                    &self.ctx.api,
                    self.ctx.auth_profile.as_deref(),
                    &state,
                    id,
                    None,
                ),
            )
            .await
        } else {
            with_thread_binding_deadline(
                "session/new",
                SESSION_BIND_TIMEOUT,
                start_server_thread(
                    &self.ctx.api,
                    &token,
                    &state,
                    self.ctx.system_prompt.clone(),
                ),
            )
            .await
        }
        .map_err(failure_error)?;
        let catalog = tokio::time::timeout(
            Duration::from_secs(10),
            session_runtime::fetch_model_catalog(&self.ctx.api, Some(&token)),
        )
        .await
        .map_err(|_| error(-32000, "Model catalog timed out"))?
        .map_err(|_| {
            error(
                -32000,
                "Model catalog unavailable; check Astra sign-in and service connectivity",
            )
        })?;
        let mut models =
            vec![json!({"modelId":"agent-default", "name":"Astra configured default"})];
        let mut model_options =
            vec![json!({"value":"agent-default", "name":"Astra configured default"})];
        let mut model_efforts = HashMap::new();
        let mut model_ids = std::collections::HashSet::new();
        for entry in catalog {
            if model_ids.insert(entry.offering_id.clone()) {
                models.push(json!({"modelId":entry.offering_id,"name":entry.name, "description":entry.description}));
                model_options.push(json!({"value":entry.offering_id,"name":entry.name, "description":entry.description}));
                let efforts = astra_turn_core::thinking_config::thinking_options(
                    Some(&entry.provider),
                    entry
                        .thinking_capability
                        .map(|capability| capability.as_str()),
                    entry.thinking_protocol.unwrap_or_default(),
                )
                .into_iter()
                .filter(|option| {
                    option
                        .config
                        .is_within_declared_efforts(entry.supported_reasoning_efforts.as_deref())
                })
                .filter_map(|option| match option.config {
                    astra_turn_core::thinking_config::ThinkingConfig::Adaptive { effort } => {
                        Some(effort.as_str().to_string())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
                if self.ctx.default_model.as_deref().is_some_and(|model| {
                    let base = astra_turn_core::thinking_config::resolve_model_thinking(model).0;
                    base == entry.offering_id || base.eq_ignore_ascii_case(&entry.name)
                }) {
                    model_efforts.insert("agent-default".into(), efforts.clone());
                }
                model_efforts.insert(entry.offering_id, efforts);
            }
        }
        if method == "session/load" {
            let continuation = app_server_continuation(&session_id)
                .ok_or_else(|| error(-32000, "Canonical session history could not be restored"))?;
            for update in projection::replay(&session_id, &continuation.messages) {
                write_json_line(&self.writer, update)
                    .await
                    .map_err(|_| error(-32603, "Session replay transport failed"))?;
            }
        }
        let effort = Session::configured_effort(
            self.ctx.default_model.as_deref(),
            model_efforts.get("agent-default"),
        );
        self.sessions.insert(
            session_id.clone(),
            Session {
                state,
                model: self.ctx.default_model.clone(),
                models: model_ids,
                model_options,
                model_efforts,
                effort,
                offering_id: None,
                mcp_servers,
            },
        );
        Ok(
            json!({"sessionId":session_id,"models":{"currentModelId":"agent-default","availableModels":models},
            "configOptions":self.sessions[&session_id].config_options()}),
        )
    }

    async fn permission_response(&self, value: &Value) {
        let Some(id) = value
            .get("id")
            .and_then(Value::as_str)
            .and_then(|id| id.strip_prefix("astra-permission/"))
        else {
            return;
        };
        // Only allow the exact one-shot option offered by this process.
        let approved = value.get("error").is_none()
            && value
                .pointer("/result/outcome/outcome")
                .and_then(Value::as_str)
                == Some("selected")
            && value
                .pointer("/result/outcome/optionId")
                .and_then(Value::as_str)
                == Some("allow_once");
        for session in self.sessions.values() {
            if let Some(pending) = session.state.lock().await.pending_approvals.remove(id) {
                let _ = pending.response_tx.send(if approved {
                    ApprovalResponse::AllowOnce
                } else {
                    ApprovalResponse::Deny
                });
                return;
            }
        }
    }

    async fn shutdown(&mut self) {
        for session in self.sessions.values() {
            cancel_session(&session.state).await;
        }
        if tokio::time::timeout(Duration::from_secs(5), async {
            while self.tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            self.tasks.abort_all();
            while self.tasks.join_next().await.is_some() {}
        }
    }
}

async fn cancel_session(state: &Arc<Mutex<AppState>>) {
    let turn = {
        let guard = state.lock().await;
        guard.active_turn.as_ref().map(|turn| {
            turn.cancel.cancel();
            turn.turn_id.clone()
        })
    };
    if let Some(turn) = turn {
        deny_pending_approvals_for_turn(state, &turn).await;
    }
}

fn required_string<'a>(params: &'a Value, key: &str) -> Result<&'a str, Value> {
    params
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| error(-32602, &format!("{key} must be a non-empty string")))
}

fn error(code: i64, message: &str) -> Value {
    json!({"code":code,"message":message})
}

fn failure_error(failure: AppServerFailure) -> Value {
    response_failure_value(Value::Null, &failure)["error"].clone()
}

fn validate_cwd(params: &Value, launch: &std::path::Path) -> Result<(), Value> {
    let cwd = PathBuf::from(required_string(params, "cwd")?);
    if !cwd.is_absolute() || std::fs::canonicalize(cwd).ok().as_deref() != Some(launch) {
        return Err(error(
            -32602,
            "cwd must match the ACP process launch directory; launch a separate process for another workspace",
        ));
    }
    Ok(())
}

fn prompt_text(params: &Value) -> Result<String, Value> {
    let blocks = params
        .get("prompt")
        .and_then(Value::as_array)
        .filter(|blocks| !blocks.is_empty())
        .ok_or_else(|| error(-32602, "prompt must contain text blocks"))?;
    let mut text = Vec::new();
    for block in blocks {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => text.push(
                block
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(|| error(-32602, "Text block is missing text"))?
                    .to_owned(),
            ),
            Some("resource_link") => {
                let name = required_string(block, "name")?;
                let uri = required_string(block, "uri")?;
                url::Url::parse(uri).map_err(|_| error(-32602, "Resource link URI is invalid"))?;
                // Carry the reference as user content. Reading it, if needed,
                // goes through the ordinary admitted file/network/MCP tools.
                text.push(format!(
                    "Resource reference: {}",
                    json!({"name":name,"uri":uri})
                ));
            }
            _ => {
                return Err(error(
                    -32602,
                    "Only text and resource_link prompt blocks are supported",
                ));
            }
        }
    }
    let text = text.join("\n");
    if text.trim().is_empty() {
        return Err(error(-32602, "Prompt is empty"));
    }
    Ok(text)
}

fn parse_mcp_servers(params: &Value) -> Result<Vec<astra_mcp::McpServerConfig>, Value> {
    use astra_mcp::{McpServerConfig, Transport};
    let servers = params
        .get("mcpServers")
        .and_then(Value::as_array)
        .ok_or_else(|| error(-32602, "mcpServers must be an array"))?;
    let invalid = || {
        error(
            -32602,
            "Invalid MCP server configuration; expected unique names and stdio, http or sse transport",
        )
    };
    let mut configs: Vec<McpServerConfig> = Vec::new();
    for server in servers {
        let name = required_string(server, "name")?;
        if configs.iter().any(|c| c.name == name) {
            return Err(invalid());
        }
        let pairs = |key: &str, value_key: &str| -> Result<HashMap<String, String>, Value> {
            server
                .get(key)
                .and_then(Value::as_array)
                .ok_or_else(invalid)?
                .iter()
                .map(|pair| {
                    let name = required_string(pair, "name")?;
                    let value = pair
                        .get(value_key)
                        .and_then(Value::as_str)
                        .ok_or_else(invalid)?;
                    Ok((name.to_owned(), value.to_owned()))
                })
                .collect()
        };
        let transport = match server.get("type").and_then(Value::as_str) {
            None | Some("stdio") => Transport::Stdio {
                command: vec![required_string(server, "command")?.to_owned()],
                args: server
                    .get("args")
                    .and_then(Value::as_array)
                    .ok_or_else(invalid)?
                    .iter()
                    .map(|arg| arg.as_str().map(str::to_owned).ok_or_else(invalid))
                    .collect::<Result<_, _>>()?,
                env: pairs("env", "value")?,
            },
            Some("http") => Transport::StreamableHttp {
                url: required_string(server, "url")?.to_owned(),
                headers: pairs("headers", "value")?,
                auth_token: None,
            },
            Some("sse") => Transport::Sse {
                url: required_string(server, "url")?.to_owned(),
                headers: pairs("headers", "value")?,
                auth_token: None,
            },
            _ => return Err(invalid()),
        };
        configs.push(McpServerConfig {
            name: name.to_owned(),
            transport,
            description: String::new(),
            enabled: true,
            retry: Default::default(),
        });
    }
    Ok(configs)
}
