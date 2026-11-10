//! Projection of the shared execution owner's events onto ACP v1 wire messages.
use super::*;

#[derive(Debug)]
pub(in crate::cli::app_server) struct TurnProjection {
    session_id: String,
    text: String,
    terminal: Option<Value>,
    diagnostic: Option<Value>,
    tools: std::collections::HashSet<String>,
}

impl TurnProjection {
    pub(super) fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.into(),
            text: String::new(),
            terminal: None,
            diagnostic: None,
            tools: std::collections::HashSet::new(),
        }
    }

    pub(in crate::cli::app_server) fn project(&mut self, value: Value) -> Vec<Value> {
        let params = &value["params"];
        let update = match value["method"].as_str().unwrap_or("") {
            "item/agentMessage/delta" => {
                let text = params["delta"].as_str().unwrap_or("");
                self.text.push_str(text);
                Some(text_update("agent_message_chunk", text))
            }
            "item/reasoning/textDelta" => Some(text_update(
                "agent_thought_chunk",
                params["delta"].as_str().unwrap_or(""),
            )),
            "item/completed" if params["item"]["type"] == "agentMessage" => {
                // The runtime sends both deltas and a complete final message.
                // Emit only a missing suffix, never repeat already streamed text.
                let final_text = params["item"]["text"].as_str().unwrap_or("");
                let missing = final_text.strip_prefix(&self.text).unwrap_or("");
                let update =
                    (!missing.is_empty()).then(|| text_update("agent_message_chunk", missing));
                if update.is_some() {
                    self.text = final_text.to_owned();
                }
                update
            }
            "item/started" | "item/completed" if params["item"]["type"] == "dynamicToolCall" => {
                let item = &params["item"];
                let completed = value["method"] == "item/completed";
                let first = self
                    .tools
                    .insert(item["id"].as_str().unwrap_or("").to_owned());
                let mut update = json!({
                    "sessionUpdate":if first { "tool_call" } else { "tool_call_update" },
                    "toolCallId":item["id"], "title":item["name"], "kind":"other",
                    "status":if completed {
                        match item["status"].as_str() { Some("error" | "failed" | "denied" | "cancelled") => "failed", _ => "completed" }
                    } else { "in_progress" }
                });
                if let Some(input) = item.get("input") {
                    update["rawInput"] = input.clone();
                }
                if let Some(output) = item.get("output").filter(|o| !o.is_null()) {
                    update["rawOutput"] = output.clone();
                }
                Some(update)
            }
            "approval/requested" => {
                let approval = &params["approval"];
                return vec![json!({
                    "jsonrpc":"2.0", "id":format!("astra-permission/{}",approval["id"].as_str().unwrap_or("")),
                    "method":"session/request_permission",
                    "params":{
                        "sessionId":self.session_id,
                        "toolCall":{"toolCallId":approval["id"],"title":approval["header"],"status":"pending","rawInput":approval["args"]},
                        "options":[
                            {"optionId":"allow_once","name":"Allow once","kind":"allow_once"},
                            {"optionId":"reject_once","name":"Deny","kind":"reject_once"}
                        ]
                    }
                })];
            }
            "warning" => Some(text_update(
                "agent_message_chunk",
                &format!(
                    "\n[Astra warning] {}\n",
                    params["message"].as_str().unwrap_or("Runtime warning")
                ),
            )),
            "error" => {
                self.diagnostic = Some(params.clone());
                None
            }
            "turn/completed" => {
                self.terminal = Some(params.clone());
                None
            }
            _ => None,
        };
        update
            .map(|update| notification(&self.session_id, update))
            .into_iter()
            .collect()
    }

    pub(super) fn finish(
        &mut self,
        id: Value,
        result: Result<(), AppServerFailure>,
        cancelled: bool,
    ) -> Value {
        if let Err(failure) = result {
            if cancelled
                && matches!(
                    failure.message.as_str(),
                    "Edge registration interrupted before chat" | "MCP setup cancelled"
                )
            {
                return json!({"jsonrpc":"2.0","id":id,"result":{"stopReason":"cancelled"}});
            }
            // Preserve uncertain/committed terminal facts even when cancellation races.
            let mut error = failure_error(failure);
            if cancelled && error["data"]["code"] == TURN_FAILED_CODE {
                error["data"]["cancelled"] = json!(true);
            }
            return json!({"jsonrpc":"2.0","id":id,"error":error});
        }
        let completed = self
            .terminal
            .as_ref()
            .is_some_and(|p| p["status"] == "completed");
        if !completed && !cancelled {
            let mut failure = error(-32000, "Astra turn failed");
            if let Some(diagnostic) = self.diagnostic.take() {
                failure["data"] = diagnostic;
            }
            return json!({"jsonrpc":"2.0","id":id,"error":failure});
        }
        json!({"jsonrpc":"2.0","id":id,"result":{"stopReason":if cancelled {"cancelled"} else {"end_turn"}}})
    }
}

fn text_update(kind: &str, text: &str) -> Value {
    json!({"sessionUpdate":kind,"content":{"type":"text","text":text}})
}

pub(super) fn notification(session_id: &str, update: Value) -> Value {
    json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":session_id,"update":update}})
}

pub(super) fn replay(session_id: &str, messages: &[Value]) -> Vec<Value> {
    let mut updates = Vec::new();
    for message in messages {
        let kind = match message["role"].as_str() {
            Some("user") => "user_message_chunk",
            Some("assistant") => "agent_message_chunk",
            Some("tool") => {
                if let Some(id) = message["tool_call_id"].as_str() {
                    updates.push(notification(
                        session_id,
                        json!({
                            "sessionUpdate":"tool_call_update","toolCallId":id,
                            "status":"completed", "rawOutput":message["content"]
                        }),
                    ));
                }
                continue;
            }
            _ => continue,
        };
        let content = &message["content"];
        if let Some(text) = content.as_str() {
            updates.push(notification(session_id, text_update(kind, text)));
        } else if let Some(blocks) = content.as_array() {
            for block in blocks {
                if block["type"] == "text"
                    && let Some(text) = block["text"].as_str()
                {
                    updates.push(notification(session_id, text_update(kind, text)));
                }
            }
        }
        if let Some(calls) = message["tool_calls"].as_array() {
            for call in calls {
                let input = call["function"]["arguments"]
                    .as_str()
                    .and_then(|text| serde_json::from_str::<Value>(text).ok())
                    .unwrap_or_else(|| call["function"]["arguments"].clone());
                updates.push(notification(session_id,json!({
                    "sessionUpdate":"tool_call","toolCallId":call["id"],
                    "title":call["function"]["name"],"status":"pending","kind":"other","rawInput":input
                })));
            }
        }
    }
    updates
}
