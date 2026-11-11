//! Live-only, exact-incarnation service routing. Astra never opens the sealed
//! payload, persists an invocation, chooses a provider or retransmits a call.
use super::*;
use astra_server_types::edge_capacity_rpc::{
    CapacityRpcFailure, EdgeCapacityProvider, EdgeCapacityRpcRequest, SealedCapacityPayload,
    advertised_provider, valid_capacity_identity,
};
use astra_server_types::edge_connection_pool::EdgeConnectionInfo;

const FORWARDED_INCARNATION: &str = "x-astra-capacity-incarnation";
type Failure = (StatusCode, Json<ErrorResponse>);

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapacityRoute {
    user_id: String,
    workspace_id: String,
    edge_id: String,
    provider_id: String,
}

impl CapacityRoute {
    fn validate(&self) -> Result<(), CapacityRpcFailure> {
        if [
            &self.user_id,
            &self.workspace_id,
            &self.edge_id,
            &self.provider_id,
        ]
        .iter()
        .all(|value| valid_capacity_identity(value))
        {
            Ok(())
        } else {
            Err(CapacityRpcFailure::Invalid)
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapacityInfo {
    /// Durable registry socket UUID, not the process-local pool counter.
    generation: String,
    provider: EdgeCapacityProvider,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CapacityCall {
    route: CapacityRoute,
    generation: String,
    timeout_secs: u64,
    payload: SealedCapacityPayload,
}

fn status_code(reason: CapacityRpcFailure) -> (StatusCode, &'static str) {
    match reason {
        CapacityRpcFailure::Invalid => (StatusCode::BAD_REQUEST, "CAPACITY_RPC_INVALID"),
        CapacityRpcFailure::Offline => (StatusCode::SERVICE_UNAVAILABLE, "CAPACITY_RPC_OFFLINE"),
        CapacityRpcFailure::BindingChanged => {
            (StatusCode::CONFLICT, "CAPACITY_RPC_BINDING_CHANGED")
        }
        CapacityRpcFailure::Unsupported => {
            (StatusCode::UNPROCESSABLE_ENTITY, "CAPACITY_RPC_UNSUPPORTED")
        }
        CapacityRpcFailure::Busy => (StatusCode::TOO_MANY_REQUESTS, "CAPACITY_RPC_BUSY"),
        CapacityRpcFailure::OutcomeUnknown => {
            (StatusCode::BAD_GATEWAY, "CAPACITY_RPC_OUTCOME_UNKNOWN")
        }
    }
}

fn fail(reason: CapacityRpcFailure) -> Failure {
    let (status, code) = status_code(reason);
    astra_core::error_response_coded(
        status,
        "Selected capacity provider could not complete this request",
        code,
    )
}

pub(crate) fn validate_relay_origin(origin: &str) -> Result<reqwest::Url, CapacityRpcFailure> {
    let url = reqwest::Url::parse(origin).map_err(|_| CapacityRpcFailure::Invalid)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CapacityRpcFailure::Invalid);
    }
    Ok(url)
}

enum CapacityOwner {
    Local(EdgeConnectionInfo),
    Remote {
        origin: reqwest::Url,
        incarnation: String,
    },
}

async fn owner(
    state: &AppState,
    route: &CapacityRoute,
    expected: Option<&str>,
    forwarded: bool,
) -> Result<CapacityOwner, CapacityRpcFailure> {
    route.validate()?;
    let local = state
        .edge_connection_pool
        .find_user_edge_by_agent_and_workspace(
            &route.user_id,
            &route.edge_id,
            Some(&route.workspace_id),
        );
    if !state.execution.edge_registry_service.has_durable_routing() {
        let info = local.ok_or(CapacityRpcFailure::Offline)?;
        if expected.is_some_and(|id| id != info.connection_id) {
            return Err(CapacityRpcFailure::BindingChanged);
        }
        return Ok(CapacityOwner::Local(info));
    }
    let record = state.execution.edge_registry_service.find_by_user_agent_and_workspace(
        &route.user_id, &route.edge_id, Some(&route.workspace_id)).await.map_err(|error| {
            tracing::warn!(target:"astra_runtime::edge_capacity", operation="resolve_owner", reason="CAPACITY_RPC_OFFLINE", %error, "capacity registry lookup failed");
            CapacityRpcFailure::Offline
        })?.ok_or(CapacityRpcFailure::Offline)?;
    if expected.is_some_and(|id| id != record.edge_id) {
        return Err(CapacityRpcFailure::BindingChanged);
    }
    if let Some(info) = local
        && info.connection_id == record.edge_id
    {
        return Ok(CapacityOwner::Local(info));
    }
    // One hop only. A moved connection cannot redirect a prepared lease or
    // start a forwarding loop through stale node metadata.
    if forwarded {
        return Err(CapacityRpcFailure::Offline);
    }
    let origin = record
        .capabilities
        .as_ref()
        .and_then(|value| value.get("capacity_relay_v1"))
        .and_then(|value| value.get("origin"))
        .and_then(serde_json::Value::as_str)
        .ok_or(CapacityRpcFailure::Unsupported)?;
    Ok(CapacityOwner::Remote {
        origin: validate_relay_origin(origin)?,
        incarnation: record.edge_id,
    })
}

async fn forward<T: serde::de::DeserializeOwned>(
    origin: &reqwest::Url,
    incarnation: &str,
    headers: &HeaderMap,
    route: &CapacityRoute,
    call: Option<&CapacityCall>,
) -> Result<T, CapacityRpcFailure> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_secs(130))
        .build()
        .map_err(|_| CapacityRpcFailure::Offline)?;
    let endpoint = origin
        .join("service/edges/capacity")
        .map_err(|_| CapacityRpcFailure::Invalid)?;
    let request = if let Some(call) = call {
        client.post(endpoint).json(call)
    } else {
        client.get(endpoint).query(route)
    };
    let mut response = request.header(axum::http::header::AUTHORIZATION, headers.get(axum::http::header::AUTHORIZATION).ok_or(CapacityRpcFailure::Invalid)?)
        .header(FORWARDED_INCARNATION, incarnation).send().await.map_err(|error| {
            tracing::warn!(target:"astra_runtime::edge_capacity", operation="forward", %error, "capacity node transport failed");
            if call.is_some() { CapacityRpcFailure::OutcomeUnknown } else { CapacityRpcFailure::Offline }
        })?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| CapacityRpcFailure::OutcomeUnknown)?
    {
        if bytes.len() + chunk.len()
            > astra_server_types::edge_ws_protocol::MAX_SEALED_CAPACITY_BYTES + 1024
        {
            return Err(CapacityRpcFailure::OutcomeUnknown);
        }
        bytes.extend_from_slice(&chunk);
    }
    if status != StatusCode::OK {
        if let Ok(error) = serde_json::from_slice::<ErrorResponse>(&bytes) {
            for reason in [
                CapacityRpcFailure::Invalid,
                CapacityRpcFailure::Offline,
                CapacityRpcFailure::BindingChanged,
                CapacityRpcFailure::Unsupported,
                CapacityRpcFailure::Busy,
                CapacityRpcFailure::OutcomeUnknown,
            ] {
                let (expected_status, code) = status_code(reason);
                if status == expected_status && error.error_code.as_deref() == Some(code) {
                    return Err(reason);
                }
            }
        }
        return Err(CapacityRpcFailure::OutcomeUnknown);
    }
    serde_json::from_slice(&bytes).map_err(|_| CapacityRpcFailure::OutcomeUnknown)
}

pub(crate) async fn describe_capacity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(route): Query<CapacityRoute>,
) -> Result<Json<CapacityInfo>, Failure> {
    super::edge_service_status_handler::check_service_auth(&headers)?;
    let forwarded = headers.get(FORWARDED_INCARNATION);
    let expected = forwarded
        .map(|value| {
            value
                .to_str()
                .map_err(|_| fail(CapacityRpcFailure::Invalid))
        })
        .transpose()?;
    match owner(&state, &route, expected, forwarded.is_some())
        .await
        .map_err(fail)?
    {
        CapacityOwner::Local(info) => {
            let provider = advertised_provider(&info, &route.provider_id)
                .ok_or_else(|| fail(CapacityRpcFailure::Unsupported))?;
            Ok(Json(CapacityInfo {
                generation: info.connection_id,
                provider,
            }))
        }
        CapacityOwner::Remote {
            origin,
            incarnation,
        } => {
            let info: CapacityInfo = forward(&origin, &incarnation, &headers, &route, None)
                .await
                .map_err(fail)?;
            if info.generation != incarnation || info.provider.id != route.provider_id {
                return Err(fail(CapacityRpcFailure::BindingChanged));
            }
            Ok(Json(info))
        }
    }
}

pub(crate) async fn call_capacity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CapacityCall>,
) -> Result<Json<SealedCapacityPayload>, Failure> {
    super::edge_service_status_handler::check_service_auth(&headers)?;
    if !valid_capacity_identity(&request.generation)
        || !(1..=130).contains(&request.timeout_secs)
        || !request.payload.is_valid()
    {
        return Err(fail(CapacityRpcFailure::Invalid));
    }
    let forwarded = headers.get(FORWARDED_INCARNATION);
    if forwarded.is_some_and(|value| value.to_str().ok() != Some(&request.generation)) {
        return Err(fail(CapacityRpcFailure::BindingChanged));
    }
    let payload = match owner(
        &state,
        &request.route,
        Some(&request.generation),
        forwarded.is_some(),
    )
    .await
    .map_err(fail)?
    {
        CapacityOwner::Local(_) => state
            .edge_connection_pool
            .call_capacity_provider(EdgeCapacityRpcRequest {
                user_id: &request.route.user_id,
                workspace_id: &request.route.workspace_id,
                edge_id: &request.route.edge_id,
                provider_id: &request.route.provider_id,
                connection_id: request.generation,
                timeout_secs: request.timeout_secs,
                payload: request.payload,
            })
            .await
            .map_err(fail)?,
        CapacityOwner::Remote {
            origin,
            incarnation,
        } => forward(
            &origin,
            &incarnation,
            &headers,
            &request.route,
            Some(&request),
        )
        .await
        .map_err(fail)?,
    };
    if !payload.is_valid() {
        return Err(fail(CapacityRpcFailure::OutcomeUnknown));
    }
    Ok(Json(payload))
}
