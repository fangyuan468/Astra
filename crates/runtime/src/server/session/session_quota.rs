use crate::server::*;

/// Create an `agent_sessions` row while enforcing the per-user session quota.
///
/// The resource governor has two related but distinct responsibilities:
///
/// - session-create quota: counts durable chat sessions (`agent_sessions`)
/// - run-start quota: limits execution capacity for active runs
///
/// The Session service owns the counter and the actual session insert.
/// A single durable session can contain many agentic runs, so run lifecycle code
/// must not increment `sessions_created`.
pub(crate) async fn create_session_with_resource_quota(
    state: &AppState,
    user_id: String,
    request: SessionCreateRequestData,
) -> Result<
    (SessionRecord, Option<astra_services::SessionAdmissionFacts>),
    (StatusCode, Json<ErrorResponse>),
> {
    state
        .session_service
        .create_session_with_resource_quota(user_id, request, state.resource_governor.as_ref())
        .await
}
