//! Fixture contract for Memoria `/v1/observe`, pinned to the owner-header
//! rules in memoria-api/src/auth.rs::validate_owner_scoped_master_request.
//! This is deliberately test-only; live_memoria_owner_observe verifies the
//! production backend independently so a permissive fixture cannot certify it.
use axum::http::{HeaderMap, StatusCode};

pub fn validate_observer_auth(
    headers: &HeaderMap,
    master_key: &str,
    scoped_key: Option<&str>,
) -> Result<(), StatusCode> {
    let authorization = headers.get("authorization").and_then(|v| v.to_str().ok());
    if authorization == Some(format!("Memoria-Owner {master_key}").as_str()) {
        let owners = headers.get_all("x-user-id").iter().collect::<Vec<_>>();
        let valid = owners.len() == 1
            && owners[0].to_str().is_ok_and(|owner| {
                !owner.is_empty()
                    && owner.trim() == owner
                    && owner.len() <= 64
                    && !owner.starts_with("grp_")
                    && !owner.chars().any(char::is_control)
            });
        if valid {
            Ok(())
        } else {
            Err(StatusCode::BAD_REQUEST)
        }
    } else if scoped_key.is_some_and(|key| authorization == Some(format!("Bearer {key}").as_str()))
    {
        // A scoped API key supplies its owner server-side; headers cannot
        // override it. The fixture models acceptance, not key provisioning.
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
