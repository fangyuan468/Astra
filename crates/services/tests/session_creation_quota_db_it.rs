use astra_core::{MatrixOneSettings, SharedPool};
use astra_services::{
    AuthPrincipal, AuthPrincipalOrigin, AuthProviderAuthorizedRequestContext, AuthUserRecord,
    DatabaseSessionService, ProviderSessionCreationIdentity, SessionCreateRequestData,
    SessionService,
    resource_governor::{DatabaseResourceGovernor, LimitCheck, ResourceGovernor, ResourceLimits},
};
use axum::http::StatusCode;
use sqlx::{Connection, MySqlConnection};
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires live DB: run with ASTRA_TEST_DB_IT=1"]
async fn provider_creation_reserves_daily_quota_once_in_its_transaction() {
    assert_eq!(std::env::var("ASTRA_TEST_DB_IT").as_deref(), Ok("1"));
    let mut settings = MatrixOneSettings::from_env();
    settings.database = "mysql".into();
    let mut admin = MySqlConnection::connect(&settings.database_url_with_password())
        .await
        .unwrap();
    let database = format!("astra_test_creation_quota_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE `{database}`")))
        .execute(&mut admin)
        .await
        .unwrap();
    settings.database = database.clone();
    astra_services::storage::ensure_core_schema(&settings, "mysql")
        .await
        .unwrap();
    let pool = SharedPool::new(&settings).await.unwrap();
    let governor = DatabaseResourceGovernor::new(pool.clone());
    let sessions = DatabaseSessionService::new(settings)
        .with_pool(pool.clone())
        .with_scope_encryptor(Arc::new(
            astra_services::FernetTokenEncryptor::new("provider-session-scope-test-key").unwrap(),
        ));
    // Internal core-only users retain the unmetered creation API. HTTP quota
    // admission instead fails closed if its required resource tables are absent.
    let internal = sessions
        .create_session(
            "quota-internal".into(),
            SessionCreateRequestData {
                agent_id: None,
                title: None,
                metadata: None,
            },
        )
        .await;
    let unavailable = sessions
        .create_session_with_resource_quota(
            "quota-unavailable".into(),
            SessionCreateRequestData {
                agent_id: None,
                title: None,
                metadata: None,
            },
            &governor,
        )
        .await;
    let unavailable_sessions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_sessions WHERE user_id = ?")
            .bind("quota-unavailable")
            .fetch_one(pool.get())
            .await
            .unwrap();
    governor.ensure_tables().await.unwrap();
    let user_id = format!("quota-{}", Uuid::new_v4().simple());
    let principal = AuthPrincipal {
        user: AuthUserRecord {
            user_id: user_id.clone(),
            username: user_id.clone(),
            email: "quota@example.test".into(),
            display_name: None,
        },
        session_id: None,
        execution_continuation: None,
        origin: AuthPrincipalOrigin::ProviderAuthorizedRequest(
            AuthProviderAuthorizedRequestContext {
                provider_id: "provider-a".into(),
                external_subject: user_id.clone(),
                provider_scope_id: "scope-a".into(),
                request_authorization_id: "quota-request".into(),
                edge_agent_id: None,
            },
        ),
    };
    governor
        .set_limits(
            &user_id,
            ResourceLimits {
                max_sessions_per_day: 1,
                ..Default::default()
            },
        )
        .await;
    let request = SessionCreateRequestData {
        agent_id: None,
        title: None,
        metadata: None,
    };
    let first_identity =
        ProviderSessionCreationIdentity::from_principal(&principal, "first").unwrap();
    let first = sessions
        .create_provider_session(first_identity.clone(), request.clone(), LimitCheck::Allowed)
        .await;
    let proof_key = "__astra_provider_scope_proof_v1";
    let original_proof = first
        .as_ref()
        .ok()
        .and_then(|result| result.session.metadata.get(proof_key).cloned());
    let (replacement, forged) = if let Ok(result) = first.as_ref() {
        let session_id = result.session.session_id.clone();
        let replacement = sessions
            .update_session(
                session_id.clone(),
                user_id.clone(),
                astra_services::SessionUpdateRequestData {
                    title: None,
                    metadata: Some(serde_json::Map::from_iter([(
                        "user_key".into(),
                        serde_json::json!("value"),
                    )])),
                    metadata_patch: None,
                    status: None,
                },
            )
            .await;
        let forged = sessions
            .update_session(
                session_id,
                user_id.clone(),
                astra_services::SessionUpdateRequestData {
                    title: None,
                    metadata: None,
                    metadata_patch: Some(serde_json::Map::from_iter([(
                        proof_key.into(),
                        serde_json::Value::Null,
                    )])),
                    status: None,
                },
            )
            .await;
        (Some(replacement), Some(forged))
    } else {
        (None, None)
    };
    let replay = sessions
        .create_provider_session(first_identity.clone(), request.clone(), LimitCheck::Allowed)
        .await;
    let (old_replay, corrupt_replay) = if let Ok(first) = first.as_ref() {
        // Existing deterministic creation intents remain readable across an
        // upgrade. Replaying them must not invent ownership of old history.
        sqlx::query(
            "UPDATE agent_sessions SET metadata = '{}' WHERE user_id = ? AND session_id = ?",
        )
        .bind(&user_id)
        .bind(&first.session.session_id)
        .execute(pool.get())
        .await
        .unwrap();
        let old = sessions
            .create_provider_session(first_identity.clone(), request.clone(), LimitCheck::Allowed)
            .await;
        sqlx::query("UPDATE agent_sessions SET metadata = ? WHERE user_id = ? AND session_id = ?")
            .bind(serde_json::json!({(proof_key): null}).to_string())
            .bind(&user_id)
            .bind(&first.session.session_id)
            .execute(pool.get())
            .await
            .unwrap();
        let corrupt = sessions
            .create_provider_session(first_identity, request.clone(), LimitCheck::Allowed)
            .await;
        (Some(old), Some(corrupt))
    } else {
        (None, None)
    };
    // A stale preflight check must not bypass the authoritative transaction.
    let second = sessions
        .create_provider_session(
            ProviderSessionCreationIdentity::from_principal(&principal, "second").unwrap(),
            request.clone(),
            LimitCheck::Allowed,
        )
        .await;
    let usage = governor.get_usage(&user_id).await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_sessions WHERE user_id = ?")
        .bind(&user_id)
        .fetch_one(pool.get())
        .await
        .unwrap();
    governor
        .set_limits(
            &user_id,
            ResourceLimits {
                max_sessions_per_day: 2,
                ..Default::default()
            },
        )
        .await;
    // The 255-character title column rejects this insert after quota reservation.
    let failed_insert = sessions
        .create_session_with_resource_quota(
            user_id.clone(),
            SessionCreateRequestData {
                title: Some("x".repeat(1_024)),
                ..request.clone()
            },
            &governor,
        )
        .await;
    let after_rollback = governor.get_usage(&user_id).await;
    let (ordinary, provider) = tokio::join!(
        sessions.create_session_with_resource_quota(user_id.clone(), request.clone(), &governor),
        sessions.create_provider_session(
            ProviderSessionCreationIdentity::from_principal(&principal, "concurrent").unwrap(),
            request,
            LimitCheck::Allowed,
        ),
    );
    let after_race = governor.get_usage(&user_id).await;
    let count_after_race: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_sessions WHERE user_id = ?")
            .bind(&user_id)
            .fetch_one(pool.get())
            .await
            .unwrap();
    pool.get().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE `{database}`")))
        .execute(&mut admin)
        .await
        .unwrap();
    let replacement = replacement
        .expect("provider session created")
        .expect("metadata replacement");
    assert!(original_proof.is_some());
    assert_eq!(replacement.metadata.get(proof_key), original_proof.as_ref());
    assert_eq!(
        forged
            .expect("provider session created")
            .expect_err("scope proof removal must be rejected")
            .0,
        StatusCode::BAD_REQUEST
    );
    assert!(
        internal.is_ok(),
        "core-only internal Session creation remains supported"
    );
    assert_eq!(
        unavailable.unwrap_err().0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        unavailable_sessions, 0,
        "quota storage failure must not create a Session"
    );
    assert!(first.unwrap().created);
    assert!(!replay.unwrap().created);
    let old_replay = old_replay.unwrap().unwrap();
    assert!(!old_replay.created);
    assert!(
        !old_replay.session.metadata.contains_key(proof_key),
        "replay must not backfill scope"
    );
    assert_eq!(
        corrupt_replay.unwrap().unwrap_err().0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(second.unwrap_err().0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        usage.sessions_created, 1,
        "replay must not consume quota twice"
    );
    assert_eq!(count, 1, "quota rejection must not leave a Session");
    assert_eq!(
        failed_insert.unwrap_err().0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        after_rollback.sessions_created, 1,
        "failed creation releases its count"
    );
    let race = [ordinary.map(|_| ()), provider.map(|_| ())];
    assert_eq!(race.iter().filter(|result| result.is_ok()).count(), 1);
    for error in race.into_iter().filter_map(Result::err) {
        assert_eq!(error.0, StatusCode::TOO_MANY_REQUESTS);
    }
    assert_eq!(after_race.sessions_created, 2);
    assert_eq!(
        count_after_race, 2,
        "ordinary and provider creation share the quota lock"
    );
}
