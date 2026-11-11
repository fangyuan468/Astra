//! Explicit local endpoints for sealed capacity RPC. Endpoint/key configuration
//! is local-only; neither the model nor the server may choose a URL or command.
use std::path::Path;

use astra_server_types::edge_ws_protocol::{
    CapacityRpcFailure, EdgeCapacityProvider, MAX_CAPACITY_RPC_TIMEOUT_SECS,
    MAX_SEALED_CAPACITY_BYTES, SealedCapacityPayload, valid_capacity_identity,
};
use base64::Engine;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalCapacityProvider {
    id: String,
    public_key: String,
    endpoint: String,
    bearer_key: String,
}

impl std::fmt::Debug for LocalCapacityProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCapacityProvider")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl LocalCapacityProvider {
    pub(crate) fn advertisement(&self) -> EdgeCapacityProvider {
        EdgeCapacityProvider {
            id: self.id.clone(),
            public_key: self.public_key.clone(),
        }
    }

    fn validate(&self) -> bool {
        let Ok(endpoint) = reqwest::Url::parse(&self.endpoint) else {
            return false;
        };
        valid_capacity_identity(&self.id)
            && base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&self.public_key)
                .is_ok_and(|key| key.len() == 32)
            && endpoint.scheme() == "http"
            && matches!(endpoint.host_str(), Some("127.0.0.1" | "[::1]"))
            && endpoint.port().is_some()
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none()
            && !self.bearer_key.is_empty()
            && self.bearer_key.len() <= 4096
            && !self.bearer_key.chars().any(char::is_control)
    }

    pub(crate) async fn call(
        &self,
        payload: SealedCapacityPayload,
        timeout_secs: u64,
        cancel: CancellationToken,
    ) -> Result<SealedCapacityPayload, CapacityRpcFailure> {
        if !payload.is_valid() || !(1..=MAX_CAPACITY_RPC_TIMEOUT_SECS).contains(&timeout_secs) {
            return Err(CapacityRpcFailure::Invalid);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .map_err(|_| CapacityRpcFailure::Offline)?;
        let call = async {
            let mut response = client
                .post(&self.endpoint)
                .bearer_auth(&self.bearer_key)
                .json(&payload)
                .send()
                .await
                .map_err(|_| CapacityRpcFailure::OutcomeUnknown)?;
            if !response.status().is_success() {
                return Err(CapacityRpcFailure::OutcomeUnknown);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| CapacityRpcFailure::OutcomeUnknown)?
            {
                if bytes.len() + chunk.len() > MAX_SEALED_CAPACITY_BYTES + 2 {
                    return Err(CapacityRpcFailure::OutcomeUnknown);
                }
                bytes.extend_from_slice(&chunk);
            }
            let payload: SealedCapacityPayload =
                serde_json::from_slice(&bytes).map_err(|_| CapacityRpcFailure::OutcomeUnknown)?;
            if !payload.is_valid() {
                return Err(CapacityRpcFailure::OutcomeUnknown);
            }
            Ok(payload)
        };
        tokio::select! {
            result = call => result,
            _ = cancel.cancelled() => Err(CapacityRpcFailure::OutcomeUnknown),
        }
    }
}

pub(crate) fn load(path: Option<&Path>) -> Result<Vec<LocalCapacityProvider>, String> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "Capacity provider config is unreadable")?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("Capacity provider config must be a private regular file (0600)".into());
        }
    }
    let bytes = std::fs::read(path).map_err(|_| "Capacity provider config is unreadable")?;
    if bytes.len() > 64 * 1024 {
        return Err("Capacity provider config is too large".into());
    }
    let providers: Vec<LocalCapacityProvider> =
        serde_json::from_slice(&bytes).map_err(|_| "Capacity provider config is invalid")?;
    let mut names = std::collections::HashSet::new();
    if providers.is_empty()
        || providers.len() > 8
        || providers
            .iter()
            .any(|item| !item.validate() || !names.insert(item.id.clone()))
    {
        return Err("Capacity provider config must contain distinct approved loopback endpoints and public keys".into());
    }
    Ok(providers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method},
    };

    fn provider(endpoint: String) -> LocalCapacityProvider {
        LocalCapacityProvider {
            id: "approved".into(),
            endpoint,
            public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7; 32]),
            bearer_key: "local-only-secret".into(),
        }
    }

    #[test]
    fn provider_config_accepts_only_explicit_loopback_and_hides_local_secrets() {
        let local = provider("http://127.0.0.1:5000/sealed".into());
        assert!(local.validate());
        assert!(provider("http://[::1]:5000/sealed".into()).validate());
        for endpoint in [
            "https://127.0.0.1:5000/sealed",
            "http://localhost:5000/sealed",
            "http://10.0.0.1:5000/sealed",
            "http://127.0.0.1:5000/sealed?q=x",
            "http://user@127.0.0.1:5000/sealed",
        ] {
            assert!(!provider(endpoint.into()).validate(), "{endpoint}");
        }
        let visible = serde_json::to_string(&local.advertisement()).unwrap();
        assert!(!visible.contains("5000"));
        assert!(!visible.contains("local-only-secret"));
        assert!(!format!("{local:?}").contains("local-only-secret"));
        assert!(load(None).unwrap().is_empty());
    }

    #[tokio::test]
    async fn provider_forwards_only_sealed_payload_with_local_key_and_rejects_redirects() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("authorization", "Bearer local-only-secret"))
            .and(body_json("c2VhbGVk"))
            .respond_with(ResponseTemplate::new(200).set_body_json("cmVzdWx0"))
            .expect(1)
            .mount(&server)
            .await;
        let result = provider(server.uri())
            .call(
                SealedCapacityPayload("c2VhbGVk".into()),
                5,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.0, "cmVzdWx0");
        server.verify().await;
        server.reset().await;
        let redirect = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", redirect.uri()))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            provider(server.uri())
                .call(
                    SealedCapacityPayload("c2VhbGVk".into()),
                    5,
                    CancellationToken::new()
                )
                .await
                .unwrap_err(),
            CapacityRpcFailure::OutcomeUnknown
        );
        assert!(redirect.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn canceled_or_malformed_provider_response_has_no_replay() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("RAW-PRIVATE-DIAGNOSTIC"))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            provider(server.uri())
                .call(
                    SealedCapacityPayload("c2VhbGVk".into()),
                    5,
                    CancellationToken::new()
                )
                .await
                .unwrap_err(),
            CapacityRpcFailure::OutcomeUnknown
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            provider(server.uri())
                .call(SealedCapacityPayload("c2VhbGVk".into()), 5, cancel)
                .await
                .unwrap_err(),
            CapacityRpcFailure::OutcomeUnknown
        );
    }
}
