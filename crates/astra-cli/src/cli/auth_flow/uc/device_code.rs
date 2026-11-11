use astra_credentials::native::{self, Environment, NativeStore, TokenResponse};
use astra_services::auth::uc::UcDiscovery;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::Instant;

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const EXPIRED: &str = "Device sign-in expired. Run `astra login --device-code` to start again.";
const MAX_WAIT_SECS: u64 = 600;
const TOKEN_UNCONFIRMED: &str = "The device sign-in outcome could not be confirmed. No local session was changed. Start a new sign-in request; the previous grant will not be retried.";
const STOPPED: &str = "Device sign-in stopped. No local session was changed.";

// Deliberately not Debug: the grant secret must never be rendered or logged.
#[derive(Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    #[serde(default = "default_interval")]
    interval: u64,
}

fn default_interval() -> u64 {
    5
}

fn issuer_endpoint(value: &str, issuer: &str, suffix: &str) -> Result<reqwest::Url, String> {
    let target = native::secure_url(value)?;
    let issuer = native::secure_url(issuer)?;
    if target.origin() != issuer.origin()
        || target.path() != format!("{}{suffix}", issuer.path().trim_end_matches('/'))
        || target.query().is_some()
        || target.fragment().is_some()
    {
        return Err("Invalid UC device sign-in endpoint".into());
    }
    Ok(target)
}

impl DeviceAuthorization {
    fn validate(&self, issuer: &str) -> Result<(), String> {
        issuer_endpoint(&self.verification_uri, issuer, "/device")?;
        if self.device_code.is_empty()
            || self.device_code.len() > 4096
            || !(6..=64).contains(&self.user_code.len())
            || !self
                .user_code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || self.expires_in == 0
            || self.interval == 0
            || self.interval > self.expires_in
        {
            return Err("Invalid UC device authorization response".into());
        }
        Ok(())
    }

    fn wait_duration(&self) -> Duration {
        Duration::from_secs(self.expires_in.min(MAX_WAIT_SECS))
    }

    fn deadline_error(&self) -> String {
        format!(
            "Stopped waiting for device sign-in after {} seconds. No local session was changed; the request may remain valid until it expires. Run `astra login --device-code` to start again.",
            self.wait_duration().as_secs()
        )
    }
}

async fn authorization_response(
    response: reqwest::Response,
    issuer: &str,
) -> Result<DeviceAuthorization, String> {
    let status = response.status();
    if !status.is_success() {
        let message = if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            "Too many device sign-in requests. Wait before trying again; no local session was changed."
        } else if status.is_server_error() {
            "UC device authorization is temporarily unavailable. Try again later; no local session was changed."
        } else {
            "UC device authorization was rejected; no local session was changed."
        };
        return Err(message.into());
    }
    let grant: DeviceAuthorization = native::bounded_json(response).await?;
    grant.validate(issuer)?;
    Ok(grant)
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

struct PollPolicy {
    interval: Duration,
    delay: Duration,
}

impl PollPolicy {
    fn new(interval: u64) -> Self {
        let interval = Duration::from_secs(interval);
        Self {
            interval,
            delay: interval,
        }
    }

    fn pending(&mut self) {
        self.delay = self.interval;
    }

    fn slow_down(&mut self) {
        self.interval = self.interval.saturating_add(Duration::from_secs(5));
        self.delay = self.interval;
    }

    fn unavailable(&mut self) {
        self.delay = self.delay.saturating_mul(2).min(Duration::from_secs(60));
        self.delay = self.delay.max(self.interval);
    }
}

enum PollResponse {
    Tokens(TokenResponse),
    Pending,
    SlowDown,
    ConnectFailed,
}

async fn exchange(
    client: &reqwest::Client,
    environment: &Environment,
    grant: &DeviceAuthorization,
    verifier: &str,
) -> Result<PollResponse, String> {
    let response = match client
        .post(&environment.token_endpoint)
        .form(&[
            ("grant_type", DEVICE_GRANT),
            ("client_id", "astra-cli"),
            ("device_code", grant.device_code.as_str()),
            ("code_verifier", verifier),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) if error.is_connect() => return Ok(PollResponse::ConnectFailed),
        Err(_) => return Err(TOKEN_UNCONFIRMED.into()),
    };
    let status = response.status();
    if status.is_success() {
        return native::bounded_json(response)
            .await
            .map(PollResponse::Tokens)
            .map_err(|_| TOKEN_UNCONFIRMED.into());
    }
    // A proxy or issuer can fail after consuming the grant. A status alone
    // cannot prove that it is safe to send the same grant again.
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return Err(TOKEN_UNCONFIRMED.into());
    }
    let error: OAuthError = native::bounded_json(response)
        .await
        .map_err(|_| TOKEN_UNCONFIRMED.to_string())?;
    match error.error.as_str() {
        "authorization_pending" => Ok(PollResponse::Pending),
        "slow_down" => Ok(PollResponse::SlowDown),
        "temporarily_unavailable" => Err(TOKEN_UNCONFIRMED.into()),
        "access_denied" => Err("Device sign-in was denied. No local session was changed.".into()),
        "expired_token" => Err(EXPIRED.into()),
        _ => Err("UC rejected device sign-in. Start again; no local session was changed.".into()),
    }
}

async fn settle_in_flight<F>(
    mut request: Pin<&mut F>,
    interrupt: &mut super::LoginInterrupt,
    mut stopped: bool,
) -> (bool, Result<PollResponse, String>)
where
    F: Future<Output = Result<PollResponse, String>>,
{
    let deadline = Instant::now() + Duration::from_secs(15);
    let result = if stopped {
        tokio::time::timeout_at(deadline, &mut request).await
    } else {
        tokio::select! {
            result = tokio::time::timeout_at(deadline, &mut request) => result,
            _ = interrupt.recv() => {
                stopped = true;
                tokio::time::timeout_at(deadline, &mut request).await
            }
        }
    };
    (
        stopped,
        result.unwrap_or_else(|_| Err(TOKEN_UNCONFIRMED.into())),
    )
}

async fn poll(
    client: &reqwest::Client,
    environment: &Environment,
    grant: &DeviceAuthorization,
    verifier: &str,
    interrupt: &mut super::LoginInterrupt,
    deadline: Instant,
) -> Result<TokenResponse, String> {
    let mut policy = PollPolicy::new(grant.interval);
    loop {
        let now = Instant::now();
        // Do not shorten an issuer interval or retry delay to fit a final poll.
        // Compare before adding: an issuer can supply a very large interval.
        if policy.delay >= deadline.saturating_duration_since(now) {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => return Err(grant.deadline_error()),
                _ = interrupt.recv() => return Err(STOPPED.into()),
            }
        }
        let wake = now + policy.delay;
        tokio::select! {
            _ = tokio::time::sleep_until(wake) => {}
            _ = interrupt.recv() => return Err(STOPPED.into()),
        }
        // A ready deadline or interrupt must not start a new exchange. Once
        // polled, however, the request may have reached the issuer and must
        // be settled rather than dropped.
        let started = AtomicBool::new(false);
        let request = async {
            if Instant::now() >= deadline {
                return Err(grant.deadline_error());
            }
            started.store(true, Ordering::SeqCst);
            exchange(client, environment, grant, verifier).await
        };
        tokio::pin!(request);
        let (stopped, response) = tokio::select! {
            biased;
            _ = interrupt.recv() => {
                if !started.load(Ordering::SeqCst) { return Err(STOPPED.into()); }
                settle_in_flight(request.as_mut(), interrupt, true).await
            },
            _ = tokio::time::sleep_until(deadline) => {
                if !started.load(Ordering::SeqCst) { return Err(grant.deadline_error()); }
                settle_in_flight(request.as_mut(), interrupt, false).await
            },
            result = &mut request => (false, result),
        };
        let response = response?;
        if stopped {
            if let PollResponse::Tokens(tokens) = response {
                super::revoke_new_session(environment, &tokens.refresh_token).await;
            }
            return Err(STOPPED.into());
        }
        match response {
            PollResponse::Tokens(tokens) => return Ok(tokens),
            PollResponse::Pending => policy.pending(),
            PollResponse::SlowDown => policy.slow_down(),
            PollResponse::ConnectFailed => policy.unavailable(),
        }
    }
}

pub(crate) async fn login_device_code(
    api: &astra_thin_client::ThinClient,
    discovery: UcDiscovery,
) -> Result<(), String> {
    let store = NativeStore::new()?;
    store.prepare_for_login()?;
    let mut interrupt = super::LoginInterrupt::new()?;
    let (client, environment, endpoint) = tokio::select! {
        result = super::discover_environment(api, &discovery) => result?,
        _ = interrupt.recv() => {
            return Err("Device sign-in stopped. No local session was changed.".into());
        }
    };
    let endpoint = issuer_endpoint(
        endpoint
            .as_ref()
            .ok_or("Device code sign-in is not enabled on this MOI deployment")?
            .as_str()
            .ok_or("Invalid UC device sign-in discovery")?,
        &environment.issuer,
        "/protocol/openid-connect/auth/device",
    )?;
    let nonce = super::super::browser_code::verifier();
    let verifier = super::super::browser_code::verifier();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let started = Instant::now();
    let authorization = async {
        let response = client
            .post(endpoint)
            .form(&[
                ("client_id", "astra-cli"),
                ("scope", discovery.scope.as_str()),
                ("nonce", nonce.as_str()),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await
            .map_err(|_| "UC device authorization is unavailable; no local session was changed")?;
        authorization_response(response, &environment.issuer).await
    };
    let grant = tokio::select! {
        result = authorization => result?,
        _ = interrupt.recv() => return Err(STOPPED.into()),
    };
    eprintln!(
        "Open this page in a browser on another device:\n{}\n\nEnter this code: {}\nCheck the account and permissions, then approve or deny access.\nWaiting for authorization (up to {} seconds). Press Ctrl+C to stop.",
        grant.verification_uri,
        grant.user_code,
        grant.wait_duration().as_secs()
    );
    let tokens = poll(
        &client,
        &environment,
        &grant,
        &verifier,
        &mut interrupt,
        started + grant.wait_duration(),
    )
    .await?;
    // Preparation has no local publication. Cancellation revokes the new token;
    // the credential owner arbitrates cancellation against the commit boundary.
    eprintln!(
        "Authorization approved. Preparing sign-in. Credential lock waiting can be cancelled with Ctrl+C; once commit starts, please wait for it to settle."
    );
    let preparation = tokio::time::timeout(
        Duration::from_secs(60),
        super::prepare(&client, &environment, &tokens, &nonce),
    );
    let prepared = tokio::select! {
        biased;
        _ = interrupt.recv() => Err("Device sign-in stopped before credential publication. No local session was changed.".into()),
        result = preparation => result
            .map_err(|_| "UC product sign-in timed out".to_string())
            .and_then(|result| result),
    };
    let (session, bootstrap) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            super::revoke_new_session(&environment, &tokens.refresh_token).await;
            return Err(error);
        }
    };
    let (session, bootstrap) =
        super::publish_prepared_login(&store, session, bootstrap, &mut interrupt).await?;
    if let Err(error) =
        super::choose_workspace(&store, &session, bootstrap, None, &mut interrupt).await
    {
        eprintln!(
            "Workspace selection: {error}. Sign-in remains active; use `astra auth workspace` later."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
