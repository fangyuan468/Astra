//! Exercise the real HTTP client in isolated subprocess environments: never
//! mutate proxy variables in the shared test process or need external servers.
use astra_tools::web_fetch::{FetchNetwork, fetch_with_cache_scope};
use astra_tools::{ToolExecutor, executor::DefaultToolExecutor};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

const TARGET: &str = "http://93.184.216.34:9/probe";

#[tokio::test]
#[ignore = "requires explicitly configured local proxy and public network"]
async fn live_owner_network() {
    let workspace = tempfile::tempdir().unwrap();
    let direct = DefaultToolExecutor::for_workspace(workspace.path(), "network-test", "direct");
    let local = DefaultToolExecutor::for_workspace(workspace.path(), "network-test", "local")
        .with_local_network(Ok(None));
    let url = std::env::var("ASTRA_TEST_PUBLIC_URL").expect("explicit public URL required");
    let args = json!({"url": url, "timeout": 5, "max_content": 2048});
    let result = local.execute("web_fetch", &args).await;
    assert!(!result.is_error, "local fetch: {result:?}");
    let data: Value = serde_json::from_str(&result.output).unwrap();
    println!(
        "local fetch status={} content_bytes={}",
        data["status"], data["content_length"]
    );
    let result = direct.execute("web_fetch", &args).await;
    assert!(
        result.is_error,
        "this control requires a proxy-only destination"
    );
    println!(
        "direct error_kind={}",
        result.metadata.unwrap()["error_kind"]
    );
    let result = local
        .execute(
            "web_search",
            &json!({"query": "Rust official documentation", "engine": "google", "num_results": 3}),
        )
        .await;
    assert!(!result.is_error, "local search: {result:?}");
    let data: Value = serde_json::from_str(&result.output).unwrap();
    println!(
        "local search status={} content_bytes={}",
        data["results"]["status"], data["results"]["content_length"]
    );
}

#[tokio::test]
#[ignore = "requires a fake-IP DNS, a reachable DoH resolver and public network"]
async fn live_fake_ip_screening() {
    use astra_config::runtime_config::{FakeIpMode, WebFetchConfig};
    use astra_tools::web_fetch::FakeIpPolicy;
    let url = std::env::var("ASTRA_TEST_PUBLIC_URL").expect("explicit public URL required");
    let resolver = std::env::var("ASTRA_TEST_DOH_RESOLVER").expect("explicit DoH URL required");
    let args = json!({"url": url, "timeout": 15, "max_content": 2048});
    let blocked =
        fetch_with_cache_scope(&args, "", &FetchNetwork::local_environment(Ok(None))).await;
    assert!(
        blocked.is_error,
        "requires a host the local DNS maps to 198.18.0.0/15"
    );
    println!("without opt-in: {}", blocked.output);
    let policy = FakeIpPolicy::from_config(&WebFetchConfig {
        fake_ip: FakeIpMode::AllowDohScreened,
        fake_ip_ranges: Vec::new(),
        doh_resolvers: vec![resolver],
    })
    .unwrap()
    .map(std::sync::Arc::new);
    let admitted =
        fetch_with_cache_scope(&args, "", &FetchNetwork::local_environment(Ok(policy))).await;
    assert!(!admitted.is_error, "with opt-in: {admitted:?}");
    let data: Value = serde_json::from_str(&admitted.output).unwrap();
    println!(
        "with opt-in: status={} content_bytes={}",
        data["status"], data["content_length"]
    );
}

#[tokio::test]
async fn proxy_worker() {
    let Ok(mode) = std::env::var("ASTRA_TEST_WEB_TRANSPORT") else {
        return;
    };
    // no_proxy must exercise LocalEnvironment while bypassing the proxy.
    let network = if mode == "direct" {
        FetchNetwork::direct_pinned()
    } else {
        FetchNetwork::local_environment(Ok(None))
    };
    let result = fetch_with_cache_scope(
        &json!({"url": TARGET, "allow_http": true, "timeout": 1}),
        "transport-test",
        &network,
    )
    .await;
    let output: Value = serde_json::from_str(&result.output).unwrap();
    match mode.as_str() {
        "success" => {
            assert!(!result.is_error, "{result:?}");
            assert_eq!(output["content"], "proxy evidence");
            let direct = fetch_with_cache_scope(
                &json!({"url": TARGET, "allow_http": true, "timeout": 1}),
                "transport-test",
                &FetchNetwork::direct_pinned(),
            )
            .await;
            assert!(
                direct.is_error,
                "proxy cache must not satisfy a direct request"
            );
        }
        "http_error" => {
            assert!(result.is_error);
            assert_eq!(result.metadata.unwrap()["error_kind"], "auth");
            assert_eq!(output["response"]["status"], 403);
        }
        "redirect" => {
            assert!(result.is_error);
            assert_eq!(result.metadata.unwrap()["error_kind"], "policy_denied");
        }
        "slow" => {
            assert!(result.is_error);
            assert_eq!(result.metadata.unwrap()["error_kind"], "tool_timeout");
        }
        "direct" | "no_proxy" => {
            assert!(result.is_error);
        }
        other => panic!("unexpected mode {other}"),
    }
}

#[test]
fn real_transport_respects_owner_proxy_boundary_and_total_deadline() {
    for mode in [
        "success",
        "direct",
        "no_proxy",
        "redirect",
        "slow",
        "http_error",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let mode_owned = mode.to_string();
        let server = std::thread::spawn(move || {
            let end = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                            .unwrap();
                        let mut request = [0u8; 4096];
                        let n = stream.read(&mut request).unwrap();
                        let line = String::from_utf8_lossy(&request[..n]);
                        assert!(
                            line.starts_with(&format!("GET {TARGET} HTTP/1.1")),
                            "{line}"
                        );
                        if mode_owned == "slow" {
                            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 14\r\nConnection: close\r\n\r\nproxy").unwrap();
                            std::thread::sleep(std::time::Duration::from_millis(1300));
                        } else if mode_owned == "redirect" {
                            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                        } else if mode_owned == "http_error" {
                            stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied").unwrap();
                        } else {
                            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 14\r\nConnection: close\r\n\r\nproxy evidence").unwrap();
                        }
                        return 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= end {
                            return 0;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("proxy accept: {e}"),
                }
            }
        });
        let mut child = Command::new(std::env::current_exe().unwrap());
        child.args(["--exact", "proxy_worker", "--nocapture"]);
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ] {
            child.env_remove(key);
        }
        child
            .env("http_proxy", &proxy)
            .env("https_proxy", &proxy)
            .env("ASTRA_TEST_WEB_TRANSPORT", mode);
        if mode == "no_proxy" {
            child.env("NO_PROXY", "93.184.216.34");
        }
        let result = child.output().unwrap();
        assert!(
            result.status.success(),
            "mode={mode}\n{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            server.join().unwrap(),
            usize::from(!matches!(mode, "direct" | "no_proxy")),
            "mode={mode}"
        );
    }
}
