#![cfg(feature = "native")]
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn command(root: &std::path::Path, address: &str, proxy: bool) -> Command {
    let key =
        RsaPrivateKey::from_pkcs8_pem(include_str!("fixtures/oidc-test-private.pem")).unwrap();
    let config = root.join("oidc.json");
    std::fs::write(&config,json!({"issuer":"https://issuer.example","client_id":"test","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","keys":[{"kid":"test","n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())}]}).to_string()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut c = Command::new(env!("CARGO_BIN_EXE_waypost"));
    c.env_clear()
        .args(["serve", "--data"])
        .arg(root.join("data"))
        .args(["--listen", address])
        .env(
            "WAYPOST_ADMIN_SECRET",
            "isolated-test-admin-secret-at-least-32",
        )
        .env("WAYPOST_OIDC_CONFIG_FILE", config)
        .env("WAYPOST_OAUTH_CLIENT_DISCOVERY", "{}")
        .env(
            "WAYPOST_ENCRYPTION_KEYS",
            json!({"active":"test","keys":{"test":"11".repeat(32)}}).to_string(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if proxy {
        c.env("HTTPS_PROXY", "http://127.0.0.1:9");
    }
    c
}
#[tokio::test(flavor = "current_thread")]
async fn discovery_without_static_client_file_registers_and_proxy_disables_only_cimd() {
    for proxy in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        let mut process = Process(command(root.path(), &address, proxy).spawn().unwrap());
        // Only this isolated loopback server is contacted; OIDC and CIMD network
        // exchanges are not invoked. The fake proxy verifies fail-closed advertising.
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let origin = format!("http://{address}");
        let url = format!("{origin}/.well-known/oauth-authorization-server");
        let mut metadata = None;
        for _ in 0..100 {
            if let Ok(response) = client.get(&url).send().await
                && response.status().is_success()
            {
                metadata = Some(
                    serde_json::from_slice::<Value>(&response.bytes().await.unwrap()).unwrap(),
                );
                break;
            }
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "Native server exited during startup"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let metadata = metadata.expect("OAuth metadata unavailable");
        assert_eq!(metadata["client_id_metadata_document_supported"], !proxy);
        assert_eq!(
            metadata["registration_endpoint"],
            format!("{origin}/oauth/register")
        );
        let registration=client.post(format!("{origin}/oauth/register"))
            .header("content-type","application/json")
            .body(json!({"client_name":"Isolated Native CLI","redirect_uris":["http://127.0.0.1:54321/callback"],"token_endpoint_auth_method":"none"}).to_string()).send().await.unwrap();
        assert_eq!(registration.status(), reqwest::StatusCode::CREATED);
        let value: Value = serde_json::from_slice(&registration.bytes().await.unwrap()).unwrap();
        assert!(value["client_id"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(value.get("client_secret").is_none());
    }
}

#[test]
fn legacy_runtime_configuration_requires_explicit_offline_migration() {
    for variable in ["WAYPOST_OAUTH_CLIENTS_FILE", "WAYPOST_OAUTH_CLIENTS"] {
        let root = tempfile::tempdir().unwrap();
        let mut c = Command::new(env!("CARGO_BIN_EXE_waypost"));
        let output = c
            .env_clear()
            .args(["init", "--data"])
            .arg(root.path().join("data"))
            .env(variable, "legacy-config-not-loaded")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("offline migration"));
        assert!(!root.path().join("data").exists());
    }
}
