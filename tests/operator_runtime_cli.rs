#![cfg(feature = "native")]
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts};
use std::{path::Path, process::Command};
fn cli(data: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_waypost"));
    c.env_clear().args(["init", "--data"]).arg(data);
    c
}
fn account_config(root: &Path) -> std::path::PathBuf {
    let key =
        RsaPrivateKey::from_pkcs8_pem(include_str!("fixtures/oidc-test-private.pem")).unwrap();
    let path = root.join("oidc.json");
    std::fs::write(&path,serde_json::to_vec(&serde_json::json!({"issuer":"https://issuer.example","client_id":"test","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","keys":[{"kid":"test","n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())}]})).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}
fn disabled(root: &Path) -> Command {
    let mut c = cli(&root.join("data"));
    c.env("WAYPOST_OPERATOR_MODE", "disabled")
        .env("WAYPOST_OIDC_CONFIG_FILE", account_config(root))
        .env(
            "WAYPOST_CURSOR_SECRET",
            "test-cursor-independent-secret-at-least-32",
        )
        .env(
            "WAYPOST_CSRF_SECRET",
            "test-csrf-independent-secret-at-least-32",
        )
        .env(
            "WAYPOST_ENCRYPTION_KEYS",
            serde_json::json!({"active":"test","keys":{"test":"11".repeat(32)}}).to_string(),
        );
    c
}
#[test]
fn disabled_init_needs_no_admin_secret_and_generates_no_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let out = disabled(dir.path()).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!dir.path().join("data/admin-secret").exists());
    assert!(!dir.path().join("data/encryption-keys").exists());
    assert!(dir.path().join("data/metadata.sqlite").exists());
    assert!(String::from_utf8_lossy(&out.stdout).contains("operator access disabled"));
}
#[test]
fn missing_disabled_configuration_fails_without_auto_generating_credentials() {
    let dir = tempfile::tempdir().unwrap();
    for missing in [
        "WAYPOST_OIDC_CONFIG_FILE",
        "WAYPOST_CURSOR_SECRET",
        "WAYPOST_CSRF_SECRET",
        "WAYPOST_ENCRYPTION_KEYS",
    ] {
        let mut cmd = disabled(dir.path());
        cmd.env_remove(missing);
        let out = cmd.output().unwrap();
        assert!(
            !out.status.success(),
            "Missing {missing} unexpectedly accepted"
        );
        assert!(!dir.path().join("data/admin-secret").exists());
        assert!(!dir.path().join("data/encryption-keys").exists());
    }
}
#[test]
fn legacy_default_init_still_provisions_private_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let out = cli(dir.path()).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.path().join("admin-secret").exists());
    assert!(dir.path().join("encryption-keys").exists());
}
