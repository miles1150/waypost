use std::{net::SocketAddr, path::PathBuf, rc::Rc};
use waypost::{Config, native::server};
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args.iter().any(|s| s == "--help" || s == "-h") {
        println!(
            "Waypost\n\n  waypost init [--data ./var]\n  waypost encrypt [--data ./var]\n  waypost serve [--data ./var] [--listen 127.0.0.1:8787]\n\nWAYPOST_ADMIN_SECRET overrides the private admin-secret file.\nWAYPOST_ENCRYPTION_KEYS sets the private JSON encryption keyring.\nWAYPOST_CURSOR_SECRET optionally separates cursor signing from admin rotation.\nWAYPOST_CSRF_SECRET optionally separates browser CSRF signing from admin rotation.\nWAYPOST_OPERATOR_MODE=disabled retires global operator access; requires OIDC and independent cursor/CSRF secrets.\nWAYPOST_PUBLIC_ORIGIN sets the browser Origin / generated HTTP URLs."
        );
        return Ok(());
    }
    let command = &args[0];
    if !["init", "serve", "encrypt"].contains(&command.as_str()) {
        return Err("Unknown command; use --help.".into());
    }
    let mut data = PathBuf::from("var");
    let mut address: SocketAddr = "127.0.0.1:8787".parse()?;
    let mut i = 1;
    while i < args.len() {
        let v = args.get(i + 1).ok_or("Missing option value.")?;
        match args[i].as_str() {
            "--data" => data = PathBuf::from(v),
            "--listen" => address = v.parse()?,
            _ => return Err("Unknown option.".into()),
        }
        i += 2;
    }
    let operator_mode = std::env::var("WAYPOST_OPERATOR_MODE").unwrap_or_else(|_| "enabled".into());
    if !["enabled", "disabled"].contains(&operator_mode.as_str()) {
        return Err("Operator mode must be enabled or disabled.".into());
    }
    let operator_disabled = operator_mode == "disabled";
    if operator_disabled && command == "encrypt" {
        return Err("Offline encryption maintenance requires explicitly enabled operator mode; disabled mode never re-enables it.".into());
    }
    if operator_disabled
        && (std::env::var("WAYPOST_OIDC_CONFIG_FILE").is_err()
            || std::env::var("WAYPOST_CURSOR_SECRET").is_err()
            || std::env::var("WAYPOST_CSRF_SECRET").is_err())
    {
        return Err("Disabled operator requires explicit OIDC configuration and independent cursor/CSRF secrets.".into());
    }
    std::fs::create_dir_all(&data)?;
    let secret = match std::env::var("WAYPOST_ADMIN_SECRET") {
        Ok(value) => value,
        Err(_) => {
            let path = data.join("admin-secret");
            if operator_disabled && !path.exists() {
                String::new()
            } else {
                if !path.exists() {
                    use std::io::Write;
                    let mut bytes = [0; 32];
                    getrandom::getrandom(&mut bytes)
                        .map_err(|_| "Unable to generate credential.")?;
                    let mut options = std::fs::OpenOptions::new();
                    options.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600);
                    }
                    match options.open(&path) {
                        Ok(mut file) => {
                            file.write_all(hex::encode(bytes).as_bytes())?;
                            file.sync_all()?
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                std::fs::read_to_string(path)?.trim().to_owned()
            }
        }
    };
    let _runtime_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(data.join("runtime-lock"))?;
    _runtime_lock.try_lock().map_err(
        |_| "This data directory is in use; stop the service before initialization or migration.",
    )?;
    let origin =
        std::env::var("WAYPOST_PUBLIC_ORIGIN").unwrap_or_else(|_| format!("http://{address}"));
    let keyring = match std::env::var("WAYPOST_ENCRYPTION_KEYS") {
        Ok(value) => zeroize::Zeroizing::new(value),
        Err(_) => {
            let path = data.join("encryption-keys");
            if !path.exists() {
                if operator_disabled {
                    return Err("Disabled operator never generates secrets; configure or restore the encryption keyring.".into());
                }
                if data.join("metadata.sqlite").exists() {
                    return Err("Encryption keyring is missing. Restore encryption-keys, or explicitly configure WAYPOST_ENCRYPTION_KEYS for legacy migration.".into());
                }
                use std::io::Write;
                let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
                getrandom::getrandom(bytes.as_mut())
                    .map_err(|_| "Unable to generate encryption key.")?;
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                match options.open(&path) {
                    Ok(mut file) => {
                        file.write_all(serde_json::json!({"active":"v1","keys":{"v1":hex::encode(bytes.as_ref())}}).to_string().as_bytes())?;
                        file.sync_all()?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
            }
            zeroize::Zeroizing::new(std::fs::read_to_string(path)?)
        }
    };
    let migration_admin = secret.clone();
    let config = Config {
        admin_secret: secret,
        public_origin: origin.clone(),
    };
    let app = if operator_disabled {
        // The temporary builder is never served before OIDC and independent signing
        // keys are installed and with_operator_mode validates the complete setup.
        waypost::App::new(
            waypost::native::SqliteDb::open(data.join("metadata.sqlite"))?,
            waypost::native::FileStore::open(data.join("objects"))?,
            config,
        )
    } else {
        server::open_app(&data, config)?
    };
    let app = if let Ok(secret) = std::env::var("WAYPOST_CURSOR_SECRET") {
        app.with_cursor_secret(&secret)?
    } else {
        app
    };
    let app = if let Ok(secret) = std::env::var("WAYPOST_CSRF_SECRET") {
        app.with_csrf_secret(&secret)?
    } else {
        app
    };
    let allow_legacy = std::env::var("WAYPOST_ALLOW_LEGACY_PLAINTEXT").is_ok_and(|v| v == "1");
    let app = app.with_encryption_keys(&keyring, allow_legacy)?;
    let app = if let Ok(path) = std::env::var("WAYPOST_OIDC_CONFIG_FILE") {
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.len() > 65536 {
            return Err("Invalid private OIDC configuration file.".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("OIDC configuration must be mode 0600.".into());
            }
        }
        let raw = zeroize::Zeroizing::new(std::fs::read_to_string(path)?);
        let config: waypost::accounts_oidc::OidcConfig =
            serde_json::from_str(&raw).map_err(|_| "Invalid OIDC configuration.")?;
        let exchange = waypost::accounts_oidc::OidcHttpExchange::new(&config)?;
        let limit = std::env::var("WAYPOST_ACCOUNT_SIGNUP_LIMIT")
            .unwrap_or_else(|_| "0".into())
            .parse()?;
        app.with_accounts(config, Rc::new(exchange), limit)?
    } else {
        app
    };
    let app = if let Ok(path) = std::env::var("WAYPOST_OAUTH_CLIENTS_FILE") {
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.len() > 65536 {
            return Err("Invalid OAuth client configuration file.".into());
        }
        let config: waypost::OAuthConfig = serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|_| "Invalid OAuth client configuration.")?;
        app.with_oauth(config)?
    } else {
        app
    };
    let app = app.with_onboarding_mode(
        &std::env::var("WAYPOST_ONBOARDING_MODE").unwrap_or_else(|_| "legacy".into()),
    )?;
    let app = app.with_operator_mode(&operator_mode)?;
    let app = Rc::new(app);
    if command == "init" {
        if operator_disabled {
            println!(
                "Initialized {} with operator access disabled; account authentication is configured. No operator credential was generated.",
                data.display()
            );
            return Ok(());
        }
        println!(
            "Initialized {}. Admin credential: {}/admin-secret (or WAYPOST_ADMIN_SECRET).",
            data.display(),
            data.display()
        );
        return Ok(());
    }
    if command == "encrypt" {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            for kind in [
                "objects",
                "messages",
                "uploads",
                "blobs",
                "memory_items",
                "access_requests",
            ] {
                let mut cursor = serde_json::Value::Null;
                loop {
                    let response = app
                        .handle(waypost::Request::json(
                            "POST",
                            "/admin/v0/maintenance/encrypt",
                            &migration_admin,
                            serde_json::json!({"kind":kind,"dry_run":false,"cursor":cursor}),
                        ))
                        .await;
                    let value: serde_json::Value = serde_json::from_slice(&response.body)
                        .map_err(|_| "Invalid migration response.")?;
                    if response.status != 200 {
                        return Err(
                            "Encryption migration failed; retry with the same keyring.".into()
                        );
                    }
                    if value["data"]["has_more"] != true {
                        break;
                    }
                    cursor = value["data"]["next_cursor"].clone();
                }
                println!("Encrypted {kind}.");
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        return Ok(());
    }
    eprintln!("Waypost listening at {address}; MCP: {origin}/mcp");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    tokio::task::LocalSet::new().block_on(&runtime, server::listen(address, app))?;
    Ok(())
}
