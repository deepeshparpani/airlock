use airlock_core::{
    get_port_file_path, get_socket_path, CircuitBreaker, PortManifest, SingletonLock,
};
use serde::Deserialize;
use serde_json::Value;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

const STAGE_1_SCHEMA: &str = r#"{"type":"object","properties":{"thinking":{"type":"string"},"decision":{"type":"string","enum":["allow","deny"]},"confidence":{"type":"string","enum":["high","low"]},"reason":{"type":"string"}},"required":["thinking","decision","confidence","reason"]}"#;

#[derive(Deserialize)]
struct ClientRequest {
    token: String,
    prompt: String,
}

struct WorkerManager {
    child: Option<Child>,
    gemini_dir: PathBuf,
    query_count: usize,
}

impl WorkerManager {
    fn new() -> Self {
        let user = env::var("USER").unwrap_or_else(|_| "default".to_string());
        let gemini_dir = env::temp_dir().join(format!("airlock_gemini_{}", user));
        Self {
            child: None,
            gemini_dir,
            query_count: 0,
        }
    }

    fn setup_isolated_gemini_dir(&self) {
        let cli_dir = self.gemini_dir.join("antigravity-cli");
        let _ = fs::create_dir_all(&cli_dir);
        let _ = fs::create_dir_all(&self.gemini_dir);
        let home = env::var("HOME").unwrap_or_default();
        let root_gemini = PathBuf::from(&home).join(".gemini");
        let real_cli = root_gemini.join("antigravity-cli");

        let link_file = |src: &PathBuf, dst: &PathBuf| {
            if src.exists() {
                if dst.exists() || dst.is_symlink() {
                    let _ = fs::remove_file(dst);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;
                    if symlink(src, dst).is_err() {
                        let _ = fs::copy(src, dst);
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = fs::copy(src, dst);
                }
            }
        };

        for item in ["oauth_creds.json", "google_accounts.json", "installation_id", "settings.json"] {
            let src = root_gemini.join(item);
            link_file(&src, &self.gemini_dir.join(item));
            link_file(&src, &cli_dir.join(item));
        }

        for item in ["settings.json", "installation_id", "antigravity-oauth-token"] {
            let src = real_cli.join(item);
            link_file(&src, &cli_dir.join(item));
        }
    }

    async fn spawn_worker(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.setup_isolated_gemini_dir();
        if let Some(mut old) = self.child.take() {
            let _ = old.kill().await;
        }

        let mut cmd = Command::new("agy");
        cmd.arg(format!("--gemini_dir={}", self.gemini_dir.display()))
            .arg("--input-format")
            .arg("stream-json")
            .arg("--output-format")
            .arg("stream-json")
            .arg(format!("--json-schema={}", STAGE_1_SCHEMA))
            .arg("--model")
            .arg("gemini-3.8-flash-low")
            .env("AGY_HOOK_BYPASS", "1")
            .env("AIRLOCK_HOOK_BYPASS", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .current_dir(env::temp_dir());

        let mut child = cmd.spawn()?;

        // Wait for worker init message
        if let Some(stdout) = child.stdout.as_mut() {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let _ = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;
        }

        self.child = Some(child);
        self.query_count = 0;
        Ok(())
    }

    async fn query(
        &mut self,
        prompt: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if self.child.is_none() || self.query_count >= 25 {
            self.spawn_worker().await?;
        }

        let payload = serde_json::json!({
            "event": "user",
            "message": { "content": prompt }
        });
        let payload_str = format!("{}\n", payload);

        let child = self.child.as_mut().ok_or("No worker child available")?;

        let stdin = child.stdin.as_mut().ok_or("Worker stdin not open")?;
        stdin.write_all(payload_str.as_bytes()).await?;
        stdin.flush().await?;

        let stdout = child.stdout.as_mut().ok_or("Worker stdout not open")?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();

        loop {
            line.clear();
            let read_res =
                tokio::time::timeout(Duration::from_secs(30), reader.read_line(&mut line)).await?;
            if read_res? == 0 {
                return Err("EOF from worker".into());
            }

            if let Ok(val) = serde_json::from_str::<Value>(&line) {
                if val.get("event").and_then(|v| v.as_str()) == Some("result") {
                    let result_obj = val.get("result").cloned().unwrap_or(Value::Null);
                    if let Some(structured) = result_obj.get("structured_output") {
                        if structured.is_object() && structured.get("decision").is_some() {
                            self.query_count += 1;
                            return Ok(structured.to_string());
                        }
                    }
                    if let Some(resp_str) = result_obj.get("response").and_then(|v| v.as_str()) {
                        self.query_count += 1;
                        return Ok(resp_str.to_string());
                    }
                }
            }
        }
    }
}

async fn handle_connection<R, W>(
    reader: R,
    mut writer: W,
    auth_token: Arc<String>,
    breaker: Arc<Mutex<CircuitBreaker>>,
    worker: Arc<Mutex<WorkerManager>>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    if let Ok(Ok(n)) =
        tokio::time::timeout(Duration::from_secs(5), buf_reader.read_line(&mut line)).await
    {
        if n == 0 {
            return;
        }

        let req: ClientRequest = match serde_json::from_str(&line.trim()) {
            Ok(r) => r,
            Err(_) => {
                let err_resp = serde_json::json!({
                    "decision": "deny",
                    "confidence": "high",
                    "reason": "Malformed request JSON"
                });
                let _ = writer.write_all(format!("{}\n", err_resp).as_bytes()).await;
                return;
            }
        };

        if req.token != *auth_token {
            let err_resp = serde_json::json!({
                "decision": "deny",
                "confidence": "high",
                "reason": "Unauthorized: invalid authentication token"
            });
            let _ = writer.write_all(format!("{}\n", err_resp).as_bytes()).await;
            return;
        }

        // Check circuit breaker
        {
            let cb = breaker.lock().await;
            if cb.is_open() {
                let err_resp = serde_json::json!({
                    "decision": "deny",
                    "confidence": "low",
                    "reason": "Circuit breaker active: repeated backend failures"
                });
                let _ = writer.write_all(format!("{}\n", err_resp).as_bytes()).await;
                return;
            }
        }

        // Query worker
        let eval_res = {
            let mut w = worker.lock().await;
            w.query(&req.prompt).await
        };

        match eval_res {
            Ok(json_str) => {
                let _ = writer.write_all(format!("{}\n", json_str).as_bytes()).await;
            }
            Err(e) => {
                {
                    let cb = breaker.lock().await;
                    cb.record_failure();
                }
                let err_resp = serde_json::json!({
                    "decision": "deny",
                    "confidence": "low",
                    "reason": format!("Airlock daemon worker error: {}", e)
                });
                let _ = writer.write_all(format!("{}\n", err_resp).as_bytes()).await;
            }
        }
        let _ = writer.flush().await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = match SingletonLock::acquire() {
        Some(l) => l,
        None => {
            eprintln!("airlock-daemon: another daemon instance is already active, exiting.");
            return Ok(());
        }
    };

    let auth_token = Arc::new(format!(
        "{:016x}{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        std::process::id() as u64
    ));

    // Bind loopback TCP listener
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = tcp_listener.local_addr()?.port();

    let manifest = PortManifest::new(port, (*auth_token).clone());
    manifest.write_atomic()?;

    // Bind Unix domain socket on /tmp/airlock_daemon_{USER}.sock
    let sock_path = get_socket_path();
    if sock_path.exists() {
        let _ = fs::remove_file(&sock_path);
    }
    let unix_listener = UnixListener::bind(&sock_path)?;
    if let Ok(metadata) = fs::metadata(&sock_path) {
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(&sock_path, perms);
    }

    eprintln!(
        "\x1b[92m[airlock-daemon]\x1b[0m Listening on UDS: {} and TCP: 127.0.0.1:{}",
        sock_path.display(),
        port
    );

    let breaker = Arc::new(Mutex::new(CircuitBreaker::new(3, Duration::from_secs(60))));
    let worker = Arc::new(Mutex::new(WorkerManager::new()));

    // Warm up worker in background
    let worker_clone = worker.clone();
    tokio::spawn(async move {
        let mut w = worker_clone.lock().await;
        let _ = w.spawn_worker().await;
    });

    let token_tcp = auth_token.clone();
    let breaker_tcp = breaker.clone();
    let worker_tcp = worker.clone();

    // TCP accept loop
    tokio::spawn(async move {
        loop {
            if let Ok((socket, _)) = tcp_listener.accept().await {
                let (r, w) = socket.into_split();
                let t = token_tcp.clone();
                let b = breaker_tcp.clone();
                let wk = worker_tcp.clone();
                tokio::spawn(async move {
                    handle_connection(r, w, t, b, wk).await;
                });
            }
        }
    });

    let token_uds = auth_token.clone();
    let breaker_uds = breaker.clone();
    let worker_uds = worker.clone();

    // UDS accept loop
    let uds_handle = tokio::spawn(async move {
        loop {
            if let Ok((socket, _)) = unix_listener.accept().await {
                let (r, w) = socket.into_split();
                let t = token_uds.clone();
                let b = breaker_uds.clone();
                let wk = worker_uds.clone();
                tokio::spawn(async move {
                    handle_connection(r, w, t, b, wk).await;
                });
            }
        }
    });

    // Handle shutdown
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\n\x1b[93m[airlock-daemon]\x1b[0m Shutdown signal received, exiting.");
        }
        _ = uds_handle => {}
    }

    // Cleanup paths
    let port_path = get_port_file_path();
    if port_path.exists() {
        let _ = fs::remove_file(&port_path);
    }
    if sock_path.exists() {
        let _ = fs::remove_file(&sock_path);
    }

    Ok(())
}
