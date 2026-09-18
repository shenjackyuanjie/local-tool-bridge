//! `ltb-host` —— 作为 Library 使用的本地 Bridge 进程实现。

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use ltb_core::audit::AuditLog;
use ltb_core::dispatch::Dispatcher;
use ltb_core::policy::{Policy, PolicyEngine};
use ltb_core::tools::ToolRegistry;
use ltb_core::{Result, audit_path, policy_path};

pub mod direct_mcp;
pub mod http;
pub mod mcp;
pub mod mcp_servers;
pub mod oauth;
pub mod tunnel;
pub mod websocket;

/// 读取策略文档；失败时回退到内置默认配置。
pub fn load_policy(path: Option<&PathBuf>) -> Policy {
    let path = match path.cloned().or_else(policy_path) {
        Some(path) => path,
        None => return Policy::default(),
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<Policy>(&text) {
            Ok(policy) => policy,
            Err(error) => {
                tracing::error!(
                    path = %path.display(),
                    %error,
                    "策略文件格式错误，回退到默认配置"
                );
                Policy::default()
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Policy::default(),
        Err(error) => {
            tracing::error!(
                path = %path.display(),
                %error,
                "读取策略失败，使用默认配置"
            );
            Policy::default()
        }
    }
}

/// 持久化策略文档，并在需要时创建配置目录。
pub fn save_policy(policy: &Policy) -> Result<PathBuf> {
    let path = policy_path().ok_or_else(|| {
        ltb_core::BridgeError::internal("当前系统无法获取用户级配置目录")
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ltb_core::BridgeError::from_io("创建配置目录失败", e)
        })?;
    }
    let json = serde_json::to_string_pretty(policy)
        .map_err(|e| ltb_core::BridgeError::internal(format!("序列化策略失败: {e}")))?;
    std::fs::write(&path, json)
        .map_err(|e| ltb_core::BridgeError::from_io("写入策略文件失败", e))?;
    Ok(path)
}

/// 读取已持久化的 Bridge Secret；首次运行时自动生成。
pub fn load_or_create_secret() -> std::io::Result<String> {
    let Some(dir) = ltb_core::config_dir() else {
        return Ok(uuid::Uuid::new_v4().to_string());
    };
    let path = dir.join("secret");
    std::fs::create_dir_all(&dir)?;
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let secret = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    std::fs::write(&path, &secret)?;
    restrict_permissions(&path)?;
    Ok(secret)
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// 根据磁盘配置构建调度器。已启用的外部 stdio MCP
/// Server 会在这里完成发现，然后调度器再共享给各传输层。
pub async fn build_dispatcher(
    policy_override: Option<PathBuf>,
    audit_enabled: bool,
) -> Result<Arc<Dispatcher>> {
    let policy = load_policy(policy_override.as_ref());
    let engine = PolicyEngine::new(policy)?;
    let audit = match (audit_enabled, audit_path()) {
        (true, Some(path)) => AuditLog::open(path, true).await?,
        _ => AuditLog::open(PathBuf::new(), false).await?,
    };

    let mut registry = ToolRegistry::with_builtins();
    mcp_servers::load_into_registry(&mut registry).await;
    let registry = Arc::new(registry);
    let secret = load_or_create_secret().ok();
    Dispatcher::new(registry, engine, Arc::new(audit), secret)
}

pub async fn run_websocket(
    port: u16,
    dispatcher: Arc<Dispatcher>,
    secret: String,
) -> std::io::Result<SocketAddr> {
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await?;
    let address = listener.local_addr()?;
    tokio::spawn(websocket::serve(listener, dispatcher, Arc::new(secret)));
    Ok(address)
}

pub async fn run_http(
    port: u16,
    dispatcher: Arc<Dispatcher>,
    secret: String,
) -> std::io::Result<SocketAddr> {
    let listener = http::bind(port).await?;
    let address = listener.local_addr()?;
    tokio::spawn(http::serve(listener, dispatcher, Arc::new(secret)));
    Ok(address)
}

pub async fn run_mcp(
    port: u16,
    dispatcher: Arc<Dispatcher>,
    secret: String,
) -> std::io::Result<SocketAddr> {
    let listener = mcp::bind(port).await?;
    let address = listener.local_addr()?;
    tokio::spawn(mcp::serve(
        listener,
        dispatcher,
        Arc::new(mcp::McpAuth::bridge_secret(secret)),
    ));
    Ok(address)
}

/// 启动可选的 Direct Remote MCP listener，并使用独立的
/// 静态 Bearer Token 认证。现有 loopback / Tunnel 路径彼此独立，
/// 行为保持不变。
pub async fn run_direct_mcp(
    bind: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    bearer_token: String,
) -> std::io::Result<SocketAddr> {
    let listener = mcp::bind_address(bind).await?;
    let address = listener.local_addr()?;
    tokio::spawn(mcp::serve(
        listener,
        dispatcher,
        Arc::new(mcp::McpAuth::bearer(bearer_token)),
    ));
    Ok(address)
}

#[derive(Debug, Clone)]
pub struct DirectMcpRunning {
    pub address: SocketAddr,
    pub mcp_path: String,
}

/// 使用 GUI 持久化配置启动 Direct MCP；这是 OAuth 与 Secret
/// Capability URL 模式的统一入口。
pub async fn run_configured_direct_mcp(
    config: &direct_mcp::DirectMcpConfig,
    dispatcher: Arc<Dispatcher>,
) -> Result<DirectMcpRunning> {
    let runtime = direct_mcp::build_runtime(config)?;
    let listener = mcp::bind_address(runtime.bind)
        .await
        .map_err(|error| ltb_core::BridgeError::from_io("绑定 Direct MCP 监听地址失败", error))?;
    let address = listener.local_addr().map_err(|error| {
        ltb_core::BridgeError::from_io("读取 Direct MCP 监听地址失败", error)
    })?;
    let mcp_path = runtime.mcp_path.clone();
    tokio::spawn(mcp::serve_at(
        listener,
        dispatcher,
        Arc::new(runtime.auth),
        runtime.mcp_path,
        runtime.reveal_path_in_errors,
        true,
    ));
    Ok(DirectMcpRunning { address, mcp_path })
}
