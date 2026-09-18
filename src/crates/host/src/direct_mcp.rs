//! 可选的 Direct Remote MCP 配置。
//!
//! Direct MCP 默认关闭，建议部署在 Caddy 等 TLS 反向代理之后。
//! 提供三种认证模式：
//! - 静态 Bearer Token（最初的 Direct MCP 行为）；
//! - 面向 ChatGPT / 自定义 MCP 客户端的 OAuth Authorization Code + PKCE；
//! - 形如 `/<random>/mcp` 的高熵 Capability URL，无需额外 Header 认证。
//!
//! Capability URL 使用方便，但其安全性弱于 OAuth / Bearer：URL
//! 本身就是凭证，可能通过日志、截图或历史记录泄漏。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::mcp::McpAuth;
use crate::oauth::{OAuthServer, OAuthServerConfig};
use ltb_core::{BridgeError, Result};

const CONFIG_FILE: &str = "direct-mcp.json";
const TOKEN_FILE: &str = "direct-mcp-token";
const PATH_TOKEN_FILE: &str = "direct-mcp-path-token";
const OAUTH_CLIENT_ID_FILE: &str = "direct-mcp-oauth-client-id";
const OAUTH_CLIENT_SECRET_FILE: &str = "direct-mcp-oauth-client-secret";
const OAUTH_SIGNING_KEY_FILE: &str = "direct-mcp-oauth-signing-key";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DirectAuthMode {
    #[default]
    StaticBearer,
    OAuth,
    SecretPath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DirectMcpConfig {
    /// GUI 启动时是否自动启动 Direct listener。
    pub enabled: bool,
    /// 监听地址。使用本机反向代理时应保持为 127.0.0.1。
    pub bind: String,
    /// Direct MCP 专用端口，避开 GUI 的 loopback 探测范围。
    pub port: u16,
    /// 公网反向代理 Base URL，例如 https://ddns.example.com:8443。
    pub public_base_url: String,
    /// 静态 Bearer Token 文件覆盖配置；留空时使用当前用户默认路径。
    pub token_file: String,
    /// Direct listener 使用的认证模式。
    pub auth_mode: DirectAuthMode,
    /// 从 ChatGPT Connector 设置页复制的精确 OAuth Redirect URI。
    pub oauth_redirect_uri: String,
}

impl Default for DirectMcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: Ipv4Addr::LOCALHOST.to_string(),
            port: 8792,
            public_base_url: String::new(),
            token_file: String::new(),
            auth_mode: DirectAuthMode::StaticBearer,
            oauth_redirect_uri: String::new(),
        }
    }
}

impl DirectMcpConfig {
    pub fn socket_addr(&self) -> Result<SocketAddr> {
        let ip = self.bind.trim().parse::<IpAddr>().map_err(|error| {
            BridgeError::invalid_params(format!(
                "无效的 Direct MCP 监听地址 '{}': {error}",
                self.bind
            ))
        })?;
        Ok(SocketAddr::new(ip, self.port))
    }

    pub fn normalized_public_base_url(&self) -> Result<String> {
        let value = self.public_base_url.trim().trim_end_matches('/');
        if value.is_empty() {
            return Err(BridgeError::invalid_params(
                "当前认证模式必须配置 Direct MCP Public URL",
            ));
        }
        let parsed = url::Url::parse(value)
            .map_err(|error| BridgeError::invalid_params(format!("无效的 Public URL: {error}")))?;
        if parsed.scheme() != "https" {
            return Err(BridgeError::invalid_params(
                "Direct MCP Public URL 必须使用 HTTPS",
            ));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(BridgeError::invalid_params(
                "Direct MCP Public URL 不能包含 Query 或 Fragment",
            ));
        }
        if parsed.path() != "/" {
            return Err(BridgeError::invalid_params(
                "Direct MCP Public URL 不能包含 Path",
            ));
        }
        Ok(value.to_string())
    }
}

pub struct DirectMcpRuntime {
    pub bind: SocketAddr,
    pub mcp_path: String,
    pub auth: McpAuth,
    pub reveal_path_in_errors: bool,
}

#[derive(Debug, Clone)]
pub struct OAuthClientCredentials {
    pub client_id: String,
    pub client_secret: String,
}

pub fn config_path() -> Option<PathBuf> {
    ltb_core::config_dir().map(|dir| dir.join(CONFIG_FILE))
}

pub fn default_token_path() -> Option<PathBuf> {
    ltb_core::config_dir().map(|dir| dir.join(TOKEN_FILE))
}

pub fn token_path(config: &DirectMcpConfig) -> Option<PathBuf> {
    let configured = config.token_file.trim();
    if configured.is_empty() {
        default_token_path()
    } else {
        Some(PathBuf::from(configured))
    }
}

pub fn path_token_path() -> Option<PathBuf> {
    ltb_core::config_dir().map(|dir| dir.join(PATH_TOKEN_FILE))
}

pub fn oauth_client_id_path() -> Option<PathBuf> {
    ltb_core::config_dir().map(|dir| dir.join(OAUTH_CLIENT_ID_FILE))
}

pub fn oauth_client_secret_path() -> Option<PathBuf> {
    ltb_core::config_dir().map(|dir| dir.join(OAUTH_CLIENT_SECRET_FILE))
}

pub fn oauth_signing_key_path() -> Option<PathBuf> {
    ltb_core::config_dir().map(|dir| dir.join(OAUTH_SIGNING_KEY_FILE))
}

pub fn load_config() -> DirectMcpConfig {
    let Some(path) = config_path() else {
        return DirectMcpConfig::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_else(|error| {
            tracing::error!(
                path = %path.display(),
                %error,
                "Direct MCP 配置格式错误，改用默认配置"
            );
            DirectMcpConfig::default()
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => DirectMcpConfig::default(),
        Err(error) => {
            tracing::error!(
                path = %path.display(),
                %error,
                "读取 Direct MCP 配置失败，改用默认配置"
            );
            DirectMcpConfig::default()
        }
    }
}

pub fn save_config(config: &DirectMcpConfig) -> Result<PathBuf> {
    let path = config_path().ok_or_else(|| {
        BridgeError::internal("当前系统无法获取用户级配置目录")
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| BridgeError::from_io("创建配置目录失败", e))?;
    }
    let json = serde_json::to_string_pretty(config).map_err(|e| {
        BridgeError::internal(format!("序列化 Direct MCP 配置失败: {e}"))
    })?;
    std::fs::write(&path, json)
        .map_err(|e| BridgeError::from_io("写入 Direct MCP 配置失败", e))?;
    Ok(path)
}

pub fn load_or_create_token(config: &DirectMcpConfig) -> std::io::Result<String> {
    let Some(path) = token_path(config) else {
        return Ok(random_text_secret(32));
    };
    load_or_create_text_secret(&path, || random_text_secret(32))
}

pub fn load_or_create_path_token() -> std::io::Result<String> {
    let Some(path) = path_token_path() else {
        return Ok(random_text_secret(32));
    };
    load_or_create_text_secret(&path, || random_text_secret(32))
}

pub fn rotate_path_token() -> std::io::Result<String> {
    if let Some(path) = path_token_path() {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    load_or_create_path_token()
}

pub fn load_or_create_oauth_credentials() -> std::io::Result<OAuthClientCredentials> {
    let client_id = match oauth_client_id_path() {
        Some(path) => {
            load_or_create_text_secret(&path, || format!("ltb_{}", random_text_secret(18)))?
        }
        None => format!("ltb_{}", random_text_secret(18)),
    };
    let client_secret = match oauth_client_secret_path() {
        Some(path) => load_or_create_text_secret(&path, || random_text_secret(32))?,
        None => random_text_secret(32),
    };
    Ok(OAuthClientCredentials {
        client_id,
        client_secret,
    })
}

pub fn build_runtime(config: &DirectMcpConfig) -> Result<DirectMcpRuntime> {
    let bind = config.socket_addr()?;
    match config.auth_mode {
        DirectAuthMode::StaticBearer => {
            let token = load_or_create_token(config)
                .map_err(|error| BridgeError::from_io("读取 Direct MCP Token 失败", error))?;
            Ok(DirectMcpRuntime {
                bind,
                mcp_path: "/mcp".into(),
                auth: McpAuth::bearer(token),
                reveal_path_in_errors: true,
            })
        }
        DirectAuthMode::SecretPath => {
            let path_token = load_or_create_path_token().map_err(|error| {
                BridgeError::from_io("读取 Direct MCP Secret Path 失败", error)
            })?;
            Ok(DirectMcpRuntime {
                bind,
                mcp_path: secret_mcp_path(&path_token),
                auth: McpAuth::none(),
                reveal_path_in_errors: false,
            })
        }
        DirectAuthMode::OAuth => {
            let base_url = config.normalized_public_base_url()?;
            if config.oauth_redirect_uri.trim().is_empty() {
                return Err(BridgeError::invalid_params(
                    "OAuth 模式必须配置 Redirect URI",
                ));
            }
            let credentials = load_or_create_oauth_credentials().map_err(|error| {
                BridgeError::from_io("读取 OAuth Client 凭据失败", error)
            })?;
            let signing_key = load_or_create_oauth_signing_key()
                .map_err(|error| BridgeError::from_io("读取 OAuth 签名密钥失败", error))?;
            let resource_url = format!("{base_url}/mcp");
            let server = OAuthServer::new(OAuthServerConfig {
                public_base_url: base_url,
                resource_url,
                client_id: credentials.client_id,
                client_secret: credentials.client_secret,
                redirect_uri: config.oauth_redirect_uri.trim().to_string(),
                signing_key,
            })
            .map_err(BridgeError::invalid_params)?;
            Ok(DirectMcpRuntime {
                bind,
                mcp_path: "/mcp".into(),
                auth: McpAuth::oauth(Arc::new(server)),
                reveal_path_in_errors: true,
            })
        }
    }
}

pub fn public_mcp_url(config: &DirectMcpConfig) -> Result<String> {
    let base = config.normalized_public_base_url()?;
    let path = match config.auth_mode {
        DirectAuthMode::SecretPath => {
            let token = load_or_create_path_token().map_err(|error| {
                BridgeError::from_io("读取 Direct MCP Secret Path 失败", error)
            })?;
            secret_mcp_path(&token)
        }
        DirectAuthMode::StaticBearer | DirectAuthMode::OAuth => "/mcp".into(),
    };
    Ok(format!("{base}{path}"))
}

pub fn oauth_endpoint_lines(config: &DirectMcpConfig) -> Result<Vec<(String, String)>> {
    let base = config.normalized_public_base_url()?;
    Ok(vec![
        ("MCP URL".into(), format!("{base}/mcp")),
        ("资源 URL".into(), format!("{base}/mcp")),
        ("授权 URL".into(), format!("{base}/oauth/authorize")),
        ("Token URL".into(), format!("{base}/oauth/token")),
        (
            "OAuth Metadata".into(),
            format!("{base}/.well-known/oauth-authorization-server"),
        ),
        (
            "资源 Metadata".into(),
            format!("{base}/.well-known/oauth-protected-resource"),
        ),
        ("Authorization Server".into(), base),
    ])
}

fn secret_mcp_path(token: &str) -> String {
    format!("/{token}/mcp")
}

fn load_or_create_oauth_signing_key() -> std::io::Result<Vec<u8>> {
    let Some(path) = oauth_signing_key_path() else {
        let mut bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        return Ok(bytes);
    };
    let encoded = load_or_create_text_secret(&path, || random_text_secret(32))?;
    URL_SAFE_NO_PAD.decode(encoded.trim()).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("无效的 OAuth 签名密钥: {error}"),
        )
    })
}

fn load_or_create_text_secret(
    path: &Path,
    generate: impl FnOnce() -> String,
) -> std::io::Result<String> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let secret = generate();
    std::fs::write(path, &secret)?;
    restrict_permissions(path)?;
    Ok(secret)
}

fn random_text_secret(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buffer);
    URL_SAFE_NO_PAD.encode(buffer)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_preserve_static_bearer_behavior() {
        let config = DirectMcpConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.bind, "127.0.0.1");
        assert_eq!(config.port, 8792);
        assert_eq!(config.auth_mode, DirectAuthMode::StaticBearer);
        assert!(config.public_base_url.is_empty());
    }

    #[test]
    fn socket_addr_parses_ipv4_and_ipv6() {
        let mut config = DirectMcpConfig {
            bind: "::1".into(),
            ..Default::default()
        };
        assert_eq!(
            config.socket_addr().unwrap(),
            "[::1]:8792".parse::<SocketAddr>().unwrap()
        );
        config.bind = "not-an-ip".into();
        assert!(config.socket_addr().is_err());
    }

    #[test]
    fn secret_path_keeps_mcp_as_the_final_segment() {
        assert_eq!(secret_mcp_path("abc"), "/abc/mcp");
    }

    #[test]
    fn public_url_requires_https() {
        let mut config = DirectMcpConfig {
            public_base_url: "http://example.com:8443".into(),
            ..Default::default()
        };
        assert!(config.normalized_public_base_url().is_err());
        config.public_base_url = "https://example.com:8443/".into();
        assert_eq!(
            config.normalized_public_base_url().unwrap(),
            "https://example.com:8443"
        );
    }
}
