//! MCP（Model Context Protocol）传输实现。
//!
//! 该端点实现 MCP Streamable HTTP，让 ChatGPT、
//! Codex 或其他 MCP 客户端能够访问本地工具。
//! 默认接入路径是 OpenAI Secure MCP Tunnel；也可以额外启用
//! 第二个 listener，并通过用户自管的 HTTPS 反向代理对外暴露。
//! 两条路径刻意使用不同凭据，因此启用 Direct
//! 访问不会降低 loopback / Tunnel 端点的安全性。
//!
//! 这里刻意**不维护第二套工具实现**：所有 MCP 方法都会
//! 转换到其他传输共用的 [`Dispatcher`]，因此策略
//! 判定、审批与审计行为完全一致，不受前端来源影响。
//! `tools/list` 直接从注册表描述生成，
//! `tools/call` 会转换为 Bridge 的 `tools.call`，再映射回
//! MCP Result 结构。
//!
//! ## 安全性
//!
//! 普通 listener 绑定到 `127.0.0.1`，并使用与 loopback HTTP
//! 相同的共享 Secret。Direct Remote MCP 使用独立的
//! 静态 Bearer Token，并认证所有 MCP 操作，包括会话
//! 删除。为兼容旧客户端，loopback DELETE 行为保持不变。
//! 详见 `docs/chatgpt-mcp.md` 与 `docs/direct-mcp.md`。
//!
//! ## 协议范围
//!
//! 已实现：`initialize`、`server/discover`（2026-07-28 无状态
//! Discovery）、`ping`、`tools/list`、`tools/call`，以及返回空结果的 `resources/*`
//! 与 `prompts/*`，同时确认 `notifications/initialized` /
//! `notifications/cancelled`。服务端会跟踪 Session，
//! 因此遵循有状态生命周期的客户端会获得 `Mcp-Session-Id`；
//! 没有 Session ID 的请求则按无状态方式处理，以兼容新的
//! 自包含 MCP 请求。所有 JSON-RPC 响应都会回显
//! 请求 `id`；严格客户端（例如官方 Go SDK）会拒绝
//! 缺失或为 null 的响应 ID。

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use ltb_core::dispatch::{Dispatcher, PeerTrust};
use ltb_core::error::code as bridge_code;
use ltb_core::rpc::{Incoming as BridgeIncoming, JsonRpcRequest, RequestId};
use ltb_core::tools::{DefaultEffect, ToolDescriptor};

/// MCP 规范定义的 JSON-RPC 错误码。
mod mcp_code {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
    /// MCP 专用：客户端发送了服务端未知的 `Mcp-Session-Id`。
    pub const SESSION_NOT_FOUND: i64 = -32001;
}

/// 默认 MCP 端点。
const MCP_PATH: &str = "/mcp";

/// 无需 Secret 的健康检查端点，与 HTTP 传输保持一致。
const HEALTH_PATH: &str = "/health";

/// 允许的最大请求体大小（字节）。
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Bridge Secret 使用的 Header，与 loopback HTTP
/// 传输同名，因此同一 Secret 可保护相关传输。
const SECRET_HEADER: &str = "x-dlb-secret";

/// Direct Remote MCP 使用的标准 HTTP Bearer Authorization Header。
const AUTHORIZATION_HEADER: &str = "authorization";

/// MCP Session Header；客户端在 `initialize` 后持续回传。
const SESSION_HEADER: &str = "mcp-session-id";

/// 单个 MCP listener 接受的认证方式。
#[derive(Clone)]
pub enum McpAuth {
    BridgeSecret(String),
    StaticBearer(String),
    None,
    OAuth(Arc<crate::oauth::OAuthServer>),
}

impl McpAuth {
    pub fn bridge_secret(secret: String) -> Self {
        Self::BridgeSecret(secret)
    }

    pub fn bearer(token: String) -> Self {
        Self::StaticBearer(token)
    }

    pub fn none() -> Self {
        Self::None
    }

    pub fn oauth(server: Arc<crate::oauth::OAuthServer>) -> Self {
        Self::OAuth(server)
    }

    fn accepts(&self, headers: &HeaderMap) -> bool {
        match self {
            Self::BridgeSecret(expected) => headers
                .get(SECRET_HEADER)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|provided| constant_time_eq(provided, expected)),
            Self::StaticBearer(expected) => {
                bearer_token(headers).is_some_and(|provided| constant_time_eq(provided, expected))
            }
            Self::None => true,
            Self::OAuth(server) => {
                bearer_token(headers).is_some_and(|token| server.validate_access_token(token))
            }
        }
    }

    fn delete_requires_auth(&self) -> bool {
        matches!(self, Self::StaticBearer(_) | Self::OAuth(_))
    }

    fn oauth_server(&self) -> Option<Arc<crate::oauth::OAuthServer>> {
        match self {
            Self::OAuth(server) => Some(server.clone()),
            _ => None,
        }
    }

    fn resource_metadata_url(&self) -> Option<String> {
        match self {
            Self::OAuth(server) => Some(server.resource_metadata_url()),
            _ => None,
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION_HEADER)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

/// MCP 协议版本 Header，会在响应中回显。
const PROTOCOL_HEADER: &str = "mcp-protocol-version";

/// 当前服务端实现的协议版本。客户端主动请求版本时会回显其版本，
/// 该常量用于客户端未提供版本时的回退。
const DEFAULT_PROTOCOL_VERSION: &str = "2026-07-28";

/// 服务端可处理的协议版本，按新到旧排序。与
/// 官方 Go SDK 的 `supportedProtocolVersions` 保持一致，并通过
/// `server/discover` 公布，避免旧式协商往返。
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];

/// MCP 调用写入审计日志时使用的 Origin；同时附加 User-Agent，
/// 便于审计日志显示具体是哪个客户端发起调用。
const MCP_ORIGIN_PREFIX: &str = "mcp";

/// 共享 Session 注册表。这样有状态客户端若回传
/// 陈旧的 `Mcp-Session-Id`（例如 Host 重启后），会收到明确错误，
/// 而不是静默断开。
struct McpState {
    sessions: Mutex<HashMap<String, ()>>,
}

impl McpState {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn insert(&self, id: String) {
        tracing::debug!(%id, "MCP Session 已初始化");
        self.sessions
            .lock()
            .expect("Session 锁已中毒")
            .insert(id, ());
    }

    fn contains(&self, id: &str) -> bool {
        self.sessions
            .lock()
            .expect("Session 锁已中毒")
            .contains_key(id)
    }

    fn remove(&self, id: &str) -> bool {
        self.sessions
            .lock()
            .expect("Session 锁已中毒")
            .remove(id)
            .is_some()
    }
}

#[derive(Clone)]
struct RequestContext {
    dispatcher: Arc<Dispatcher>,
    auth: Arc<McpAuth>,
    state: Arc<McpState>,
    mcp_path: Arc<String>,
    reveal_path_in_errors: bool,
    allow_get_probe: bool,
    peer: SocketAddr,
}

/// 运行默认 `/mcp` Server，直到进程退出。
pub async fn serve(
    listener: TcpListener,
    dispatcher: Arc<Dispatcher>,
    auth: Arc<McpAuth>,
) -> std::io::Result<()> {
    serve_at(
        listener,
        dispatcher,
        auth,
        MCP_PATH.to_string(),
        true,
        false,
    )
    .await
}

/// 在指定端点路径运行 MCP。Capability URL 模式会把
/// `reveal_path_in_errors` 设为 false，避免探测与日志泄漏路径。
pub async fn serve_at(
    listener: TcpListener,
    dispatcher: Arc<Dispatcher>,
    auth: Arc<McpAuth>,
    mcp_path: String,
    reveal_path_in_errors: bool,
    allow_get_probe: bool,
) -> std::io::Result<()> {
    let state = Arc::new(McpState::new());
    let address = listener.local_addr()?;
    if reveal_path_in_errors {
        tracing::info!(%address, path = %mcp_path, "MCP 传输开始监听");
    } else {
        tracing::info!(%address, "MCP Capability URL 传输开始监听");
    }
    let mcp_path = Arc::new(mcp_path);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(%error, "接受 MCP 连接失败");
                continue;
            }
        };

        let context = RequestContext {
            dispatcher: dispatcher.clone(),
            auth: auth.clone(),
            state: state.clone(),
            mcp_path: mcp_path.clone(),
            reveal_path_in_errors,
            allow_get_probe,
            peer,
        };

        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let context = context.clone();
                async move { handle(request, context).await }
            });

            if let Err(error) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!(%peer, %error, "MCP 连接已关闭");
            }
        });
    }
}

/// 构造带 CORS Header 的 JSON 响应，与 HTTP 传输保持一致。
fn json_response(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", "no-store")
        .header("access-control-allow-origin", "*")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}"))))
}

fn unauthorized_response(auth: &McpAuth, body: String) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", "no-store")
        .header("access-control-allow-origin", "*");
    if let Some(metadata) = auth.resource_metadata_url() {
        builder = builder.header(
            "www-authenticate",
            format!(r#"Bearer resource_metadata="{metadata}""#),
        );
    }
    builder
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}"))))
}

fn sse_probe_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .body(Full::new(Bytes::from_static(b": ltb-mcp-ready\n\n")))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// MCP 结构的 JSON-RPC 错误对象。
fn rpc_error(code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": null, "error": { "code": code, "message": message.into() } })
}

/// Header 存在且为有效 UTF-8 时读取为 String。
fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// 处理一个 HTTP 请求。
async fn handle(
    request: Request<Incoming>,
    context: RequestContext,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let RequestContext {
        dispatcher,
        auth,
        state,
        mcp_path,
        reveal_path_in_errors,
        allow_get_probe,
        peer,
    } = context;
    // CORS Preflight 在 Origin / Secret 检查之前响应，
    // 以便浏览器客户端完成握手。
    if request.method() == Method::OPTIONS {
        return Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("access-control-allow-origin", "*")
            .header("access-control-allow-methods", "POST, GET, DELETE, OPTIONS")
            .header(
                "access-control-allow-headers",
                "content-type, mcp-session-id, x-dlb-secret, authorization",
            )
            .header("access-control-max-age", "600")
            .body(Full::new(Bytes::new()))
            .expect("static response must build"));
    }

    if request.uri().path() == HEALTH_PATH {
        let body = serde_json::json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string();
        return Ok(json_response(StatusCode::OK, body));
    }

    if let Some(oauth) = auth.oauth_server() {
        if oauth.handles_path(request.uri().path()) {
            return Ok(oauth.handle(request).await);
        }
    }

    if request.uri().path() != mcp_path.as_str() {
        let message = if reveal_path_in_errors {
            format!("未知路径 `{}`; use {}", request.uri().path(), mcp_path)
        } else {
            "未知路径".to_string()
        };
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            rpc_error(mcp_code::INVALID_REQUEST, message).to_string(),
        ));
    }

    // ChatGPT 自定义 Connector 的验证器目前会对无状态 2026 MCP 端点
    // 发起 SSE 风格的 GET Probe。2026 规范允许
    // GET 返回 405，但这里返回短暂的 text/event-stream Probe
    // 可以提升兼容性，同时不会创建持久化服务端推送通道。
    if request.method() == Method::GET && allow_get_probe {
        if !auth.accepts(request.headers()) {
            let body = rpc_error(
                mcp_code::SESSION_NOT_FOUND,
                "MCP 认证缺失或无效",
            )
            .to_string();
            return Ok(unauthorized_response(&auth, body));
        }
        return Ok(sse_probe_response());
    }

    // 为兼容旧客户端，保留 loopback DELETE 行为。
    // 可选的 Direct Remote listener 面向公网，因此
    // 删除 Session 时同样必须校验 Bearer Token。
    if request.method() == Method::DELETE {
        if auth.delete_requires_auth() && !auth.accepts(request.headers()) {
            tracing::warn!(%peer, "拒绝未认证的 MCP Session 删除请求");
            let body = rpc_error(
                mcp_code::SESSION_NOT_FOUND,
                "MCP 认证缺失或无效",
            )
            .to_string();
            return Ok(unauthorized_response(&auth, body));
        }
        return handle_delete(request.headers(), &state, &dispatcher);
    }

    if request.method() != Method::POST {
        let body = rpc_error(
            mcp_code::INVALID_REQUEST,
            "MCP 端点仅接受 POST（不支持 GET Streaming）",
        )
        .to_string();
        return Ok(json_response(StatusCode::METHOD_NOT_ALLOWED, body));
    }

    if !auth.accepts(request.headers()) {
        tracing::warn!(%peer, "拒绝未认证的 MCP 请求");
        let body = rpc_error(
            mcp_code::SESSION_NOT_FOUND,
            "MCP 认证缺失或无效",
        )
        .to_string();
        return Ok(unauthorized_response(&auth, body));
    }

    let headers = request.headers().clone();
    let body = match request.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(error) => {
            let body = rpc_error(
                mcp_code::PARSE_ERROR,
                format!("读取请求体失败: {error}"),
            )
            .to_string();
            return Ok(json_response(StatusCode::BAD_REQUEST, body));
        }
    };

    if body.len() > MAX_BODY_BYTES {
        let body = rpc_error(
            mcp_code::INVALID_REQUEST,
            format!("请求体超过 {MAX_BODY_BYTES} 字节上限"),
        )
        .to_string();
        return Ok(json_response(StatusCode::PAYLOAD_TOO_LARGE, body));
    }

    let text = String::from_utf8_lossy(&body);
    let value: Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            let body = rpc_error(
                mcp_code::PARSE_ERROR,
                format!("JSON-RPC 格式错误: {error}"),
            )
            .to_string();
            return Ok(json_response(StatusCode::BAD_REQUEST, body));
        }
    };

    handle_jsonrpc(value, &dispatcher, &state, &headers).await
}

/// 处理 Session 终止。
fn handle_delete(
    headers: &HeaderMap,
    state: &Arc<McpState>,
    dispatcher: &Arc<Dispatcher>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let session_id = headers
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let removed = session_id
        .as_deref()
        .map(|id| state.remove(id))
        .unwrap_or(false);

    if removed {
        if let Some(session_id) = session_id.as_deref() {
            dispatcher.clear_read_scope(session_id);
        }
        Ok(json_response(StatusCode::OK, "{}".into()))
    } else {
        Ok(json_response(
            StatusCode::NOT_FOUND,
            rpc_error(
                mcp_code::SESSION_NOT_FOUND,
                "未知或已关闭的 Session",
            )
            .to_string(),
        ))
    }
}

/// 路由一个已经解码的 JSON-RPC 消息。
async fn handle_jsonrpc(
    value: Value,
    dispatcher: &Arc<Dispatcher>,
    state: &Arc<McpState>,
    headers: &HeaderMap,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let object = match value.as_object() {
        Some(object) => object,
        None => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                rpc_error(
                    mcp_code::INVALID_REQUEST,
                    "MCP Payload 必须是 JSON 对象",
                )
                .to_string(),
            ));
        }
    };

    let method = object.get("method").and_then(Value::as_str);

    // Notification 不包含 ID，也不会收到 JSON-RPC 响应；HTTP
    // 状态码本身就是确认（202 Accepted）。
    if object.contains_key("id") {
        // 有状态客户端会回传 Session ID。未知 ID 通常表示
        // Host 已重启（或客户端伪造 ID），这里应明确返回错误，
        // 而不是在损坏的 Session 上静默继续。没有
        // Session ID 的请求会按无状态方式处理，以保持新式
        // 自包含 MCP 请求可用。
        if let Some(session_id) = header_str(headers, SESSION_HEADER) {
            if method != Some("initialize") && !state.contains(&session_id) {
                return Ok(json_response(
                    StatusCode::OK,
                    rpc_error(
                        mcp_code::SESSION_NOT_FOUND,
                        format!("未知或已过期的 Session `{session_id}`；请重新 initialize"),
                    )
                    .to_string(),
                ));
            }
        }

        let result = route_request(method, object, dispatcher, state, headers).await;

        let request_id = object.get("id").cloned().unwrap_or(Value::Null);

        let (status, payload, session_id, protocol_version) = match result {
            Ok((reply, session_id, protocol_version)) => {
                // 成功结果通过完整 JSON-RPC Envelope 返回：调用方
                // 通过 `id` 匹配请求并读取 `result`。所有完整结果
                // 都带 `resultType: "complete"`（SEP-2322）；OpenAI
                // Connector 验证与 tunnel-client E2E 测试都要求
                // 非 initialize 响应包含该字段，而其他客户端
                // 会忽略未知 Result 字段。
                let result = if method == Some("initialize") {
                    reply
                } else {
                    match reply {
                        Value::Object(mut map) => {
                            map.insert(
                                "resultType".to_string(),
                                Value::String("complete".to_string()),
                            );
                            Value::Object(map)
                        }
                        other => other,
                    }
                };
                let envelope = json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": result,
                });
                (StatusCode::OK, envelope, session_id, protocol_version)
            }
            Err((code, message)) => {
                // HTTP 200 中的错误响应也必须回显请求 ID。官方 Go SDK 等客户端
                // 会拒绝 ID 与请求
                // 不匹配的响应（id:null 也无效），否则往往只会表现为
                // 难以理解的“invalid request”解码失败。
                let envelope = json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": { "code": code, "message": message },
                });
                (StatusCode::OK, envelope, None, None)
            }
        };

        let mut builder = Response::builder()
            .status(status)
            .header("content-type", "application/json; charset=utf-8");
        if let Some(session_id) = session_id {
            builder = builder.header(SESSION_HEADER, session_id);
        }
        if let Some(protocol_version) = protocol_version {
            builder = builder.header(PROTOCOL_HEADER, protocol_version);
        }

        let response = builder
            .header("cache-control", "no-store")
            .body(Full::new(Bytes::from(payload.to_string())))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}"))));
        return Ok(response);
    }

    // Notification。MCP 规范只定义了少数几种；其他通知
    // 仍然确认接收，但不返回响应。
    match method {
        Some("notifications/initialized") => {}
        Some("notifications/cancelled") => {}
        Some("notifications/progress") => {}
        Some(other) => {
            tracing::debug!(method = %other, "忽略未知 MCP Notification");
        }
        None => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                rpc_error(
                    mcp_code::INVALID_REQUEST,
                    "MCP 消息既没有 id，也没有 method",
                )
                .to_string(),
            ));
        }
    }

    Ok(Response::builder()
        .status(StatusCode::ACCEPTED)
        .header("content-type", "application/json; charset=utf-8")
        .body(Full::new(Bytes::from("{}")))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("{}")))))
}

/// 单次 MCP 请求的路由结果：要么返回结果值与可选的
/// Session / Protocol Header，要么返回 JSON-RPC 错误码与消息。
type RouteOutcome = Result<(Value, Option<String>, Option<String>), (i64, String)>;

/// 按方法名分发请求。
async fn route_request(
    method: Option<&str>,
    object: &serde_json::Map<String, Value>,
    dispatcher: &Arc<Dispatcher>,
    state: &Arc<McpState>,
    headers: &HeaderMap,
) -> RouteOutcome {
    let params = object.get("params").cloned();

    match method {
        Some("initialize") => Ok(handle_initialize(params, state, headers)),
        Some("server/discover") => Ok(handle_server_discover()),
        Some("ping") => Ok((json!({}), None, None)),
        Some("tools/list") => Ok((handle_tools_list(dispatcher), None, None)),
        Some("tools/call") => handle_tools_call(dispatcher, params, headers).await,
        // 返回最小但完整的结果，避免 Connector Discovery 继续无意义探测；
        // 当前 Server 不暴露 Resource 或 Prompt。
        Some("resources/list") => Ok((json!({ "resources": [] }), None, None)),
        Some("resources/templates/list") => Ok((json!({ "resourceTemplates": [] }), None, None)),
        Some("prompts/list") => Ok((json!({ "prompts": [] }), None, None)),
        Some("logging/setLevel") => Ok((json!({}), None, None)),
        Some("completion/complete") => Err((
            mcp_code::INVALID_PARAMS,
            "当前没有可用于 Completion 的 Prompt".into(),
        )),
        Some(other) => Err((
            mcp_code::METHOD_NOT_FOUND,
            format!("未找到方法：{other}"),
        )),
        None => Err((
            mcp_code::INVALID_REQUEST,
            "MCP 请求缺少 method".into(),
        )),
    }
}

/// `initialize`：协商协议、创建 Session，并声明
/// Server 能力。
fn handle_initialize(
    params: Option<Value>,
    state: &Arc<McpState>,
    headers: &HeaderMap,
) -> (Value, Option<String>, Option<String>) {
    let params = params.unwrap_or_else(|| json!({}));

    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| DEFAULT_PROTOCOL_VERSION.to_string());

    // 已有 Session 再次 initialize 时刷新记录，避免泄漏旧 Session。
    let session_id = headers
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    if let Some(client_info) = params.get("clientInfo") {
        tracing::debug!(client = ?client_info, "MCP client initialized");
    }
    state.insert(session_id.clone());

    let result = json!({
        "protocolVersion": requested,
        "capabilities": {
            "tools": { "listChanged": false },
            "resources": {},
            "prompts": {},
            "logging": {}
        },
        "serverInfo": {
            "name": "local-tool-bridge",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": concat!(
            "该 Server 通过 Local Tool Bridge 暴露本地文件系统、Shell 与 HTTP 工具。",
            "所有调用都会经过本地策略控制，执行前可能需要在 Bridge 窗口中人工审批。",
            "路径必须使用绝对路径；Windows 上优先使用正斜杠（C:/Users/...）而不是反斜杠。",
            "Shell 工具是真实命令行环境，执行破坏性命令前必须谨慎确认。"
        )
    });

    (result, Some(session_id), Some(requested))
}

/// `server/discover`（SEP-2575，协议 2026-07-28）：现代客户端会优先尝试的
/// 无状态 Discovery 握手，发生在旧式 `initialize` 之前。响应
/// 严格匹配官方 SDK 的 `DiscoverResult`（通用 Envelope
/// 额外加入 `resultType: "complete"`）：包含降序的 `supportedVersions`、
/// Server Capability 与 `_meta` 中的身份信息。OpenAI Connector
/// 会校验该结构；缺少任意字段都会被拒绝为
/// “server/discover response was invalid”。
fn handle_server_discover() -> (Value, Option<String>, Option<String>) {
    let result = json!({
        "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "_meta": {
            "io.modelcontextprotocol/serverInfo": {
                "name": "local-tool-bridge",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });
    (result, None, Some(DEFAULT_PROTOCOL_VERSION.to_string()))
}

/// `tools/list`：把注册表中的工具描述转换为 MCP Tool 结构。
fn handle_tools_list(dispatcher: &Arc<Dispatcher>) -> Value {
    let tools: Vec<Value> = dispatcher
        .registry()
        .descriptors()
        .iter()
        .map(mcp_tool)
        .collect();
    json!({ "tools": tools })
}

/// 把一个 Bridge ToolDescriptor 转换为 MCP Tool 定义。
fn mcp_tool(descriptor: &ToolDescriptor) -> Value {
    json!({
        "name": mcp_name(&descriptor.name),
        "description": mcp_description(descriptor),
        "inputSchema": descriptor.input_schema,
        "outputSchema": mcp_output_schema(),
    })
}

fn mcp_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "content": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": { "const": "text" },
                        "text": { "type": "string" }
                    },
                    "required": ["type", "text"],
                    "additionalProperties": false
                }
            },
            "isError": { "type": "boolean" },
            "truncated": { "type": "boolean" },
            "originalBytes": { "type": "integer", "minimum": 0 },
            "durationMs": { "type": "integer", "minimum": 0 }
        },
        "required": ["content", "isError"],
        "additionalProperties": false
    })
}

/// MCP 工具名要求匹配 `^[a-zA-Z0-9_-]{1,64}$`，因此不能包含
/// Bridge 名称中的点（如 `fs.read_file`）。内置工具使用下划线进行
/// 无损替换，这也是模型实际调用时使用的名称。
fn mcp_name(bridge_name: &str) -> String {
    bridge_name.replace('.', "_")
}

/// 通过注册表反向解析 [`mcp_name`]，因此调用方即使直接发送
/// 带点的 Bridge 名称也能正常处理。
fn bridge_name<'a>(descriptors: &'a [ToolDescriptor], candidate: &str) -> Option<&'a str> {
    for descriptor in descriptors {
        if descriptor.name == candidate || mcp_name(&descriptor.name) == candidate {
            return Some(&descriptor.name);
        }
    }
    None
}

/// 构造 ChatGPT / Codex 读取的工具说明；先使用 Bridge
/// Descriptor，再追加远程模型需要知道的约束。
fn mcp_description(descriptor: &ToolDescriptor) -> String {
    let mut text = format!("{}\n\n{}", descriptor.summary, descriptor.description);

    if descriptor.default_effect != DefaultEffect::Allow {
        text.push_str("\n\n此工具执行前可能需要人工审批。");
    }

    if descriptor.name.starts_with("fs.") {
        text.push_str(
            "\n路径必须使用绝对路径。Windows 上优先使用正斜杠（C:/Users/...），不要使用反斜杠。",
        );
    }

    text
}

/// `tools/call`：把 MCP Tool Call 转换给 Bridge Dispatcher，随后
/// 把结果（或失败）映射回 MCP Result 结构。
async fn handle_tools_call(
    dispatcher: &Arc<Dispatcher>,
    params: Option<Value>,
    headers: &HeaderMap,
) -> RouteOutcome {
    let params =
        params.ok_or_else(|| (mcp_code::INVALID_PARAMS, "缺少 `params`".to_string()))?;

    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| (mcp_code::INVALID_PARAMS, "缺少工具 `name`".to_string()))?;

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    // 先把 MCP 名称还原为 Bridge 名称；模型自行编造的名称会在
    // 真正分发前直接拒绝。
    let descriptors = dispatcher.registry().descriptors();
    let bridge = bridge_name(&descriptors, name)
        .ok_or_else(|| (mcp_code::INVALID_PARAMS, format!("未知工具：{name}")))?;

    let user_agent = headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    // 按字符安全截断：直接按字节切片可能截断多字节 User-Agent。
    let origin: String = format!("{MCP_ORIGIN_PREFIX}:{user_agent}")
        .chars()
        .take(128)
        .collect();

    let conversation_id = header_str(headers, SESSION_HEADER);

    // 所有调用共用一个 Dispatcher 与一条审计链路：这里构造的调用与扩展
    // 原本发送的调用一致，只增加调用方不可见的合成 ID。
    let reply = dispatcher
        .handle(
            BridgeIncoming::Request(JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: RequestId::Number(0),
                method: "tools.call".into(),
                params: Some(json!({
                    "name": bridge,
                    "arguments": arguments,
                    "callId": uuid::Uuid::new_v4().to_string(),
                    "origin": origin,
                    "conversationId": conversation_id,
                })),
            }),
            PeerTrust::Untrusted,
        )
        .await;

    let Some(reply) = reply else {
        return Err((
            mcp_code::INTERNAL_ERROR,
            "Bridge 没有返回响应".into(),
        ));
    };

    if let Some(result) = reply.get("result") {
        // 成功的 Bridge 调用返回序列化后的 ToolOutput：包含 content
        // Block 以及 isError / truncated / duration 等 Metadata。MCP 需要 content
        // 与 isError；structuredContent 则保留完整结构化结果。
        let content = result.get("content").cloned().unwrap_or_else(|| json!([]));
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        return Ok((
            json!({
                "content": content,
                "structuredContent": result,
                "isError": is_error
            }),
            None,
            None,
        ));
    }

    if let Some(error) = reply.get("error") {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .unwrap_or(bridge_code::INTERNAL_ERROR);
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("工具执行失败")
            .to_string();

        // 未知工具属于调用方错误；其他失败（拒绝、
        // 审批超时、沙箱拒绝、执行失败）都作为 *Tool
        // Result* 返回，让模型能够看到并调整，而不是收到
        // 协议级错误。
        if code == bridge_code::TOOL_NOT_FOUND {
            return Err((mcp_code::INVALID_PARAMS, message));
        }

        let content = json!([{ "type": "text", "text": message }]);
        return Ok((
            json!({
                "content": content,
                "structuredContent": {
                    "content": content,
                    "isError": true
                },
                "isError": true
            }),
            None,
            None,
        ));
    }

    Err((
        mcp_code::INTERNAL_ERROR,
        "Bridge 返回了无法识别的 Envelope".into(),
    ))
}

/// 绑定 loopback MCP listener，并持续服务直到进程退出。
pub async fn bind(port: u16) -> std::io::Result<TcpListener> {
    bind_address(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await
}

/// 把 MCP 绑定到指定地址。若调用方暴露非 loopback 地址，
/// 必须自行提供 TLS Termination；Direct Remote MCP 通常仍
/// 监听 loopback，由 Caddy 接管公网 :443。
pub async fn bind_address(address: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(address).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_secret_auth_is_preserved() {
        let auth = McpAuth::bridge_secret("bridge-secret".into());
        let mut headers = HeaderMap::new();
        headers.insert(SECRET_HEADER, "bridge-secret".parse().unwrap());
        assert!(auth.accepts(&headers));

        headers.insert(SECRET_HEADER, "wrong".parse().unwrap());
        assert!(!auth.accepts(&headers));
    }

    #[test]
    fn direct_bearer_auth_accepts_standard_authorization_header() {
        let auth = McpAuth::bearer("public-token".into());
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION_HEADER, "Bearer public-token".parse().unwrap());
        assert!(auth.accepts(&headers));

        headers.insert(AUTHORIZATION_HEADER, "Bearer wrong".parse().unwrap());
        assert!(!auth.accepts(&headers));
        assert!(!auth.accepts(&HeaderMap::new()));
        assert!(auth.delete_requires_auth());

        let loopback = McpAuth::bridge_secret("bridge-secret".into());
        assert!(!loopback.delete_requires_auth());

        let no_auth = McpAuth::none();
        assert!(no_auth.accepts(&HeaderMap::new()));
        assert!(!no_auth.delete_requires_auth());
    }

    #[test]
    fn mcp_names_are_safe_and_reversible() {
        assert_eq!(mcp_name("fs.read_file"), "fs_read_file");
        assert_eq!(mcp_name("shell.exec"), "shell_exec");
        assert_eq!(mcp_name("http.request"), "http_request");
    }

    #[test]
    fn bridge_name_accepts_both_spellings() {
        let descriptors = vec![ToolDescriptor {
            name: "fs.read_file".into(),
            summary: "s".into(),
            description: "d".into(),
            category: "fs".into(),
            input_schema: ltb_core::tools::ObjectSchema {
                schema_type: "object".into(),
                properties: Default::default(),
                required: vec!["path".into()],
            },
            mutating: false,
            default_effect: DefaultEffect::Ask,
            latency_hint: "instant".into(),
        }];

        assert_eq!(
            bridge_name(&descriptors, "fs_read_file"),
            Some("fs.read_file")
        );
        assert_eq!(
            bridge_name(&descriptors, "fs.read_file"),
            Some("fs.read_file")
        );
        assert_eq!(bridge_name(&descriptors, "nope"), None);
    }

    #[test]
    fn tool_shape_is_mcp_compliant() {
        let descriptor = ToolDescriptor {
            name: "fs.read_file".into(),
            summary: "读取文件".into(),
            description: "从磁盘读取 UTF-8 文本文件。".into(),
            category: "fs".into(),
            input_schema: ltb_core::tools::ObjectSchema {
                schema_type: "object".into(),
                properties: serde_json::from_value(json!({
                    "path": { "type": "string", "description": "绝对路径" }
                }))
                .unwrap(),
                required: vec!["path".into()],
            },
            mutating: false,
            default_effect: DefaultEffect::Ask,
            latency_hint: "instant".into(),
        };

        let tool = mcp_tool(&descriptor);
        assert_eq!(tool["name"], "fs_read_file");
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert_eq!(tool["inputSchema"]["required"], json!(["path"]));
        assert_eq!(tool["outputSchema"]["type"], "object");
        assert_eq!(
            tool["outputSchema"]["required"],
            json!(["content", "isError"])
        );
        assert_eq!(
            tool["outputSchema"]["properties"]["content"]["items"]["properties"]["type"]["const"],
            "text"
        );
        let description = tool["description"].as_str().unwrap();
        assert!(description.contains("可能需要人工审批"));
        assert!(description.contains("正斜杠"));
    }
}
