//! RPC 调度器。
//!
//! 这里是工具调用进入执行阶段的唯一入口，负责完整流程：
//! 按以下顺序处理：
//!
//! 1. 校验工具是否存在，以及参数是否符合 Schema。
//! 2. 执行策略判定 → `allow` / `ask` / `deny`。
//! 3. 遇到 `ask` 时发起审批并等待用户决定。
//! 4. 执行工具、按限制截断输出并写入审计记录。
//!
//! 故意把这条链路集中在一个函数里，避免拆到多个调用方之后
//! 某条路径遗漏策略检查。

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::sync::RwLock;

use crate::audit::{AuditEntry, AuditLog, AuditOutcome, now_rfc3339, redact_arguments};
use crate::error::{BridgeError, Result, code};
use crate::policy::{Effect, Policy, PolicyEngine, Verdict};
use crate::rpc::{Incoming, JsonRpcFailure, JsonRpcSuccess, PROTOCOL_VERSION};
use crate::tools::{ReadBeforeWriteTracker, ToolContext, ToolRegistry};

/// 客户端可调用的方法。
pub mod method {
    pub const HELLO: &str = "bridge.hello";
    pub const PING: &str = "bridge.ping";
    pub const TOOLS_LIST: &str = "tools.list";
    pub const TOOLS_CALL: &str = "tools.call";
    pub const POLICY_GET: &str = "policy.get";
    pub const POLICY_SET: &str = "policy.set";
}

/// Host 主动推送给已连接客户端的通知。
pub mod notification {
    pub const POLICY_CHANGED: &str = "bridge.policyChanged";
    pub const SHUTTING_DOWN: &str = "bridge.shuttingDown";
    pub const CALL_STARTED: &str = "tools.callStarted";
    pub const CALL_FINISHED: &str = "tools.callFinished";
}

/// 审批请求在过期前保持有效的时长。
const APPROVAL_TTL: Duration = Duration::from_secs(180);

/// 调度器向用户请求决定的接口。
///
/// GUI 通过弹窗实现；无界面的 Host 则直接拒绝，
/// 以保持默认拒绝（fail-closed）的安全行为。
#[async_trait::async_trait]
pub trait Approver: Send + Sync {
    /// 展示审批请求并返回用户的决定。
    ///
    /// 返回 `None` 表示当前没有用户可以处理审批；调度器会把它
    /// 转换为拒绝，而不是默认允许。
    async fn request(&self, challenge: &ApprovalChallenge) -> Option<ApprovalDecision>;

    /// 当前是否确实能够联系到用户。
    fn is_interactive(&self) -> bool;
}

/// 一个待处理的审批请求。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalChallenge {
    pub token: String,
    pub tool: String,
    pub arguments: Value,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    /// 审批请求失效的 Unix Epoch 毫秒时间戳。
    pub expires_at: u64,
}

/// 用户的审批结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalDecision {
    pub approved: bool,
    /// 为 true 时，Host 会持久化规则，避免同类调用再次询问。
    pub remember: bool,
}

/// 始终拒绝的 `Approver`，用于测试与无界面运行。
pub struct DenyAllApprover;

#[async_trait::async_trait]
impl Approver for DenyAllApprover {
    async fn request(&self, _challenge: &ApprovalChallenge) -> Option<ApprovalDecision> {
        None
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

/// 从传输层可验证信息来看，对端的可信身份。
///
/// 该信息必须由*传输层*提供，绝不能信任消息体自行声明；否则对端
/// 可以自行宣称可信，整个认证机制就失去意义。
///
/// 调用方必须在 `bridge.hello` 中使用共享 Secret 证明身份。
/// 所有 loopback 传输都启用该要求：本机任意进程都能打开 Socket，
/// 因此真正的授权凭证是 Token 本身。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTrust {
    Untrusted,
}

/// Host 的共享状态。
pub struct Dispatcher {
    registry: Arc<ToolRegistry>,
    policy: RwLock<PolicyEngine>,
    audit: Arc<AuditLog>,
    approver: RwLock<Arc<dyn Approver>>,
    /// 握手成功后置为 true。
    authenticated: RwLock<bool>,
    /// WebSocket 传输期望的共享 Secret。
    secret: Option<String>,
    /// Host 要主动推送的通知，通过广播通道分发。
    events: tokio::sync::broadcast::Sender<Value>,
    /// 成功的 `read_file` 读取记录，用于保护结构化文件写入。
    read_tracker: ReadBeforeWriteTracker,
}

impl Dispatcher {
    pub fn new(
        registry: Arc<ToolRegistry>,
        policy: PolicyEngine,
        audit: Arc<AuditLog>,
        secret: Option<String>,
    ) -> Result<Arc<Self>> {
        let (events, _) = tokio::sync::broadcast::channel(256);
        Ok(Arc::new(Self {
            registry,
            policy: RwLock::new(policy),
            audit,
            approver: RwLock::new(Arc::new(DenyAllApprover)),
            authenticated: RwLock::new(false),
            secret,
            events,
            read_tracker: ReadBeforeWriteTracker::default(),
        }))
    }

    /// 替换审批器；GUI 窗口创建完成后会调用。
    pub async fn set_approver(&self, approver: Arc<dyn Approver>) {
        *self.approver.write().await = approver;
    }

    /// 订阅 Host 主动发出的通知。
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Value> {
        self.events.subscribe()
    }

    pub fn audit(&self) -> &Arc<AuditLog> {
        &self.audit
    }

    pub fn registry(&self) -> &Arc<ToolRegistry> {
        &self.registry
    }

    pub async fn policy_snapshot(&self) -> Policy {
        self.policy.read().await.policy().clone()
    }

    pub fn clear_read_scope(&self, scope: &str) {
        self.read_tracker.clear_scope(scope);
    }

    /// 替换策略文档并递增 revision。
    pub async fn replace_policy(&self, mut policy: Policy) -> Result<u64> {
        let revision = self.policy.read().await.policy().revision + 1;
        policy.revision = revision;
        let engine = PolicyEngine::new(policy)?;
        *self.policy.write().await = engine;

        let _ = self.events.send(json!({
            "jsonrpc": "2.0",
            "method": notification::POLICY_CHANGED,
            "params": { "revision": revision }
        }));
        Ok(revision)
    }

    /// 处理一个入站 Envelope，并按需返回响应。
    ///
    /// `trust` 表示传输层已经证明的对端身份信息；
    /// 详见 [`PeerTrust`]。
    pub async fn handle(&self, message: Incoming, trust: PeerTrust) -> Option<Value> {
        let request = match message {
            Incoming::Request(request) => request,
            // Host 主动请求对应的响应由其他路径处理。
            Incoming::Notification(note) => {
                tracing::debug!(method = %note.method, "忽略入站 Notification");
                return None;
            }
            Incoming::Response(_) => return None,
        };

        let id = request.id.clone();
        let outcome = self.dispatch(&request.method, request.params, trust).await;

        Some(match outcome {
            Ok(result) => serde_json::to_value(JsonRpcSuccess::new(id, result))
                .unwrap_or(serde_json::Value::Null),
            Err(error) => serde_json::to_value(JsonRpcFailure::new(Some(id), error))
                .unwrap_or(serde_json::Value::Null),
        })
    }

    /// 按方法名路由到对应处理器。
    async fn dispatch(
        &self,
        method: &str,
        params: Option<Value>,
        trust: PeerTrust,
    ) -> Result<Value> {
        match method {
            method::HELLO => self.handle_hello(params, trust).await,
            method::PING => Ok(json!({ "pong": true, "at": now_rfc3339() })),
            method::TOOLS_LIST => self.handle_tools_list().await,
            method::TOOLS_CALL => self.handle_tools_call(params).await,
            method::POLICY_GET => Ok(serde_json::to_value(self.policy_snapshot().await)
                .map_err(|e| BridgeError::internal(e.to_string()))?),
            method::POLICY_SET => self.handle_policy_set(params).await,
            other => Err(BridgeError::method_not_found(other)),
        }
    }

    /// 握手方法，也是认证前唯一允许调用的方法。
    async fn handle_hello(&self, params: Option<Value>, trust: PeerTrust) -> Result<Value> {
        let params = params.unwrap_or_else(|| json!({}));

        // 已由传输层验证的对端无需再次校验 Secret；详见 `PeerTrust`。
        if trust == PeerTrust::Untrusted {
            if let Some(expected) = &self.secret {
                let provided = params
                    .get("secret")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if provided != expected {
                    return Err(BridgeError::new(
                        code::NOT_AUTHENTICATED,
                        "Bridge secret did not match; copy the current token from the \
                         bridge window",
                    ));
                }
            }
        }

        let peer_protocol = params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or_default();

        // 只要求主版本一致；补丁版本差异不值得
        // 破坏一个原本可用的会话。
        if !peer_protocol.is_empty() && major_of(peer_protocol) != major_of(PROTOCOL_VERSION) {
            return Err(BridgeError::new(
                code::PROTOCOL_MISMATCH,
                format!(
                    "Extension speaks protocol {peer_protocol} but this host speaks \
                     {PROTOCOL_VERSION}"
                ),
            ));
        }

        *self.authenticated.write().await = true;

        let policy = self.policy.read().await;
        let approver = self.approver.read().await;
        let transports = vec!["websocket"];

        Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "hostVersion": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "sessionId": uuid::Uuid::new_v4().to_string(),
            "capabilities": {
                "transports": transports,
                "availableTools": self.registry.names(),
                "interactiveApproval": approver.is_interactive(),
                "auditLog": self.audit.is_enabled(),
                "policyRevision": policy.policy().revision,
            }
        }))
    }

    async fn handle_tools_list(&self) -> Result<Value> {
        let policy = self.policy.read().await;
        Ok(json!({
            "tools": self.registry.descriptors(),
            "policyRevision": policy.policy().revision,
        }))
    }

    /// 校验、授权并执行一次工具调用。
    async fn handle_tools_call(&self, params: Option<Value>) -> Result<Value> {
        let params = params.ok_or_else(|| BridgeError::invalid_params("缺少 `params`"))?;

        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| BridgeError::invalid_params("缺少 `name`"))?
            .to_string();

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let call_id = params
            .get("callId")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let origin = params
            .get("origin")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let conversation_id = params
            .get("conversationId")
            .and_then(Value::as_str)
            .map(str::to_string);

        let started = Instant::now();
        let tool = self.registry.require(&name)?;
        let descriptor = tool.descriptor();

        // 第 1 步：先按声明的 Schema 校验参数，确保任何其他逻辑执行前
        // 就拒绝格式错误的调用，不让其进入策略或执行阶段。
        validate_arguments(&descriptor.input_schema, &arguments)?;

        // 第 2 步：策略判定。
        let verdict = {
            let policy = self.policy.read().await;
            policy.evaluate(&name, &arguments, descriptor.default_effect.into())
        };

        let _ = self.events.send(json!({
            "jsonrpc": "2.0",
            "method": notification::CALL_STARTED,
            "params": { "callId": call_id, "tool": name }
        }));

        let (outcome, approved_via_human) = match verdict.effect {
            Effect::Deny => {
                self.record(
                    &call_id,
                    &name,
                    &arguments,
                    AuditOutcome::Denied,
                    &verdict,
                    &origin,
                    conversation_id.clone(),
                    None,
                )
                .await;
                return Err(BridgeError::denied(verdict.reason));
            }
            Effect::Ask => {
                let decision = self.request_approval(&name, &arguments, &verdict).await;

                match decision {
                    Some(decision) if decision.approved => {
                        if decision.remember {
                            self.remember_rule(&name, &arguments).await;
                        }
                        (AuditOutcome::Approved, true)
                    }
                    Some(_) => {
                        self.record(
                            &call_id,
                            &name,
                            &arguments,
                            AuditOutcome::Rejected,
                            &verdict,
                            &origin,
                            conversation_id.clone(),
                            None,
                        )
                        .await;
                        return Err(BridgeError::new(
                            code::TOOL_DENIED,
                            format!("用户拒绝执行 `{name}`"),
                        ));
                    }
                    None => {
                        self.record(
                            &call_id,
                            &name,
                            &arguments,
                            AuditOutcome::Expired,
                            &verdict,
                            &origin,
                            conversation_id.clone(),
                            None,
                        )
                        .await;
                        return Err(BridgeError::new(
                            code::APPROVAL_TIMEOUT,
                            format!(
                                "No approval was given for `{name}`. Approve it in the bridge \
                                 window, or add an allow rule for this tool."
                            ),
                        ));
                    }
                }
            }
            Effect::Allow => (AuditOutcome::Allowed, false),
        };
        let _ = approved_via_human;

        // 第 4 步：执行。整个调用期间都必须保持 policy guard 存活，
        // 因为 `ToolContext` 借用了负责路径约束的策略引擎。
        let policy_guard = self.policy.read().await;
        let (max_output, timeout) = (
            policy_guard.max_output_chars(),
            Duration::from_millis(policy_guard.default_timeout_ms()),
        );

        let read_scope = conversation_id.as_deref().unwrap_or(&origin);
        let context = ToolContext {
            policy: &policy_guard,
            call_id: &call_id,
            origin: &origin,
            read_tracker: &self.read_tracker,
            read_scope,
        };

        let execution =
            tokio::time::timeout(timeout, tool.execute(arguments.clone(), &context)).await;
        drop(policy_guard);

        let (final_outcome, payload) = match execution {
            Ok(Ok(output)) => {
                let duration = started.elapsed().as_millis() as u64;
                let output = output.truncate_to(max_output);
                let outcome = if output.is_error {
                    AuditOutcome::Failed
                } else {
                    outcome
                };
                let mut output = output;
                output.duration_ms = Some(duration);
                (
                    outcome,
                    serde_json::to_value(output)
                        .map_err(|e| BridgeError::internal(e.to_string()))?,
                )
            }
            Ok(Err(error)) => {
                self.record(
                    &call_id,
                    &name,
                    &arguments,
                    AuditOutcome::Failed,
                    &verdict,
                    &origin,
                    conversation_id.clone(),
                    Some(started.elapsed().as_millis() as u64),
                )
                .await;
                return Err(error);
            }
            Err(_) => {
                self.record(
                    &call_id,
                    &name,
                    &arguments,
                    AuditOutcome::Failed,
                    &verdict,
                    &origin,
                    conversation_id.clone(),
                    Some(started.elapsed().as_millis() as u64),
                )
                .await;
                return Err(BridgeError::timeout(format!(
                    "`{name}` 超过 Host 的 {timeout:?} 超时限制"
                )));
            }
        };

        self.record(
            &call_id,
            &name,
            &arguments,
            final_outcome,
            &verdict,
            &origin,
            conversation_id,
            Some(started.elapsed().as_millis() as u64),
        )
        .await;

        let _ = self.events.send(json!({
            "jsonrpc": "2.0",
            "method": notification::CALL_FINISHED,
            "params": { "callId": call_id, "tool": name, "outcome": final_outcome }
        }));

        Ok(payload)
    }

    async fn handle_policy_set(&self, params: Option<Value>) -> Result<Value> {
        let params = params.ok_or_else(|| BridgeError::invalid_params("缺少 `params`"))?;
        let policy: Policy =
            serde_json::from_value(params.get("policy").cloned().unwrap_or(params.clone()))
                .map_err(|error| {
                    BridgeError::invalid_params(format!("策略文档无效：{error}"))
                })?;

        let revision = self.replace_policy(policy).await?;
        Ok(json!({ "revision": revision }))
    }

    /// 发起审批请求并等待审批结果。
    async fn request_approval(
        &self,
        name: &str,
        arguments: &Value,
        verdict: &Verdict,
    ) -> Option<ApprovalDecision> {
        let approver = self.approver.read().await.clone();

        // 无法联系用户时，`ask` 必须默认拒绝。这条分支
        // 防止无界面 Host 静默退化为全部允许。
        if !approver.is_interactive() {
            return None;
        }

        let token = uuid::Uuid::new_v4().to_string();
        let challenge = ApprovalChallenge {
            token: token.clone(),
            tool: name.to_string(),
            arguments: redact_arguments(arguments),
            reason: verdict.reason.clone(),
            matched_rule: verdict.matched_rule.clone(),
            expires_at: now_epoch_millis() + APPROVAL_TTL.as_millis() as u64,
        };

        tokio::time::timeout(APPROVAL_TTL, approver.request(&challenge))
            .await
            .ok()
            .flatten()
    }

    /// 为用户选择“记住”的调用持久化允许规则。
    async fn remember_rule(&self, name: &str, arguments: &Value) {
        let mut policy = self.policy_snapshot().await;
        let note = format!("用户允许执行 `{name}` 并选择记住后自动添加");

        // 文件系统调用只按其访问的目录记忆，而不是
        // 放开整个文件系统：允许一个文件不应顺带开放其他位置。
        let when = if let Some(path) = arguments.get("path").and_then(Value::as_str) {
            std::path::Path::new(path)
                .parent()
                .map(|parent| crate::policy::Predicate {
                    path_within: vec![parent.display().to_string()],
                    ..Default::default()
                })
        } else if let Some(url) = arguments.get("url").and_then(Value::as_str) {
            url::Url::parse(url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(str::to_string))
                .map(|host| crate::policy::Predicate {
                    host_in: vec![host],
                    ..Default::default()
                })
        } else {
            None
        };

        policy.rules.insert(
            0,
            crate::policy::Rule {
                tool: name.to_string(),
                effect: Effect::Allow,
                when,
                note: Some(note),
            },
        );

        if let Err(error) = self.replace_policy(policy).await {
            tracing::warn!(%error, "持久化已记住的审批规则失败");
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn record(
        &self,
        call_id: &str,
        tool: &str,
        arguments: &Value,
        outcome: AuditOutcome,
        verdict: &Verdict,
        origin: &str,
        conversation_id: Option<String>,
        duration_ms: Option<u64>,
    ) {
        self.audit
            .record(AuditEntry {
                timestamp: now_rfc3339(),
                call_id: call_id.to_string(),
                tool: tool.to_string(),
                arguments: redact_arguments(arguments),
                outcome,
                matched_rule: verdict.matched_rule.clone(),
                reason: Some(verdict.reason.clone()),
                duration_ms,
                origin: origin.to_string(),
                conversation_id,
            })
            .await;
    }
}

/// 提取语义化版本的主版本号。
fn major_of(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

fn now_epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// 按工具目录实际使用的 JSON Schema 子集校验参数。
///
/// 这里刻意不实现完整 JSON Schema：只检查类型
/// 与必填字段，这正好覆盖当前工具目录的表达能力。更复杂的
/// 约束（范围、枚举等）由具体工具自身处理。
pub fn validate_arguments(schema: &crate::tools::ObjectSchema, arguments: &Value) -> Result<()> {
    let object = arguments
        .as_object()
        .ok_or_else(|| BridgeError::invalid_params("`arguments` 必须是 JSON 对象"))?;

    for required in &schema.required {
        if !object.contains_key(required) {
            return Err(BridgeError::invalid_params(format!(
                "缺少必填参数 `{required}`"
            )));
        }
    }

    for (key, value) in object {
        let Some(expected) = schema.properties.get(key) else {
            // 未知字段直接拒绝而不是静默忽略：如果悄悄丢弃一个拼错的
            // `path`，工具就可能在错误目标上运行。
            return Err(BridgeError::invalid_params(format!(
                "未知参数 `{key}`"
            )));
        };
        let Some(kind) = expected.get("type").and_then(Value::as_str) else {
            continue;
        };

        let matches = match kind {
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "array" => value.is_array(),
            "object" => value.is_object(),
            _ => true,
        };

        if !matches {
            return Err(BridgeError::invalid_params(format!(
                "参数 `{key}` 必须是 {kind} 类型"
            )));
        }

        if let Some(allowed) = expected.get("enum").and_then(Value::as_array) {
            if !allowed.contains(value) {
                return Err(BridgeError::invalid_params(format!(
                    "参数 `{key}` 必须是以下值之一：{}",
                    allowed
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
    }

    Ok(())
}
