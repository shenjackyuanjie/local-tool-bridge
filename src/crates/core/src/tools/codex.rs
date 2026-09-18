//! 基于现有 Bridge 工具封装的 Codex 兼容工具 Schema。
//!
//! 能复用的语义都刻意委托给现有文件系统 / Shell 工具，
//! 从而让策略、沙箱、审计、输出限制
//! 与平台 Shell 选择都只维护一套实现。

use std::time::Instant;

use serde_json::{Value, json};

use super::{Tool, ToolContext, ToolDescriptor, ToolOutput, required_str};
use crate::error::{BridgeError, Result};

fn object_schema(properties: Value, required: &[&str]) -> super::ObjectSchema {
    super::ObjectSchema {
        schema_type: "object".into(),
        properties: serde_json::from_value(properties)
            .expect("schema properties must be an object"),
        required: required.iter().map(|s| (*s).to_string()).collect(),
    }
}

/// Codex `read_file` Schema 的轻量兼容包装。
pub struct ReadFile;

#[async_trait::async_trait]
impl Tool for ReadFile {
    fn descriptor(&self) -> ToolDescriptor {
        let mut descriptor = super::fs::ReadFile.descriptor();
        descriptor.name = "read_file".into();
        descriptor.summary = "从磁盘读取 UTF-8 文本文件（Codex Schema）".into();
        descriptor.description =
            "使用 Bridge 现有的文件系统沙箱与编码支持读取文件。"
                .into();
        descriptor.category = "codex-filesystem".into();
        descriptor
    }

    async fn execute(&self, arguments: Value, context: &ToolContext<'_>) -> Result<ToolOutput> {
        super::fs::ReadFile.execute(arguments, context).await
    }
}

/// Codex `list_dir` Schema 的轻量兼容包装。
pub struct ListDir;

#[async_trait::async_trait]
impl Tool for ListDir {
    fn descriptor(&self) -> ToolDescriptor {
        let mut descriptor = super::fs::ListDir.descriptor();
        descriptor.name = "list_dir".into();
        descriptor.summary = "列出目录内容（Codex Schema）".into();
        descriptor.description =
            "使用 Bridge 现有的文件系统沙箱列出目录内容。".into();
        descriptor.category = "codex-filesystem".into();
        descriptor
    }

    async fn execute(&self, arguments: Value, context: &ToolContext<'_>) -> Result<ToolOutput> {
        super::fs::ListDir.execute(arguments, context).await
    }
}

/// Codex 形态的一次性执行工具，复用 Bridge 的 Shell 执行器。
pub struct Exec;

#[async_trait::async_trait]
impl Tool for Exec {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "exec".into(),
            summary: "使用已配置的 Shell 执行命令".into(),
            description: "Codex 兼容的命令执行 Schema。Bridge 保持 Shell \
                          选择由 GUI 策略控制；可选 shell 字段仅用于 \
                          Schema 兼容，不能覆盖已配置的 Shell。"
                .into(),
            category: "codex-execution".into(),
            mutating: true,
            default_effect: super::DefaultEffect::Ask,
            latency_hint: "slow".into(),
            input_schema: object_schema(
                json!({
                    "cmd": { "type": "string", "description": "要执行的命令行" },
                    "shell": {
                        "type": "string",
                        "description": "兼容字段；Shell 由 \
                                        Bridge 策略选择",
                    },
                    "login": { "type": "boolean", "default": true },
                    "tty": { "type": "boolean", "default": false },
                    "yield_time_ms": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 600000,
                        "default": 10000,
                    },
                    "timeout_ms": { "type": "integer", "minimum": 100, "maximum": 600000 },
                    "max_output_tokens": { "type": "integer", "minimum": 1, "maximum": 100000 },
                    "cwd": { "type": "string", "description": "绝对工作目录" },
                    "env": { "type": "object", "description": "额外环境变量" },
                }),
                &["cmd"],
            ),
        }
    }

    async fn execute(&self, arguments: Value, context: &ToolContext<'_>) -> Result<ToolOutput> {
        let cmd = required_str(&arguments, "cmd")?;
        let mut translated = arguments.clone();
        if let Some(object) = translated.as_object_mut() {
            object.insert("command".into(), Value::String(cmd));
            if let Some(timeout) = object.get("timeout_ms").cloned() {
                object.insert("timeoutMs".into(), timeout);
            }
        }
        super::shell::Exec.execute(translated, context).await
    }
}

/// 同一执行路径的别名。Bridge 当前刻意保持进程模型
/// 简单，继续复用现有 Shell 执行器。
pub struct UnifiedExec;

#[async_trait::async_trait]
impl Tool for UnifiedExec {
    fn descriptor(&self) -> ToolDescriptor {
        let mut descriptor = Exec.descriptor();
        descriptor.name = "unified_exec".into();
        descriptor.summary = "通过 unified exec Schema 执行命令".into();
        descriptor.description = "Codex unified-exec 兼容 Schema，底层复用 Bridge \
                                  现有的 Shell 执行器与策略控制。"
            .into();
        descriptor
    }

    async fn execute(&self, arguments: Value, context: &ToolContext<'_>) -> Result<ToolOutput> {
        Exec.execute(arguments, context).await
    }
}

/// Codex 的自由格式 Patch 工具。这里使用独立解析器，确保 Patch
/// 语义不依赖 Shell 引号规则或平台特定工具。
pub struct ApplyPatch;

#[async_trait::async_trait]
impl Tool for ApplyPatch {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "apply_patch".into(),
            summary: "使用 Patch 创建、更新、删除或移动文件".into(),
            description: "把 Codex 面向文件的 Patch 格式直接应用到沙箱\
                          文件系统。已有文件必须先在同一会话中通过 read_file \
                          读取；陈旧读取会被拒绝。支持 Add File、\
                          Delete File、Update File，以及带 Move to 的 Update File。"
                .into(),
            category: "codex-filesystem".into(),
            mutating: true,
            default_effect: super::DefaultEffect::Ask,
            latency_hint: "instant".into(),
            input_schema: object_schema(
                json!({
                    "patch": {
                        "type": "string",
                        "description": "Codex apply_patch 文档，必须以 \
                                        *** Begin Patch 开始并以 *** End Patch 结束",
                    },
                }),
                &["patch"],
            ),
        }
    }

    async fn execute(&self, arguments: Value, context: &ToolContext<'_>) -> Result<ToolOutput> {
        let started = Instant::now();
        let patch = required_str(&arguments, "patch")?;
        let changes = parse_patch(&patch)?;
        if changes.is_empty() {
            return Err(BridgeError::invalid_params(
                "Patch 中没有任何文件操作",
            ));
        }

        // 在发生任何修改前，先预检 Patch 涉及的全部已有文件。
        // 这样可以避免多文件 Patch 已经修改一部分后，
        // 才发现后面的目标文件从未读取。
        for change in &changes {
            match change {
                PatchChange::Add { .. } => {}
                PatchChange::Delete { path } => {
                    require_prior_read(context, path).await?;
                }
                PatchChange::Update {
                    path,
                    move_to,
                    ..
                } => {
                    require_prior_read(context, path).await?;
                    if let Some(move_to) = move_to {
                        let source = context.policy.sandbox().resolve(path, false)?;
                        let target = context.policy.sandbox().resolve(move_to, false)?;
                        if target != source && target.exists() {
                            require_prior_read(context, move_to).await?;
                        }
                    }
                }
            }
        }

        let mut applied = Vec::new();
        for change in changes {
            match change {
                PatchChange::Add { path, content } => {
                    let path = context.policy.sandbox().resolve(&path, false)?;
                    if path.exists() {
                        return Err(BridgeError::invalid_params(format!(
                            "无法新增 `{}`：文件已存在",
                            path.display()
                        )));
                    }
                    if let Some(parent) = path.parent() {
                        tokio::fs::create_dir_all(parent).await.map_err(|e| {
                            BridgeError::from_io("创建 Patch 父目录失败", e)
                        })?;
                    }
                    tokio::fs::write(&path, content)
                        .await
                        .map_err(|e| BridgeError::from_io("新增文件失败", e))?;
                    context.read_tracker.invalidate(context.read_scope, &path);
                    applied.push(format!("A {}", path.display()));
                }
                PatchChange::Delete { path } => {
                    let path = context.policy.sandbox().resolve(&path, false)?;
                    if path.is_dir() {
                        return Err(BridgeError::invalid_params(format!(
                            "apply_patch 不能删除目录 `{}`",
                            path.display()
                        )));
                    }
                    tokio::fs::remove_file(&path)
                        .await
                        .map_err(|e| BridgeError::from_io("删除文件失败", e))?;
                    context.read_tracker.invalidate(context.read_scope, &path);
                    applied.push(format!("D {}", path.display()));
                }
                PatchChange::Update {
                    path,
                    move_to,
                    hunks,
                } => {
                    let path = context.policy.sandbox().resolve(&path, false)?;
                    let original = tokio::fs::read_to_string(&path)
                        .await
                        .map_err(|e| BridgeError::from_io("读取 Patch 目标失败", e))?;
                    let updated = apply_hunks(&original, &hunks)?;
                    let target = if let Some(move_to) = move_to {
                        context.policy.sandbox().resolve(&move_to, false)?
                    } else {
                        path.clone()
                    };
                    if let Some(parent) = target.parent() {
                        tokio::fs::create_dir_all(parent).await.map_err(|e| {
                            BridgeError::from_io("创建 Patch 目标父目录失败", e)
                        })?;
                    }
                    tokio::fs::write(&target, updated)
                        .await
                        .map_err(|e| BridgeError::from_io("写入 Patch 后的文件失败", e))?;
                    if target != path {
                        tokio::fs::remove_file(&path).await.map_err(|e| {
                            BridgeError::from_io("删除移动后的源文件失败", e)
                        })?;
                    }
                    context.read_tracker.invalidate(context.read_scope, &path);
                    context.read_tracker.invalidate(context.read_scope, &target);
                    applied.push(format!(
                        "U {}{}",
                        path.display(),
                        if target != path {
                            format!(" -> {}", target.display())
                        } else {
                            String::new()
                        }
                    ));
                }
            }
        }

        Ok(ToolOutput {
            content: vec![super::ContentBlock::text(format!(
                "已应用 {} 个 Patch 操作，耗时 {} ms：\n{}",
                applied.len(),
                started.elapsed().as_millis(),
                applied.join("\n")
            ))],
            is_error: false,
            truncated: false,
            original_bytes: None,
            duration_ms: Some(started.elapsed().as_millis() as u64),
        })
    }
}

async fn require_prior_read(context: &ToolContext<'_>, raw_path: &str) -> Result<()> {
    let path = context.policy.sandbox().resolve(raw_path, false)?;
    if !path.exists() {
        return Err(BridgeError::invalid_params(format!(
            "Patch 目标不存在：{}",
            path.display()
        )));
    }
    if path.is_dir() {
        return Err(BridgeError::invalid_params(format!(
            "Patch 目标是目录：{}",
            path.display()
        )));
    }
    let current = tokio::fs::read(&path)
        .await
        .map_err(|error| BridgeError::from_io("校验 Patch 目标失败", error))?;
    context
        .read_tracker
        .require_current(context.read_scope, &path, &current)
}

#[derive(Debug)]
enum PatchChange {
    Add {
        path: String,
        content: Vec<u8>,
    },
    Delete {
        path: String,
    },
    Update {
        path: String,
        move_to: Option<String>,
        hunks: Vec<Vec<String>>,
    },
}

fn parse_patch(patch: &str) -> Result<Vec<PatchChange>> {
    let lines: Vec<&str> = patch.lines().collect();
    if lines.first().copied() != Some("*** Begin Patch")
        || lines.last().copied() != Some("*** End Patch")
    {
        return Err(BridgeError::invalid_params(
            "apply_patch Envelope 无效；应以 *** Begin Patch 开始并以 *** End Patch 结束",
        ));
    }
    let mut i = 1;
    let mut changes = Vec::new();
    while i + 1 < lines.len() {
        let header = lines[i];
        if let Some(path) = header.strip_prefix("*** Add File: ") {
            i += 1;
            let mut content = String::new();
            while i + 1 < lines.len() && !lines[i].starts_with("*** ") {
                let line = lines[i];
                if let Some(rest) = line.strip_prefix('+') {
                    content.push_str(rest);
                    content.push('\n');
                } else {
                    return Err(BridgeError::invalid_params(
                        "Add File 内容行必须以 `+` 开头",
                    ));
                }
                i += 1;
            }
            changes.push(PatchChange::Add {
                path: path.trim().into(),
                content: content.into_bytes(),
            });
            continue;
        }
        if let Some(path) = header.strip_prefix("*** Delete File: ") {
            changes.push(PatchChange::Delete {
                path: path.trim().into(),
            });
            i += 1;
            continue;
        }
        if let Some(path) = header.strip_prefix("*** Update File: ") {
            let source = path.trim().to_string();
            i += 1;
            let mut move_to = None;
            if i + 1 < lines.len() && lines[i].starts_with("*** Move to: ") {
                move_to = Some(lines[i]["*** Move to: ".len()..].trim().to_string());
                i += 1;
            }
            let mut hunks = Vec::new();
            let mut current = Vec::new();
            while i + 1 < lines.len() && !lines[i].starts_with("*** ") {
                if lines[i].starts_with("@@") {
                    if !current.is_empty() {
                        hunks.push(std::mem::take(&mut current));
                    }
                } else {
                    current.push(lines[i].to_string());
                }
                i += 1;
            }
            if !current.is_empty() {
                hunks.push(current);
            }
            changes.push(PatchChange::Update {
                path: source,
                move_to,
                hunks,
            });
            continue;
        }
        return Err(BridgeError::invalid_params(format!(
            "未知的 apply_patch 操作 `{header}`"
        )));
    }
    Ok(changes)
}

fn apply_hunks(original: &str, hunks: &[Vec<String>]) -> Result<String> {
    let mut lines: Vec<String> = original.split_inclusive('\n').map(str::to_string).collect();
    if !original.is_empty() && !original.ends_with('\n') && lines.is_empty() {
        lines.push(original.to_string());
    }
    for hunk in hunks {
        let old: Vec<String> = hunk
            .iter()
            .filter_map(|line| line.strip_prefix(' ').or_else(|| line.strip_prefix('-')))
            .map(|s| format_with_original_ending(s, original))
            .collect();
        let new: Vec<String> = hunk
            .iter()
            .filter_map(|line| match line.chars().next() {
                Some(' ') | Some('+') => line.get(1..),
                _ => None,
            })
            .map(|s| format_with_original_ending(s, original))
            .collect();
        let pos = find_sequence(&lines, &old).ok_or_else(|| {
            BridgeError::invalid_params("Patch Hunk 上下文与目标文件不匹配")
        })?;
        lines.splice(pos..pos + old.len(), new);
    }
    Ok(lines.concat())
}

fn format_with_original_ending(s: &str, original: &str) -> String {
    if original.contains("\r\n") {
        format!("{}\r\n", s.strip_suffix('\r').unwrap_or(s))
    } else {
        format!("{}\n", s)
    }
}

fn find_sequence(lines: &[String], needle: &[String]) -> Option<usize> {
    if needle.is_empty() {
        return Some(lines.len());
    }
    lines.windows(needle.len()).position(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(a, b)| a.trim_end_matches(['\r', '\n']) == b.trim_end_matches(['\r', '\n']))
    })
}
