//! 文件系统工具。
//!
//! 所有文件系统工具都会经过 `PolicyEngine::sandbox()`，因此路径约束与
//! denylist 在这里统一执行，而不是由各个处理器各自临时检查。

use std::time::Instant;

use serde_json::{Value, json};

use super::{
    Tool, ToolContext, ToolDescriptor, ToolOutput, clamp_u64, optional_bool, optional_str,
    optional_u64, required_str,
};
use crate::error::{BridgeError, Result};
use crate::policy::path::lexical_normalize;

/// 对几乎可以确定不是文本的文件直接拒绝，避免向模型返回
/// 大量乱码内容。
const BINARY_SNIFF_BYTES: usize = 8192;

fn schema(properties: Value, required: &[&str]) -> super::ObjectSchema {
    super::ObjectSchema {
        schema_type: "object".into(),
        properties: serde_json::from_value(properties)
            .expect("schema properties must be an object"),
        required: required.iter().map(|s| (*s).to_string()).collect(),
    }
}

/// `fs.read_file`
pub struct ReadFile;

#[async_trait::async_trait]
impl Tool for ReadFile {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "fs.read_file".into(),
            summary: "从磁盘读取 UTF-8 文本文件".into(),
            description: "读取文件并返回内容。默认在每行前添加行号，\
                          同时会规范化行尾；传入 \
                          `lineNumbers: false` 可按原始内容返回。大文件可使用 `offset` 与 \
                          `limit` 分段读取。二进制文件会直接拒绝，避免产生乱码。"
                .into(),
            category: "fs".into(),
            mutating: false,
            default_effect: super::DefaultEffect::Ask,
            latency_hint: "instant".into(),
            input_schema: schema(
                json!({
                    "path": { "type": "string", "description": "文件的绝对路径" },
                    "offset": {
                        "type": "integer",
                        "description": "返回内容的起始行号（从 1 开始）",
                        "minimum": 1,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "最多返回的行数",
                        "minimum": 1,
                        "maximum": 5000,
                    },
                    "lineNumbers": {
                        "type": "boolean",
                        "description": "在每行前添加行号（会规范化行尾）",
                        "default": true,
                    },
                    "encoding": {
                        "type": "string",
                        "enum": ["utf-8", "utf-16le", "gbk"],
                        "default": "utf-8",
                    },
                }),
                &["path"],
            ),
        }
    }

    async fn execute(&self, arguments: Value, context: &ToolContext<'_>) -> Result<ToolOutput> {
        let started = Instant::now();
        let raw_path = required_str(&arguments, "path")?;
        let path = context.policy.sandbox().resolve(&raw_path, true)?;

        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|error| BridgeError::from_io("读取文件元数据失败", error))?;
        if metadata.is_dir() {
            return Err(BridgeError::invalid_params(format!(
                "`{}` 是目录；请改用 fs.list_dir",
                path.display()
            )));
        }

        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|error| BridgeError::from_io("读取文件失败", error))?;

        if looks_binary(&bytes) {
            return Ok(ToolOutput::error(format!(
                "拒绝读取 `{}`：看起来是二进制文件（{} 字节）",
                path.display(),
                bytes.len()
            )));
        }

        let encoding = optional_str(&arguments, "encoding").unwrap_or_else(|| "utf-8".into());
        let text = decode(&bytes, &encoding).map_err(|error| {
            BridgeError::invalid_params(format!("按 {encoding} 解码失败：{error}"))
        })?;

        let line_numbers = optional_bool(&arguments, "lineNumbers", true);
        let offset = optional_u64(&arguments, "offset", 1).max(1) as usize;
        let limit = clamp_u64(optional_u64(&arguments, "limit", 2000), 1, 5000) as usize;

        // `split_inclusive` 会保留每行自己的换行符，因此文件的
        // 行尾格式可以原样往返。这里若使用 `lines()` 会静默
        // 把 CRLF 改成 LF，并丢失“末尾无换行”的状态；
        // 模型读取后再写回文件时，这些差异很重要。
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        let total_lines = lines.len();
        let start_index = (offset - 1).min(total_lines);
        let end_index = (start_index + limit).min(total_lines);

        let body = if line_numbers {
            let mut body = String::new();
            for (index, line) in lines[start_index..end_index].iter().enumerate() {
                // 换行符只在展示时去除；否则行号
                // 区域可能被多余的 `\r` 干扰。
                let shown = line.strip_suffix('\n').unwrap_or(line);
                let shown = shown.strip_suffix('\r').unwrap_or(shown);
                body.push_str(&format!("{:>6}\t{shown}\n", start_index + index + 1));
            }
            body
        } else {
            lines[start_index..end_index].concat()
        };

        // 只有读取与解码都成功后，才记录精确的磁盘内容快照。
        // apply_patch / write_file 会使用该记录拒绝盲写或基于陈旧内容的
        // 已有文件写入。
        context
            .read_tracker
            .record(context.read_scope, &path, &bytes);

        let header = if line_numbers {
            format!(
                "{}（共 {} 行，当前显示 {}-{}）\n",
                path.display(),
                total_lines,
                if total_lines == 0 { 0 } else { start_index + 1 },
                end_index
            )
        } else {
            // 不显示行号时不添加 Header：调用方要求的是文件本身，
            // 任何额外前缀都会污染原始内容。
            String::new()
        };

        Ok(ToolOutput {
            content: vec![super::ContentBlock::text(format!("{header}{body}"))],
            is_error: false,
            truncated: end_index < total_lines,
            original_bytes: Some(bytes.len()),
            duration_ms: Some(started.elapsed().as_millis() as u64),
        })
    }
}

/// 启发式二进制检测：前几 KiB 中出现 NUL 字节即视为二进制。
fn looks_binary(bytes: &[u8]) -> bool {
    let window = &bytes[..bytes.len().min(BINARY_SNIFF_BYTES)];
    window.contains(&0)
}

/// 按请求的编码解码字节，并返回便于阅读的错误信息。
fn decode(bytes: &[u8], encoding: &str) -> std::result::Result<String, String> {
    match encoding.to_ascii_lowercase().as_str() {
        "utf-8" | "utf8" => String::from_utf8(bytes.to_vec())
            .map_err(|error| format!("UTF-8 无效，错误位于字节 {}", error.utf8_error().valid_up_to())),
        "utf-16le" | "utf16le" => {
            if !bytes.len().is_multiple_of(2) {
                return Err("UTF-16LE 字节数为奇数".into());
            }
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16(&units).map_err(|error| error.to_string())
        }
        "gbk" => Err("当前构建未启用 GBK 解码；请先把文件转换为 UTF-8".into()),
        other => Err(format!("不支持的编码 `{other}`")),
    }
}

/// `fs.write_file`
pub struct WriteFile;

#[async_trait::async_trait]
impl Tool for WriteFile {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "fs.write_file".into(),
            summary: "创建或覆盖文本文件".into(),
            description: "向文件写入文本，并在需要时创建父目录。已有\
                          文件必须先在同一会话中通过 read_file 读取；陈旧读取\
                          会被拒绝。除 append 模式外，该操作会破坏\
                          现有内容，因此始终需要用户明确审批。"
                .into(),
            category: "fs".into(),
            mutating: true,
            default_effect: super::DefaultEffect::Ask,
            latency_hint: "instant".into(),
            input_schema: schema(
                json!({
                    "path": { "type": "string", "description": "要写入的绝对路径" },
                    "content": { "type": "string", "description": "完整文件内容" },
                    "mode": {
                        "type": "string",
                        "enum": ["overwrite", "append", "create"],
                        "default": "overwrite",
                    },
                    "createDirs": {
                        "type": "boolean",
                        "description": "自动创建缺失的父目录",
                        "default": true,
                    },
                }),
                &["path", "content"],
            ),
        }
    }

    async fn execute(&self, arguments: Value, context: &ToolContext<'_>) -> Result<ToolOutput> {
        let started = Instant::now();
        let raw_path = required_str(&arguments, "path")?;
        let content = required_str(&arguments, "content")?;
        let mode = optional_str(&arguments, "mode").unwrap_or_else(|| "overwrite".into());
        let create_dirs = optional_bool(&arguments, "createDirs", true);

        let path = context.policy.sandbox().resolve(&raw_path, false)?;

        if create_dirs {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(|error| {
                    BridgeError::from_io("创建父目录失败", error)
                })?;
            }
        }

        let existed_before = path.exists();
        let bytes_written = content.len();

        if existed_before && mode != "create" {
            let current = tokio::fs::read(&path)
                .await
                .map_err(|error| BridgeError::from_io("校验写入目标失败", error))?;
            context
                .read_tracker
                .require_current(context.read_scope, &path, &current)?;
        }

        match mode.as_str() {
            "overwrite" => {
                tokio::fs::write(&path, content.as_bytes())
                    .await
                    .map_err(|error| BridgeError::from_io("写入文件失败", error))?;
            }
            "append" => {
                use tokio::io::AsyncWriteExt;
                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .await
                    .map_err(|error| {
                        BridgeError::from_io("以追加模式打开文件失败", error)
                    })?;
                file.write_all(content.as_bytes())
                    .await
                    .map_err(|error| BridgeError::from_io("追加文件失败", error))?;
                file.flush()
                    .await
                    .map_err(|error| BridgeError::from_io("刷新文件缓冲区失败", error))?;
            }
            "create" => {
                if existed_before {
                    return Err(BridgeError::new(
                        crate::error::code::TOOL_DENIED,
                        format!("拒绝创建 `{}`：文件已存在", path.display()),
                    ));
                }
                tokio::fs::write(&path, content.as_bytes())
                    .await
                    .map_err(|error| BridgeError::from_io("创建文件失败", error))?;
            }
            other => {
                return Err(BridgeError::invalid_params(format!(
                    "不支持的模式 `{other}`；应为 overwrite、append 或 create"
                )));
            }
        }

        context.read_tracker.invalidate(context.read_scope, &path);

        let verb = if existed_before { "已更新" } else { "已创建" };
        Ok(ToolOutput {
            content: vec![super::ContentBlock::text(format!(
                "{verb} {} ({} 字节，mode={mode})",
                path.display(),
                bytes_written
            ))],
            is_error: false,
            truncated: false,
            original_bytes: None,
            duration_ms: Some(started.elapsed().as_millis() as u64),
        })
    }
}

/// `fs.list_dir`
pub struct ListDir;

#[async_trait::async_trait]
impl Tool for ListDir {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "fs.list_dir".into(),
            summary: "列出目录内容".into(),
            description: "返回目录中的名称、大小与修改时间。\
                          默认不递归；可配合 `recursive` 与 `glob` 遍历目录树。"
                .into(),
            category: "fs".into(),
            mutating: false,
            default_effect: super::DefaultEffect::Allow,
            latency_hint: "instant".into(),
            input_schema: schema(
                json!({
                    "path": { "type": "string", "description": "目录的绝对路径" },
                    "recursive": { "type": "boolean", "default": false },
                    "glob": { "type": "string", "description": "过滤表达式，例如 `**/*.ts`" },
                    "includeHidden": { "type": "boolean", "default": false },
                    "maxEntries": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5000,
                        "default": 500,
                    },
                }),
                &["path"],
            ),
        }
    }

    async fn execute(&self, arguments: Value, context: &ToolContext<'_>) -> Result<ToolOutput> {
        let started = Instant::now();
        let raw_path = required_str(&arguments, "path")?;
        let root = context.policy.sandbox().resolve(&raw_path, true)?;

        if !root.is_dir() {
            return Err(BridgeError::invalid_params(format!(
                "`{}` 不是目录",
                root.display()
            )));
        }

        let recursive = optional_bool(&arguments, "recursive", false);
        let include_hidden = optional_bool(&arguments, "includeHidden", false);
        let max_entries = clamp_u64(optional_u64(&arguments, "maxEntries", 500), 1, 5000) as usize;

        let filter = match optional_str(&arguments, "glob") {
            Some(pattern) => Some(
                globset::Glob::new(&pattern)
                    .map_err(|error| BridgeError::invalid_params(format!("无效的 Glob：{error}")))?
                    .compile_matcher(),
            ),
            None => None,
        };

        let mut lines: Vec<String> = Vec::new();
        let mut count = 0usize;
        let mut hit_limit = false;

        if recursive {
            // `max_depth` 刻意不设上限：真正限制遍历规模的是条目数量上限，
            // 因此即使目录树很深也会及时停止。
            let walker = walkdir::WalkDir::new(&root).follow_links(false).into_iter();
            for entry in walker.filter_entry(|entry| include_hidden || !is_hidden(entry.path())) {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => continue,
                };
                if entry.path() == root {
                    continue;
                }
                if let Some(matcher) = &filter {
                    let relative = entry.path().strip_prefix(&root).unwrap_or(entry.path());
                    if !matcher.is_match(relative) {
                        continue;
                    }
                }
                if count >= max_entries {
                    hit_limit = true;
                    break;
                }
                lines.push(describe_entry(
                    entry.path(),
                    entry.file_type().is_dir(),
                    &root,
                ));
                count += 1;
            }
        } else {
            let mut reader = tokio::fs::read_dir(&root)
                .await
                .map_err(|error| BridgeError::from_io("读取目录失败", error))?;
            while let Some(entry) = reader
                .next_entry()
                .await
                .map_err(|error| BridgeError::from_io("读取目录项失败", error))?
            {
                let path = entry.path();
                if !include_hidden && is_hidden(&path) {
                    continue;
                }
                if let Some(matcher) = &filter {
                    let name = entry.file_name();
                    if !matcher.is_match(std::path::Path::new(&name)) {
                        continue;
                    }
                }
                if count >= max_entries {
                    hit_limit = true;
                    break;
                }
                let is_dir = entry
                    .file_type()
                    .await
                    .map(|kind| kind.is_dir())
                    .unwrap_or(false);
                lines.push(describe_entry(&path, is_dir, &root));
                count += 1;
            }
        }

        lines.sort();
        let header = format!(
            "{} — {} 个条目{}\n",
            root.display(),
            count,
            if hit_limit {
                "（已在 maxEntries 处截断）"
            } else {
                ""
            }
        );

        Ok(ToolOutput {
            content: vec![super::ContentBlock::text(format!(
                "{header}{}",
                lines.join("\n")
            ))],
            is_error: false,
            truncated: hit_limit,
            original_bytes: None,
            duration_ms: Some(started.elapsed().as_millis() as u64),
        })
    }
}

fn is_hidden(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.starts_with('.') && name != "." && name != "..")
        .unwrap_or(false)
}

fn describe_entry(path: &std::path::Path, is_dir: bool, root: &std::path::Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let display = relative.display();
    if is_dir {
        return format!("{display}/");
    }
    match std::fs::metadata(path) {
        Ok(metadata) => format!("{display}\t{} 字节", metadata.len()),
        Err(_) => format!("{display}\t?"),
    }
}

/// `fs.search`
pub struct Search;

#[async_trait::async_trait]
impl Tool for Search {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: "fs.search".into(),
            summary: "使用正则表达式搜索文件内容".into(),
            description: "递归搜索目录下的文本文件，并返回匹配\
                          行及其行号。默认跳过二进制文件、`.git` 与 \
                          `node_modules`。"
                .into(),
            category: "fs".into(),
            mutating: false,
            default_effect: super::DefaultEffect::Allow,
            latency_hint: "slow".into(),
            input_schema: schema(
                json!({
                    "path": { "type": "string", "description": "要搜索的目录绝对路径" },
                    "pattern": { "type": "string", "description": "Rust 正则表达式语法" },
                    "glob": {
                        "type": "string",
                        "description": "仅搜索匹配的文件，例如 `*.rs`",
                    },
                    "ignoreCase": { "type": "boolean", "default": false },
                    "maxResults": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1000,
                        "default": 100,
                    },
                    "contextLines": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 10,
                        "default": 0,
                    },
                }),
                &["path", "pattern"],
            ),
        }
    }

    async fn execute(&self, arguments: Value, context: &ToolContext<'_>) -> Result<ToolOutput> {
        let started = Instant::now();
        let raw_path = required_str(&arguments, "path")?;
        let root = context.policy.sandbox().resolve(&raw_path, true)?;
        let pattern = required_str(&arguments, "pattern")?;
        let ignore_case = optional_bool(&arguments, "ignoreCase", false);
        let max_results = clamp_u64(optional_u64(&arguments, "maxResults", 100), 1, 1000) as usize;
        let context_lines = clamp_u64(optional_u64(&arguments, "contextLines", 0), 0, 10) as usize;

        let regex = regex::RegexBuilder::new(&pattern)
            .case_insensitive(ignore_case)
            .build()
            .map_err(|error| BridgeError::invalid_params(format!("无效的正则表达式：{error}")))?;

        let filter = match optional_str(&arguments, "glob") {
            Some(pattern) => Some(
                globset::Glob::new(&pattern)
                    .map_err(|error| BridgeError::invalid_params(format!("无效的 Glob：{error}")))?
                    .compile_matcher(),
            ),
            None => None,
        };

        // 默认跳过这些容易产生大量噪声结果的目录。
        const SKIP_DIRS: &[&str] = &[
            ".git",
            "node_modules",
            "target",
            "dist",
            "build",
            ".venv",
            "__pycache__",
        ];
        const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

        let mut results: Vec<String> = Vec::new();
        let mut files_scanned = 0usize;
        let mut truncated = false;

        let walker = walkdir::WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                let name = entry.file_name().to_string_lossy();
                !(entry.file_type().is_dir() && SKIP_DIRS.iter().any(|skip| name == *skip))
            });

        'outer: for entry in walker {
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();

            if let Some(matcher) = &filter {
                let relative = path.strip_prefix(&root).unwrap_or(path);
                if !matcher.is_match(relative) {
                    continue;
                }
            }
            if let Ok(metadata) = entry.metadata() {
                if metadata.len() > MAX_FILE_BYTES {
                    continue;
                }
            }

            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            if looks_binary(&bytes) {
                continue;
            }
            let Ok(text) = String::from_utf8(bytes) else {
                continue;
            };

            files_scanned += 1;
            let lines: Vec<&str> = text.lines().collect();

            for (index, line) in lines.iter().enumerate() {
                if !regex.is_match(line) {
                    continue;
                }
                if results.len() >= max_results {
                    truncated = true;
                    break 'outer;
                }

                let relative = path
                    .strip_prefix(&root)
                    .unwrap_or(path)
                    .display()
                    .to_string();
                let line_number = index + 1;

                if context_lines > 0 {
                    let from = index.saturating_sub(context_lines);
                    let to = (index + context_lines + 1).min(lines.len());
                    for (context_index, context_line) in lines[from..to].iter().enumerate() {
                        let actual = from + context_index + 1;
                        let marker = if actual == line_number { ':' } else { '-' };
                        results.push(format!("{relative}{marker}{actual}{marker}{context_line}"));
                    }
                } else {
                    results.push(format!("{relative}:{line_number}:{line}"));
                }
            }
        }

        let header = format!(
            "共 {} 个匹配，扫描 {files_scanned} 个文件{}\n",
            results.len(),
            if truncated {
                "（已在 maxResults 处截断）"
            } else {
                ""
            }
        );

        Ok(ToolOutput {
            content: vec![super::ContentBlock::text(format!(
                "{header}{}",
                results.join("\n")
            ))],
            is_error: false,
            truncated,
            original_bytes: None,
            duration_ms: Some(started.elapsed().as_millis() as u64),
        })
    }
}

/// 暴露给 Shell 工具使用，确保双方采用相同的路径规范化逻辑。
pub fn normalize_for_display(path: &std::path::Path) -> String {
    lexical_normalize(path).display().to_string()
}
