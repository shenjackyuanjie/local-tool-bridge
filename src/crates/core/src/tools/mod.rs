//! 工具注册表与 `Tool` trait。

use crate::error::{BridgeError, Result};
use crate::policy::PolicyEngine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::hash::Hasher;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub mod codex;
pub mod fs;
pub mod http;
pub mod shell;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultEffect {
    Allow,
    Ask,
    Deny,
}
impl From<DefaultEffect> for crate::policy::Effect {
    fn from(v: DefaultEffect) -> Self {
        match v {
            DefaultEffect::Allow => crate::policy::Effect::Allow,
            DefaultEffect::Ask => crate::policy::Effect::Ask,
            DefaultEffect::Deny => crate::policy::Effect::Deny,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSchema {
    #[serde(rename = "type")]
    pub schema_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDescriptor {
    pub name: String,
    pub summary: String,
    pub description: String,
    pub category: String,
    pub input_schema: ObjectSchema,
    pub mutating: bool,
    pub default_effect: DefaultEffect,
    pub latency_hint: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    pub text: String,
}
impl ContentBlock {
    pub fn text(t: impl Into<String>) -> Self {
        Self {
            block_type: "text".into(),
            text: t.into(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolOutput {
    pub content: Vec<ContentBlock>,
    pub is_error: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}
impl ToolOutput {
    pub fn ok(t: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock::text(t)],
            is_error: false,
            truncated: false,
            original_bytes: None,
            duration_ms: None,
        }
    }
    pub fn error(t: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock::text(t)],
            is_error: true,
            truncated: false,
            original_bytes: None,
            duration_ms: None,
        }
    }
    pub fn truncate_to(mut self, max: usize) -> Self {
        let total: usize = self.content.iter().map(|b| b.text.len()).sum();
        if total <= max {
            return self;
        }
        let mut left = max;
        let mut out = Vec::new();
        for b in self.content {
            if left == 0 {
                break;
            }
            if b.text.len() <= left {
                left -= b.text.len();
                out.push(b);
            } else {
                let mut e = left;
                while e > 0 && !b.text.is_char_boundary(e) {
                    e -= 1;
                }
                out.push(ContentBlock::text(&b.text[..e]));
                break;
            }
        }
        self.content = out;
        self.truncated = true;
        self.original_bytes = Some(total);
        self
    }
}
/// 记录模型在结构化写入前实际读取过的文件内容，
/// 只有读取记录仍与磁盘内容一致时才允许覆盖。
#[derive(Default)]
pub struct ReadBeforeWriteTracker {
    reads: Mutex<HashMap<String, HashMap<PathBuf, u64>>>,
}

impl ReadBeforeWriteTracker {
    pub fn record(&self, scope: &str, path: &Path, bytes: &[u8]) {
        let path = read_tracking_key(path);
        let mut reads = self.reads.lock().expect("read-before-write lock poisoned");
        reads
            .entry(scope.to_string())
            .or_default()
            .insert(path, content_fingerprint(bytes));
    }

    pub fn require_current(
        &self,
        scope: &str,
        path: &Path,
        current_bytes: &[u8],
    ) -> Result<()> {
        let path = read_tracking_key(path);
        let current = content_fingerprint(current_bytes);
        let mut reads = self.reads.lock().expect("read-before-write lock poisoned");
        let observed = reads
            .get(scope)
            .and_then(|scope_reads| scope_reads.get(&path))
            .copied();

        match observed {
            None => Err(BridgeError::denied(format!(
                "拒绝修改 `{}`：当前会话尚未通过 read_file 读取该文件。请先读取文件，再重试写入。",
                path.display()
            ))),
            Some(fingerprint) if fingerprint != current => {
                if let Some(scope_reads) = reads.get_mut(scope) {
                    scope_reads.remove(&path);
                }
                Err(BridgeError::denied(format!(
                    "拒绝修改 `{}`：文件在上次 read_file 之后已发生变化。请重新读取文件，再重试写入。",
                    path.display()
                )))
            }
            Some(_) => Ok(()),
        }
    }

    pub fn invalidate(&self, scope: &str, path: &Path) {
        let path = read_tracking_key(path);
        let mut reads = self.reads.lock().expect("read-before-write lock poisoned");
        if let Some(scope_reads) = reads.get_mut(scope) {
            scope_reads.remove(&path);
            if scope_reads.is_empty() {
                reads.remove(scope);
            }
        }
    }

    pub fn clear_scope(&self, scope: &str) {
        self.reads
            .lock()
            .expect("read-before-write lock poisoned")
            .remove(scope);
    }
}

fn read_tracking_key(path: &Path) -> PathBuf {
    dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn content_fingerprint(bytes: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(bytes);
    hasher.finish()
}

pub struct ToolContext<'a> {
    pub policy: &'a PolicyEngine,
    pub call_id: &'a str,
    pub origin: &'a str,
    pub read_tracker: &'a ReadBeforeWriteTracker,
    pub read_scope: &'a str,
}
#[async_trait::async_trait]
pub trait Tool: Send + Sync {
    fn descriptor(&self) -> ToolDescriptor;
    async fn execute(&self, arguments: Value, context: &ToolContext<'_>) -> Result<ToolOutput>;
}
pub struct ToolRegistry {
    tools: BTreeMap<String, Arc<dyn Tool>>,
}
impl ToolRegistry {
    pub fn with_builtins() -> Self {
        let mut r = Self {
            tools: BTreeMap::new(),
        };
        r.register(Arc::new(fs::ReadFile));
        r.register(Arc::new(fs::WriteFile));
        r.register(Arc::new(fs::ListDir));
        r.register(Arc::new(fs::Search));
        r.register(Arc::new(shell::Exec));
        r.register(Arc::new(http::Request));
        r.register(Arc::new(codex::ReadFile));
        r.register(Arc::new(codex::ListDir));
        r.register(Arc::new(codex::Exec));
        r.register(Arc::new(codex::UnifiedExec));
        r.register(Arc::new(codex::ApplyPatch));
        r
    }
    pub fn register(&mut self, t: Arc<dyn Tool>) {
        self.tools.insert(t.descriptor().name, t);
    }
    pub fn get(&self, n: &str) -> Option<&Arc<dyn Tool>> {
        self.tools.get(n)
    }
    pub fn require(&self, n: &str) -> Result<&Arc<dyn Tool>> {
        self.get(n).ok_or_else(|| BridgeError::tool_not_found(n))
    }
    /// 暴露给客户端的工具描述：Codex 兼容工具集合。
    pub fn descriptors(&self) -> Vec<ToolDescriptor> {
        self.tools
            .values()
            .filter(|t| t.descriptor().category.starts_with("codex-"))
            .map(|t| t.descriptor())
            .collect()
    }
    pub fn all_descriptors(&self) -> Vec<ToolDescriptor> {
        self.tools.values().map(|t| t.descriptor()).collect()
    }
    pub fn names(&self) -> Vec<String> {
        self.descriptors().into_iter().map(|d| d.name).collect()
    }
}
impl Default for ToolRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}
pub fn required_str(a: &Value, k: &str) -> Result<String> {
    a.get(k)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            BridgeError::invalid_params(format!("缺少必填字符串参数 `{k}`"))
        })
}
pub fn optional_str(a: &Value, k: &str) -> Option<String> {
    a.get(k).and_then(Value::as_str).map(str::to_string)
}
pub fn optional_u64(a: &Value, k: &str, d: u64) -> u64 {
    a.get(k).and_then(Value::as_u64).unwrap_or(d)
}
pub fn optional_bool(a: &Value, k: &str, d: bool) -> bool {
    a.get(k).and_then(Value::as_bool).unwrap_or(d)
}
pub fn clamp_u64(v: u64, min: u64, max: u64) -> u64 {
    v.clamp(min, max)
}


#[cfg(test)]
mod read_before_write_tests {
    use super::*;

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);

            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ltb-read-before-write-{}-{unique}.txt",
                std::process::id()
            ));
            std::fs::write(&path, b"version=1\n").expect("failed to create temp file");
            Self { path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn write_requires_a_prior_read_in_the_same_scope() {
        let file = TempFile::new();
        let tracker = ReadBeforeWriteTracker::default();
        let bytes = std::fs::read(&file.path).unwrap();

        assert!(
            tracker
                .require_current("session-a", &file.path, &bytes)
                .is_err()
        );

        tracker.record("session-a", &file.path, &bytes);
        assert!(
            tracker
                .require_current("session-a", &file.path, &bytes)
                .is_ok()
        );
        assert!(
            tracker
                .require_current("session-b", &file.path, &bytes)
                .is_err()
        );
    }

    #[test]
    fn stale_reads_are_rejected_and_invalidated() {
        let file = TempFile::new();
        let tracker = ReadBeforeWriteTracker::default();
        let original = std::fs::read(&file.path).unwrap();
        tracker.record("session", &file.path, &original);

        std::fs::write(&file.path, b"version=2\n").unwrap();
        let changed = std::fs::read(&file.path).unwrap();
        assert!(
            tracker
                .require_current("session", &file.path, &changed)
                .is_err()
        );

        tracker.record("session", &file.path, &changed);
        assert!(
            tracker
                .require_current("session", &file.path, &changed)
                .is_ok()
        );
        tracker.invalidate("session", &file.path);
        assert!(
            tracker
                .require_current("session", &file.path, &changed)
                .is_err()
        );
    }
}
