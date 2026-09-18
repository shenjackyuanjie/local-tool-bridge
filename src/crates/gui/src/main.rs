//! `ltb-gui` —— Bridge 控制面板。
//!
//! 在后台 Tokio Runtime 中启动调度器与 loopback
//! 传输，并打开原生 egui 窗口。该窗口是用户处理审批请求的唯一入口，
//! 因此关闭窗口后会把审批器切换为
//! 非交互状态，之后所有 `ask` 都会被拒绝。

use std::sync::Arc;
use std::time::Duration;

use app::{BridgeApp, BridgeAppInit};
use approver::GuiApprover;

mod app;
mod approver;
mod fonts;
mod ui;

/// 审批请求保持可操作状态的最长时间，超时后自动拒绝。
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(180);

/// 按顺序尝试的 loopback 端口。
///
/// 若启动第二个实例，会因为端口绑定失败而留下一个
/// 看似正常但实际上无法工作的窗口。
const PORTS: &[u16] = &[8788, 8789, 8790, 8791];

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // 只允许一个控制面板运行：两个实例会争抢端口，并且可能针对
    // 同一次调用弹出两个审批窗口。
    let instance = match single_instance::SingleInstance::new("local-tool-bridge-gui") {
        Ok(instance) => instance,
        Err(error) => {
            eprintln!("初始化单实例保护失败: {error}");
            return Ok(());
        }
    };

    if !instance.is_single() {
        eprintln!("The bridge control panel is already running.");
        return Ok(());
    }

    // 使用多线程 Runtime，因为工具调用允许并发：耗时的 Shell
    // 命令不能阻塞文件读取。
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("启动异步 Runtime 失败: {error}");
            return Ok(());
        }
    };

    let (approver, approval_rx) = GuiApprover::new(APPROVAL_TIMEOUT);

    // 在第一帧之前准备好窗口需要的全部状态，避免 UI
    // 显示半初始化状态。
    let (
        dispatcher,
        secret,
        http_address,
        websocket_address,
        mcp_address,
        direct_mcp_address,
        direct_mcp_config,
        tunnel_process,
    ) = runtime.block_on(async {
        let dispatcher = match ltb_host::build_dispatcher(None, true).await {
            Ok(dispatcher) => dispatcher,
            Err(error) => {
                eprintln!("启动 Bridge 失败: {error}");
                std::process::exit(1);
            }
        };

        // 在启动任何传输之前先安装审批器，确保启动期间到达的调用
        // 仍然能够交给用户审批。
        dispatcher.set_approver(approver.clone()).await;

        let secret = ltb_host::load_or_create_secret().unwrap_or_default();

        let mut http_address = None;
        let mut websocket_address = None;
        let mut mcp_address = None;
        let mut direct_mcp_address = None;
        let direct_mcp_config = ltb_host::direct_mcp::load_config();
        let mut tunnel_process = None;

        for port in PORTS {
            if http_address.is_none() {
                if let Ok(address) =
                    ltb_host::run_http(*port, dispatcher.clone(), secret.clone()).await
                {
                    http_address = Some(address.to_string());
                    tracing::info!(%address, "HTTP 传输开始监听");
                }
            }
            if websocket_address.is_none() {
                // WebSocket 与 HTTP 同时提供，方便需要服务端主动推送的
                // 客户端建立连接。
                if let Ok(address) =
                    ltb_host::run_websocket(*port, dispatcher.clone(), secret.clone()).await
                {
                    websocket_address = Some(address.to_string());
                }
            }
            if mcp_address.is_none() {
                // MCP 传输让 ChatGPT / Codex 能通过 OpenAI Secure MCP Tunnel
                // 访问同一套本地工具。
                if let Ok(address) =
                    ltb_host::run_mcp(*port, dispatcher.clone(), secret.clone()).await
                {
                    mcp_address = Some(address.to_string());
                    tracing::info!(%address, "MCP 传输开始监听");
                }
            }
            if http_address.is_some() && websocket_address.is_some() && mcp_address.is_some() {
                break;
            }
        }

        if direct_mcp_config.enabled {
            match ltb_host::run_configured_direct_mcp(&direct_mcp_config, dispatcher.clone()).await
            {
                Ok(running) => {
                    direct_mcp_address =
                        Some(format!("http://{}{}", running.address, running.mcp_path));
                    tracing::info!(
                        address = %running.address,
                        "Direct Remote MCP 传输开始监听"
                    );
                }
                Err(error) => {
                    tracing::error!(%error, "启动 Direct Remote MCP 失败");
                }
            }
        }

        if let Some(mcp_address_value) = mcp_address.as_deref() {
            let tunnel_config = ltb_host::tunnel::load_config();
            if tunnel_config.enabled {
                let bridge_secret_path = ltb_core::config_dir().map(|dir| dir.join("secret"));
                if let Some(secret_path) = bridge_secret_path {
                    match ltb_host::tunnel::TunnelProcess::start(
                        &tunnel_config,
                        &format!("http://{mcp_address_value}/mcp"),
                        &secret_path,
                    )
                    .await
                    {
                        Ok(process) => tunnel_process = Some(process),
                        Err(error) => {
                            tracing::error!(%error, "启动 Secure MCP Tunnel Client 失败")
                        }
                    }
                }
            }
        }

        (
            dispatcher,
            secret,
            http_address,
            websocket_address,
            mcp_address,
            direct_mcp_address,
            direct_mcp_config,
            tunnel_process,
        )
    });

    let handle = runtime.handle().clone();

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([880.0, 660.0])
            .with_min_inner_size([640.0, 480.0])
            .with_title("Local Tool Bridge — 本地工具桥接"),
        ..Default::default()
    };

    eframe::run_native(
        "Local Tool Bridge — 本地工具桥接",
        options,
        Box::new(move |cc| {
            // 必须在第一帧前执行：默认字体不包含 CJK
            // 字形，否则中文标签会显示成方框。
            fonts::install(&cc.egui_ctx);

            let app = BridgeApp::new(BridgeAppInit {
                runtime: handle,
                dispatcher,
                secret,
                http_address,
                websocket_address,
                mcp_address,
                direct_mcp_address,
                direct_mcp_config,
                tunnel_process,
            });

            Ok(Box::new(GuiFrame {
                app,
                approvals: approval_rx,
                approver,
                runtime: Some(runtime),
            }))
        }),
    )
}

/// 包装应用供 `eframe` 驱动，同时确保 Runtime 生命周期长于
/// 窗口，而不是在 `main` 结束时被提前释放。
struct GuiFrame {
    app: BridgeApp,
    approvals: tokio::sync::mpsc::UnboundedReceiver<approver::PendingApproval>,
    approver: Arc<GuiApprover>,
    /// 在整个进程生命周期内保持存活；释放后 Host 会停止运行。
    runtime: Option<tokio::runtime::Runtime>,
}

impl eframe::App for GuiFrame {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        // 处理待审批请求并刷新审计视图。
        self.app.poll(&mut self.approvals);

        ui::draw(&mut self.app, ctx);

        // 存在待审批请求时持续重绘，避免已经临近过期的审批
        // 长时间停留在界面上并看起来仍可操作。
        if self.app.active_approval.is_some() {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // 窗口关闭后无法再询问用户，因此之后所有审批都必须
        // 拒绝而不是静默允许。这是 fail-closed 的关键边界，
        // 因为 UI 消失后传输层仍可能继续运行。
        let approver = self.approver.clone();
        if let Some(runtime) = &self.runtime {
            runtime.block_on(async move {
                approver.set_interactive(false).await;
            });
            if let Some(tunnel) = self.app.tunnel_process.as_mut() {
                runtime.block_on(tunnel.stop());
            }
        }
        tracing::info!("window closed; approvals will now be denied");
    }
}
