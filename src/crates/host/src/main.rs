//! `ltb-host` 命令行入口。
//!
//! 主要逻辑都放在 `ltb_host` Library 中，便于 GUI 直接复用；
//! 本文件只负责解析参数并组装所选运行模式。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use ltb_host::{
    build_dispatcher, load_or_create_secret, load_policy, run_http, run_mcp, run_websocket,
};

#[derive(Parser, Debug)]
#[command(name = "ltb-host", about = "本地 MCP 工具桥接", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// loopback HTTP 与 WebSocket 传输使用的端口；0 表示自动选择空闲端口。
    #[arg(long, default_value_t = 8788, global = true)]
    port: u16,

    /// MCP 传输使用的端口；0 表示自动选择空闲端口。
    #[arg(long, default_value_t = 8789, global = true)]
    mcp_port: u16,

    /// `serve-mcp` 的监听地址；默认值保持仅 loopback 行为。
    #[arg(long, default_value = "127.0.0.1", global = true)]
    mcp_bind: IpAddr,

    /// Direct Remote MCP 使用的静态 Bearer Token 文件。
    #[arg(long, global = true)]
    mcp_bearer_token_file: Option<PathBuf>,

    /// 策略文档路径；默认使用当前用户配置目录。
    #[arg(long, global = true)]
    policy: Option<PathBuf>,

    /// 禁用磁盘审计日志。
    #[arg(long, global = true)]
    no_audit: bool,

    /// 把 Bridge Secret 输出到 stdout 后退出。
    #[arg(long)]
    print_secret: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 启动 loopback HTTP 传输（默认）。
    Serve,
    /// 启动 loopback WebSocket 传输。
    ServeWs,
    /// 启动 loopback MCP（Model Context Protocol）传输。
    ServeMcp,
    /// 以 JSON 输出最终生效的策略后退出。
    DumpPolicy,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(true)
        .init();

    if cli.print_secret {
        return match load_or_create_secret() {
            Ok(secret) => {
                println!("{secret}");
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("读取 Bridge Secret 失败: {error}");
                std::process::ExitCode::FAILURE
            }
        };
    }

    if let Some(Command::DumpPolicy) = cli.command {
        let policy = load_policy(cli.policy.as_ref());
        return match serde_json::to_string_pretty(&policy) {
            Ok(json) => {
                println!("{json}");
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("序列化策略失败: {error}");
                std::process::ExitCode::FAILURE
            }
        };
    }

    let dispatcher = match build_dispatcher(cli.policy.clone(), !cli.no_audit).await {
        Ok(dispatcher) => dispatcher,
        Err(error) => {
            eprintln!("启动 Bridge 失败: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let command = cli.command.unwrap_or(Command::Serve);

    match command {
        Command::Serve | Command::ServeWs | Command::ServeMcp | Command::DumpPolicy => {
            let secret = match load_or_create_secret() {
                Ok(secret) => secret,
                Err(error) => {
                    eprintln!("读取 Bridge Secret 失败: {error}");
                    return std::process::ExitCode::FAILURE;
                }
            };

            let serve_websocket = matches!(command, Command::ServeWs);
            let serve_mcp = matches!(command, Command::ServeMcp);

            let address = if serve_mcp {
                let default_loopback = cli.mcp_bind == IpAddr::V4(Ipv4Addr::LOCALHOST)
                    && cli.mcp_bearer_token_file.is_none();
                if default_loopback {
                    run_mcp(cli.mcp_port, dispatcher, secret.clone()).await
                } else {
                    let Some(token_file) = cli.mcp_bearer_token_file.as_ref() else {
                        eprintln!(
                            "启用 Direct Remote MCP 时必须提供 --mcp-bearer-token-file"
                        );
                        return std::process::ExitCode::FAILURE;
                    };
                    let token = match std::fs::read_to_string(token_file) {
                        Ok(token) if !token.trim().is_empty() => token.trim().to_string(),
                        Ok(_) => {
                            eprintln!("MCP Bearer Token 文件为空: {}", token_file.display());
                            return std::process::ExitCode::FAILURE;
                        }
                        Err(error) => {
                            eprintln!(
                                "读取 MCP Bearer Token 文件失败 {}: {error}",
                                token_file.display()
                            );
                            return std::process::ExitCode::FAILURE;
                        }
                    };
                    ltb_host::run_direct_mcp(
                        SocketAddr::new(cli.mcp_bind, cli.mcp_port),
                        dispatcher,
                        token,
                    )
                    .await
                }
            } else if serve_websocket {
                run_websocket(cli.port, dispatcher, secret.clone()).await
            } else {
                run_http(cli.port, dispatcher, secret.clone()).await
            };

            let address = match address {
                Ok(address) => address,
                Err(error) => {
                    let port = if serve_mcp { cli.mcp_port } else { cli.port };
                    eprintln!("绑定所选传输端口失败 {port}: {error}");
                    return std::process::ExitCode::FAILURE;
                }
            };

            // 启动时只输出一次，方便手动运行 Host 的用户
            // 把 Token 粘贴到 MCP 客户端；传输层永远不会记录该值。
            if serve_mcp {
                println!("ltb-host MCP 正在监听 http://{address}/mcp");
            } else if serve_websocket {
                println!("ltb-host 正在监听 ws://{address}");
            } else {
                println!("ltb-host 正在监听 http://{address}/rpc");
            }
            if serve_mcp && cli.mcp_bearer_token_file.is_some() {
                println!("MCP 认证：静态 Bearer Token");
            } else {
                println!("Bridge Secret： {secret}");
            }
            println!("按 Ctrl+C 停止");

            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "监听 Ctrl+C 失败");
                return std::process::ExitCode::FAILURE;
            }
            tracing::info!("正在关闭");
        }
    }

    std::process::ExitCode::SUCCESS
}
