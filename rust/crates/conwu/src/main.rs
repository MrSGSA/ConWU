#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
mod adapter;
mod assistance;
mod backend;
#[cfg(windows)]
mod capture;
mod cli;
mod control;
#[cfg(windows)]
mod desktop;
mod coordination_store;
mod coordinator;
mod discovery;
mod dns;
mod flow;
mod gateway;
#[cfg(windows)]
mod installer;
mod instance;
#[cfg(windows)]
mod legacy_wintun;
mod logging;
#[cfg(windows)]
mod maintenance;
mod managed;
mod migration;
mod model;
mod native;
mod native_map;
mod pkarr;
mod projection;
mod platform;
mod raw;
mod recovery;
mod remote_admin;
mod routes;
mod runtime;
mod store;
#[cfg(test)]
mod tests;
mod transport;
mod tray;
mod updater;
mod updates;
mod uu;
mod web;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{path::PathBuf, sync::Arc};
#[derive(Parser)]
#[command(name = "conwu", about = "ConWU Windows / Linux 后台与组网管理")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    #[cfg(all(windows, feature = "lab-api"))]
    #[command(hide = true)]
    LabWintun {
        #[arg(long)]
        network: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        address: std::net::Ipv4Addr,
        #[arg(long)]
        components: PathBuf,
    },
    #[cfg(windows)]
    #[command(hide = true)]
    Msi {
        action: String,
        #[arg(trailing_var_arg = true)]
        arguments: Vec<String>,
    },
    #[cfg(windows)]
    Tray {
        #[arg(long,default_value_os_t=cli::default_data())]
        data: PathBuf,
        #[arg(long)]
        no_open: bool,
    },
    #[command(external_subcommand)]
    Manage(Vec<String>),
    #[command(hide = true)]
    ApplyUpdate {
        #[arg(long)]
        data: PathBuf,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        parent: u32,
    },
    Migrate {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        data: PathBuf,
    },
    AuthorizeUi {
        #[arg(long,default_value_os_t=cli::default_data())]
        data: PathBuf,
        #[arg(long)]
        sid: String,
    },
    Run {
        #[arg(long,default_value_os_t=cli::default_data())]
        data: PathBuf,
        #[arg(long)]
        components: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        memory: bool,
        #[arg(long)]
        no_open: bool,
        #[arg(long)]
        no_tray: bool,
        #[arg(long)]
        service: bool,
    },
    Version,
    BuildInfo,
    Stop {
        network: Option<String>,
        #[arg(long,default_value_os_t=cli::default_data())]
        data: PathBuf,
    },
    Panel {
        #[arg(long)]
        data: PathBuf,
    },
}
fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "conwu=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let command = environment_command()?;
    #[cfg(windows)]
    if matches!(command, Command::Run { service: true, .. }) {
        return platform::dispatch_service();
    }
    tokio::runtime::Runtime::new()?.block_on(run(command))
}
fn environment_command() -> Result<Command> {
    Ok(Cli::parse_from(cli::normalize_args(instance::arguments(
        std::env::args_os(),
    )?))
    .command
    .unwrap_or_else(|| {
        #[cfg(windows)]
        {
            if std::env::current_exe()
                .ok()
                .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                .is_some_and(|s| s.eq_ignore_ascii_case("ConWU.Service.exe"))
            {
                return Command::Run {
                    data: cli::default_data(),
                    components: None,
                    port: 0,
                    memory: false,
                    no_open: true,
                    no_tray: true,
                    service: true,
                };
            }
            Command::Tray {
                data: cli::default_data(),
                no_open: false,
            }
        }
        #[cfg(not(windows))]
        {
            Command::Manage(vec!["help".into()])
        }
    }))
}
async fn run(command: Command) -> Result<()> {
    #[cfg(all(windows, feature = "lab-api"))]
    if let Command::LabWintun {
        network,
        owner,
        address,
        components,
    } = &command
    {
        let network = network.clone();
        let owner = owner.clone();
        let address = *address;
        let components = components.clone();
        let adapter = tokio::task::spawn_blocking(move || {
            let legacy = model::LegacyAdapter {
                owner,
                network: network.clone(),
                slot: 1,
            };
            adapter::open(
                &network,
                address,
                &components,
                &tokio_util::sync::CancellationToken::new(),
                Some(&legacy),
            )
        })
        .await??;
        println!(
            "{}",
            serde_json::json!({"ready":true,"provider":adapter.provider()})
        );
        use std::io::Write;
        std::io::stdout().flush()?;
        let stop = tokio::task::spawn_blocking(|| {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            Ok::<_, std::io::Error>(input)
        })
        .await??;
        anyhow::ensure!(stop.trim() == "stop", "实验网卡只接受停止指令");
        drop(adapter);
        return Ok(());
    }
    match command {
        #[cfg(all(windows, feature = "lab-api"))]
        Command::LabWintun { .. } => unreachable!("handled before normal commands"),
        #[cfg(windows)]
        Command::Msi { action, arguments } => installer::execute(&action, &arguments).await?,
        #[cfg(windows)]
        Command::Tray { data, no_open } => crate::tray::client(data, !no_open).await?,
        Command::AuthorizeUi { data, sid } => {
            anyhow::ensure!(
                sid.starts_with("S-1-")
                    && sid.len() <= 192
                    && sid
                        .bytes()
                        .all(|b| b.is_ascii_digit() || matches!(b, b'S' | b'-')),
                "授权SID无效"
            );
            let store = store::Store::open(&data)?;
            store.write("ui-user.sid", sid.as_bytes(), false)?;
        }
        Command::Manage(args) => cli::execute(args).await?,
        Command::ApplyUpdate {
            data,
            nonce,
            parent,
        } => updater::apply(data, nonce, parent).await?,
        Command::Migrate { from, data } => {
            let source = store::Store::resolve_root(&from)?;
            let target = store::Store::resolve_root(&data)?;
            anyhow::ensure!(
                !source.starts_with(&target) && !target.starts_with(&source),
                "导入与输出目录必须独立"
            );
            let store = store::Store::open(&target)?;
            println!("{}", migration::import(&source, &store)?);
        }
        Command::Version => println!(
            "ConWU {} · Rust{}",
            model::VERSION,
            if cfg!(feature = "production") {
                ""
            } else {
                " experiment"
            }
        ),
        Command::BuildInfo => println!(
            "{}",
            serde_json::json!({"version":model::VERSION,"product":instance::product(),"production":cfg!(feature="production"),"localInstall":cfg!(feature="local-install"),"labApi":cfg!(feature="lab-api"),"platform":std::env::consts::OS,"architecture":std::env::consts::ARCH})
        ),
        Command::Panel { data } => {
            #[cfg(windows)]
            if let Ok(reply) = control::call(&data, &serde_json::json!({"method":"open"})).await {
                platform::open_browser(
                    reply["url"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("后台未返回面板地址"))?,
                )?;
                return Ok(());
            }
            let bytes = tokio::fs::read(data.join("panel.private.json")).await?;
            anyhow::ensure!(bytes.len() <= 8192, "面板信息过大");
            let file: serde_json::Value = serde_json::from_slice(&bytes)?;
            let origin = file["origin"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("后台面板信息缺失"))?;
            let url = url::Url::parse(origin)?;
            anyhow::ensure!(
                url.scheme() == "http"
                    && url.host_str() == Some("127.0.0.1")
                    && url.port().is_some()
                    && url.path() == "/",
                "非法后台面板地址"
            );
            let reply: serde_json::Value = discovery::http_client()?
                .post(format!("{origin}/api/open"))
                .header("Origin", origin)
                .json(&serde_json::json!({"secret":file["secret"]}))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            platform::open_browser(
                reply["url"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("后台未返回面板票据"))?,
            )?;
        }
        Command::Stop { data, network } => {
            if let Some(network) = network {
                return cli::execute(vec![
                    "stop".into(),
                    network,
                    "--data".into(),
                    data.to_str()
                        .ok_or_else(|| anyhow::anyhow!("数据路径无效"))?
                        .into(),
                ])
                .await;
            }
            let file: serde_json::Value =
                serde_json::from_slice(&tokio::fs::read(data.join("panel.private.json")).await?)?;
            let origin = file["origin"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("面板地址缺失"))?;
            let parsed = url::Url::parse(origin)?;
            anyhow::ensure!(
                parsed.scheme() == "http"
                    && parsed.host_str() == Some("127.0.0.1")
                    && parsed.port().is_some()
                    && parsed.path() == "/",
                "非法后台地址"
            );
            discovery::http_client()?
                .post(format!("{origin}/api/stop"))
                .header("Origin", origin)
                .json(&serde_json::json!({"secret":file["secret"]}))
                .send()
                .await?
                .error_for_status()?;
        }
        Command::Run {
            data,
            components,
            port,
            memory,
            no_open,
            no_tray,
            service,
        } => {
            let _ = no_tray;
            let store = Arc::new(store::Store::open(&data)?);
            let base = std::env::current_exe()?.parent().unwrap().to_owned();
            let components = components.unwrap_or_else(|| {
                if base.join("components").is_dir() {
                    base.join("components")
                } else {
                    base.join("app/components")
                }
            });
            let (app, events) = backend::App::open(store.clone(), components, memory)?;
            platform::start(app.clone());
            let event_app = app.clone();
            app.engine.tracker.spawn(async move {
                event_app.events(events).await;
            });
            let (panel, web) = web::Panel::start(app.clone(), port).await?;
            #[cfg(windows)]
            control::start(panel.clone())?;
            let url = panel.link();
            store.write(
                "panel.private.json",
                &serde_json::to_vec(
                    &serde_json::json!({"origin":panel.origin,"url":url,"secret":panel.bootstrap,"pid":std::process::id()}),
                )?,
                false,
            )?;
            println!("{url}");
            app.log(
                "INFO",
                if cfg!(feature = "production") {
                    "ConWU 后台已启动"
                } else {
                    "ConWU Rust 实验后台已启动；使用独立数据目录"
                },
            );
            app.boot().await;
            app.supervise();
            app.start_departures();
            uu::start(app.clone());
            #[cfg(windows)]
            if service {
                app.start_projection_firewall();
            }
            #[cfg(windows)]
            let tray = if !service && !no_tray {
                Some(tray::start(panel.clone()))
            } else {
                None
            };
            if !no_open && !service {
                platform::open_panel(&url)?;
            }
            tokio::select! {r=platform::shutdown_signal()=>r?,_=app.engine.cancel.cancelled()=>{},_=platform::service_cancel().cancelled_owned()=>{}}
            app.engine.shutdown().await?;
            #[cfg(windows)]
            if let Some(tray) = tray {
                tray.await??;
            }
            web.await??;
        }
    }
    Ok(())
}
