mod adapter;
mod assistance;
mod backend;
mod coordinator;
mod discovery;
mod dns;
mod flow;
mod gateway;
mod logging;
mod migration;
mod model;
mod pkarr;
mod platform;
mod raw;
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
#[command(name = "conwu", about = "ConWU Rust 隔离实验，数据目录必须单独指定")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
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
    Run {
        #[arg(long)]
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
    Stop {
        #[arg(long)]
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
    let command = Cli::parse().command;
    #[cfg(windows)]
    if matches!(command, Command::Run { service: true, .. }) {
        return platform::dispatch_service();
    }
    tokio::runtime::Runtime::new()?.block_on(run(command))
}
async fn run(command: Command) -> Result<()> {
    match command {
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
        Command::Version => println!("ConWU {} · Rust experiment", model::VERSION),
        Command::Panel { data } => {
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
        Command::Stop { data } => {
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
            let components = components.unwrap_or(
                std::env::current_exe()?
                    .parent()
                    .unwrap()
                    .join("components"),
            );
            let (app, events) = backend::App::open(store.clone(), components, memory)?;
            platform::start(app.clone());
            let event_app = app.clone();
            app.engine.tracker.spawn(async move {
                event_app.events(events).await;
            });
            let (panel, web) = web::Panel::start(app.clone(), port).await?;
            let url = panel.link();
            store.write(
                "panel.private.json",
                &serde_json::to_vec(
                    &serde_json::json!({"origin":panel.origin,"url":url,"secret":panel.bootstrap,"pid":std::process::id()}),
                )?,
                false,
            )?;
            println!("{url}");
            app.log("INFO", "ConWU Rust 实验后台已启动；使用独立数据目录");
            app.boot().await;
            app.start_departures();
            uu::start(app.clone());
            #[cfg(windows)]
            let tray = if !service && !no_tray {
                Some(tray::start(panel.clone()))
            } else {
                None
            };
            if !no_open && !service {
                platform::open_browser(&url)?;
            }
            tokio::select! {r=tokio::signal::ctrl_c()=>r?,_=app.engine.cancel.cancelled()=>{},_=platform::service_cancel().cancelled_owned()=>{}}
            app.engine.shutdown().await;
            #[cfg(windows)]
            if let Some(tray) = tray {
                tray.await??;
            }
            web.await??;
        }
    }
    Ok(())
}
