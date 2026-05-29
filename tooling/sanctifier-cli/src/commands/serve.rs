use anyhow::{Context, Result};
use clap::Args;
use sanctifier_core::rules::RuleRegistry;
use sanctifier_core::SanctifyConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

#[derive(Args)]
pub struct ServeArgs {
    /// Port to bind to
    #[arg(short, long, default_value = "9100")]
    port: u16,

    /// Address to bind to
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,
}

#[derive(Clone)]
struct AppState {
    registry: Arc<RuleRegistry>,
}

pub fn exec(args: ServeArgs) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async { serve_async(args).await })
}

async fn serve_async(args: ServeArgs) -> Result<()> {
    let registry = Arc::new(RuleRegistry::with_default_rules());
    let state = AppState { registry };

    let addr: SocketAddr = format!("{}:{}", args.bind, args.port)
        .parse()
        .context("Invalid bind address")?;

    println!("Sanctifier HTTP server starting on http://{}", addr);
    println!("   POST /analyze (body: raw Rust source) — returns NDJSON findings");
    println!("   GET  /health");

    let state_filter = warp::any().map(move || state.clone());

    let analyze_route = warp::post()
        .and(warp::path("analyze"))
        .and(warp::body::bytes())
        .and(state_filter.clone())
        .and_then(handle_analyze);

    let health_route = warp::get()
        .and(warp::path("health"))
        .map(|| warp::reply::json(&serde_json::json!({"status": "ok"})));

    let routes = analyze_route.or(health_route).recover(handle_rejection);

    warp::serve(routes).run(addr).await;

    Ok(())
}

async fn handle_analyze(
    body: warp::hyper::body::Bytes,
    state: AppState,
) -> Result<impl Reply, Rejection> {
    let source = String::from_utf8(body.to_vec()).map_err(|_| warp::reject::reject())?;
    let violations = state.registry.run_all(&source);
    let findings: Vec<serde_json::Value> = violations
        .into_iter()
        .map(|v| {
            serde_json::json!({
                "rule": v.rule_name,
                "severity": format!("{:?}", v.severity),
                "message": v.message,
                "location": v.location,
                "suggestion": v.suggestion,
            })
        })
        .collect();
    Ok(warp::reply::json(&findings))
}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Rejection> {
    if err.is_not_found() {
        Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"error": "Not found"})),
            warp::http::StatusCode::NOT_FOUND,
        ))
    } else {
        Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"error": "Internal server error"})),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        ))
    }
}
