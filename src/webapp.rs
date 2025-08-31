use askama::Template;
use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, Response},
    routing::{get, post},
};
use chrono::{NaiveDateTime, Utc};
use clap::Parser;
use config::Config;
use log::*;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde::{Deserialize, Serialize};
use sqlx::{
    FromRow,
    postgres::{PgPool, PgPoolOptions},
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::{signal, sync::Mutex, time::Duration};
use tower::ServiceBuilder;
use tower_http::{
    services::ServeDir,
    set_header::SetResponseHeaderLayer,
    trace::{self, TraceLayer},
};
use tracing::Level;

/**
 * Command line argments:
 *   --config <file.toml>
 */
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// config file to read
    #[arg(long)]
    config: String,
}

/**
 * Application config to be read from .toml file
 */
#[derive(Deserialize)]
pub struct AppConfig {
    db_url: String,
    bind_address: String,
}

/**
 * Account information delivered to handlers from the auth middlelayer
 *
 */
#[derive(Clone, Deserialize, Debug, FromRow)]
pub struct AccountInfo {
    pub id: i32,
    pub username: String,
    pub name: String,
    pub expires: NaiveDateTime,
    pub address: IpAddr,
}

type PassedAccountInfo = Option<Arc<AccountInfo>>;

/**
 * Application Context, shared between handlers and middleware
 */
#[derive(Clone)]
struct AppContext {
    db: PgPool,
    tokens: Arc<Mutex<HashMap<String, Arc<AccountInfo>>>>,
}

/**
 * Get the bearer token from a headermap.
 * Token can either be passed as Authorization header,
 * or in cookie. If both are present they must be equal
 * to qualify as an authentication.
 */
fn get_token(headers: HeaderMap) -> Option<String> {
    // see if there is a Bearer authorization header
    let maybe_token_header = match headers.get("authorization") {
        None => None::<String>,
        Some(header) => match header.to_str() {
            Ok(value) => {
                if value.starts_with("Bearer ") {
                    Some(value[7..].to_string().clone())
                } else {
                    None::<String>
                }
            }
            Err(_) => None::<String>,
        },
    };

    // see if there is a Bearer cookie
    let maybe_token_cookie = match headers.get("cookie") {
        None => None::<String>,
        Some(header) => match header.to_str() {
            Ok(value) => {
                if value.starts_with("Bearer=") {
                    Some(value[7..].to_string().clone())
                } else {
                    None::<String>
                }
            }
            Err(_) => None::<String>,
        },
    };

    // map out the discovered information to a secure decision
    match (maybe_token_header, maybe_token_cookie) {
        (Some(value1), Some(value2)) => {
            if value1 == value2 {
                Some(value1)
            } else {
                None::<String>
            }
        }
        (Some(value), None) => Some(value),
        (None, Some(value)) => Some(value),
        (None, None) => None::<String>,
    }
}

/**
 * Janitor function that evicts expired account information
 * from application context.
 */
async fn janitor(state: AppContext) {
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(120));
    loop {
        timer.tick().await;
        info!("Janitor running");

        // remove all expired tokens
        let mut lock = state.tokens.lock().await;
        let now = Utc::now().naive_utc();
        lock.retain(|_, v| v.expires > now);
    }
}

/**
 * Authentication middleware - sets Some(AccountInfo) for handlers to see.
 */
async fn bearer_middleware(
    State(state): State<AppContext>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let maybe_token = get_token(headers);

    let maybe_account_info = match maybe_token {
        None => None::<Arc<AccountInfo>>,
        Some(token) => {
            let mut lock = state.tokens.lock().await;
            match lock.get(&token) {
                Some(account_info) => {
                    if account_info.expires < Utc::now().naive_utc() {
                        lock.remove(&token);
                        None
                    } else {
                        Some(account_info.clone())
                    }
                }
                None => {
                    let maybe_account_info = sqlx::query_as::<_, AccountInfo>("select a.id, a.name, a.username, at.expires, at.address from access_token at inner join account a on a.id = at.account where at.token = $1 and expires > (now() at time zone 'utc')")
                        .bind(&token)
                        .fetch_optional(&state.db).await.map_err(internal_error).unwrap();
                    match maybe_account_info {
                        None => None,
                        Some(account_info) => {
                            let ai = Arc::new(account_info);
                            lock.insert(token.clone(), ai.clone());
                            Some(ai)
                        }
                    }
                }
            }
        }
    };
    request.extensions_mut().insert(maybe_account_info);
    let response = next.run(request).await;

    Ok(response)
}

/**
 * Main application; loads specified configuration file and start the application.
 */
#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();
    let settings = Config::builder()
        .add_source(config::File::with_name(args.config.as_str()))
        .build()
        .unwrap();
    let config = settings.try_deserialize::<AppConfig>().unwrap();

    // set up connection pool
    let pool = PgPoolOptions::new()
        .max_connections(50)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&config.db_url.as_str())
        .await
        .expect("can't connect to database");

    let app_state = AppContext {
        db: pool.clone(),
        tokens: Arc::new(Mutex::new(HashMap::new())),
    };

    // instantiate prometheus layer and metrics server
    // only allow ipv6 localhost to pull metrics for security
    PrometheusBuilder::new()
        .with_http_listener((IpAddr::from_str("::1").unwrap(), 3050))
        .add_allowed_address("::1/128")
        .unwrap()
        .install()
        .unwrap();

    // build our application with a route
    let app = Router::new()
        .merge(static_router("./static"))
        .merge(web_application(app_state.clone()))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            bearer_middleware,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::WARN))
                .on_response(trace::DefaultOnResponse::new().level(Level::WARN)),
        )
        .fallback(not_found_route())
        .layer(axum_metrics::MetricLayer::default())
        .into_make_service_with_connect_info::<SocketAddr>();

    // start janitor
    tokio::spawn(janitor(app_state.clone()));

    // run it
    let listener = tokio::net::TcpListener::bind(config.bind_address.as_str())
        .await
        .unwrap();
    info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

/**
 * Shut down gracefully on ctrl-c and terminate
 */
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn static_router(path: &str) -> Router {
    Router::new().nest_service(
        "/static",
        ServiceBuilder::new()
            .layer(SetResponseHeaderLayer::overriding(
                http::header::CACHE_CONTROL,
                http::header::HeaderValue::from_static("public, max-age=31536000, immutable"),
            ))
            .service(ServeDir::new(path).precompressed_gzip()),
    )
}

fn web_application(context: AppContext) -> Router {
    Router::new()
        .route("/", get(frontpage))
        .route("/login", post(login_handler))
        .route("/logout", get(logout_handler))
        .with_state(context)
}

/**
 * Data required for the login post
 */
#[derive(Debug, Deserialize)]
struct LoginPostData {
    username: String,
    password: String,
}

/**
 * Data returned on successful login
 */
#[derive(Debug, Serialize)]
struct LoginBearerResponse {
    bearer: String,
}

/**
 * The Login handler responds to post requests with a request body being
 * a json document of form:
 *
 * {
 *   "username": "someusername",
 *   "password": "somepassword"
 * }
 *
 * it responds with a 200 OK and a json document of:
 *
 * {
 *   "bearer": "sometoken"
 * }
 *
 * on success, and a 401 with text "invalid" on failure.
 */
async fn login_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(ctx): State<AppContext>,
    Json(payload): Json<LoginPostData>,
) -> Result<Json<LoginBearerResponse>, (StatusCode, String)> {
    let valid: Option<String> = sqlx::query_scalar("insert into access_token (account, token, address) select id, encode(gen_random_bytes(54), 'base64'), $3 from account where username = $1 and password = crypt($2, substr(password, 1, 11)) returning token;")
        .bind(payload.username)
        .bind(payload.password)
        .bind(addr.ip())
        .fetch_optional(&ctx.db).await.map_err(internal_error).unwrap();
    match valid {
        Some(token) => Ok(Json(LoginBearerResponse {
            bearer: token.to_string(),
        })),
        None => Err((StatusCode::UNAUTHORIZED, "invalid".to_string())),
    }
}

/**
 * Logout by removing the bearer token.
 */
async fn logout_handler(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
) -> Result<String, (StatusCode, String)> {
    let maybe_token = get_token(headers);
    match maybe_token {
        None => Ok("OK".to_string()),
        Some(token) => {
            let _ = sqlx::query("delete from access token where token=$1")
                .bind(&token)
                .execute(&ctx.db)
                .await;
            let mut lock = ctx.tokens.lock().await;
            lock.remove(&token);
            Ok("OK".to_string())
        }
    }
}

/**
 * Struct being passed to template
 *
 */
#[derive(Template)]
#[template(path = "frontpage.html")]
struct FrontPageTemplate<'a> {
    value: &'a i32,
    account: PassedAccountInfo,
}

/**
 * Frontpage display
 *
 */
async fn frontpage(
    Extension(account_info): Extension<PassedAccountInfo>,
    State(ctx): State<AppContext>,
) -> Result<Html<String>, (StatusCode, String)> {
    let value: i32 =
        sqlx::query_scalar("update data set count=count+1 where name='default' returning count")
            .fetch_one(&ctx.db)
            .await
            .map_err(internal_error)
            .unwrap();
    let page_data = FrontPageTemplate {
        value: &value,
        account: account_info,
    };
    Ok(Html(page_data.render().unwrap()))
}

/**
 * Utility function to map any error to '500 Internal Server Error'
 *
 */
fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

/**
 * Implementation of the fallback handler; just giving a 404 Not Found.
 */
fn not_found_route() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "NOT FOUND")
}
