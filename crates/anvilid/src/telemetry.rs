//! Telemetry installation (OPS-08): logs, the audit stream, OpenTelemetry traces and the
//! Prometheus recorder behind `/metrics`.
//!
//! - [`init_tracing`]: logs to stderr (`log_format`), audit events to stdout, and, only when
//!   `otel_endpoint` is set, an OTLP/HTTP (protobuf) batch exporter with `service.name` =
//!   `otel_service_name`. The exporter is operator infrastructure (like SMTP and Postgres): it
//!   uses its own blocking HTTP client, not the SSRF-guarded outbound client. Audit events never
//!   become span events. [`TelemetryGuard::shutdown`] flushes pending spans on exit.
//! - Incoming `traceparent` is honoured only from trusted proxies
//!   ([`TelemetryGuard::trace_context_hook`] → `AppConfig::trace_context`).
//! - The metrics recorder is process-wide and installed once, only when metrics are exposed
//!   (`metrics_listen` or `metrics_on_main_port`); otherwise the metric macros are no-ops. The
//!   exporter runs without its own listener: `/metrics` is our axum route
//!   (`anvil_web::observability::metrics_router`) and [`upkeep`] does the periodic maintenance
//!   the listener would otherwise do.

use std::io::IsTerminal as _;
use std::time::Duration;

use anvil_web::observability::{
    DURATION_BUCKETS, HTTP_REQUEST_DURATION_SECONDS, MetricsEndpoint, TraceContextHook,
    describe_metrics,
};
use anyhow::Context;
use axum::http::HeaderMap;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use opentelemetry::propagation::{Extractor, TextMapPropagator as _};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{Protocol, WithExportConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanExporter};
use tokio::sync::watch;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::filter::{FilterExt as _, LevelFilter, Targets, filter_fn};
use tracing_subscriber::layer::{Context as LayerContext, SubscriberExt as _};
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer, Registry};

use crate::config::{Config, LogFormat};

/// Tracing target of the audit stream (ADM-04).
pub const AUDIT_TARGET: &str = "audit";
/// OTLP/HTTP path of the traces signal, appended to `otel_endpoint` unless already present.
pub const OTLP_TRACES_PATH: &str = "/v1/traces";
/// Instrumentation scope of our spans.
const TRACER_NAME: &str = "anvilid";

/// The audit mirror of this binary: every recorded audit event becomes an `info` event on the
/// `audit` target, which [`AuditStdout`] prints.
struct TracingMirror;

impl anvil_core::ports::AuditMirror for TracingMirror {
    fn emit(&self, event_json: &str) {
        tracing::info!(target: AUDIT_TARGET, event = %event_json);
    }
}

/// Prints the `event` field of every `audit`-target event as one raw JSON line on stdout. The
/// JSON comes from `anvil_core::service::audit::event_json`, which holds only typed, secret-free
/// fields.
struct AuditStdout;

impl<S: tracing::Subscriber> Layer<S> for AuditStdout {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: LayerContext<'_, S>) {
        struct EventField(Option<String>);
        impl tracing::field::Visit for EventField {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "event" {
                    self.0 = Some(value.to_owned());
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "event" {
                    self.0 = Some(format!("{value:?}"));
                }
            }
        }
        if event.metadata().target() != AUDIT_TARGET {
            return;
        }
        let mut field = EventField(None);
        event.record(&mut field);
        if let Some(json) = field.0 {
            use std::io::Write as _;
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{json}");
            let _ = out.flush();
        }
    }
}

/// Trace export settings (from `otel_endpoint` / `otel_service_name`).
pub struct OtelConfig {
    /// Full OTLP/HTTP traces URL (`…/v1/traces`).
    pub traces_url: String,
    pub service_name: String,
}

impl OtelConfig {
    /// The export settings of `cfg`, or `None` when `otel_endpoint` is unset.
    pub fn from_config(cfg: &Config) -> Option<Self> {
        cfg.otel_endpoint.as_ref().map(|endpoint| Self {
            traces_url: traces_url(&endpoint.0),
            service_name: cfg.otel_service_name.clone(),
        })
    }
}

/// `otel_endpoint` is a base URL (like `OTEL_EXPORTER_OTLP_ENDPOINT`): `/v1/traces` is
/// appended unless the path already ends with it.
pub fn traces_url(endpoint: &url::Url) -> String {
    let mut url = endpoint.clone();
    let path = url.path().trim_end_matches('/').to_owned();
    if !path.ends_with(OTLP_TRACES_PATH) {
        url.set_path(&format!("{path}{OTLP_TRACES_PATH}"));
    }
    url.to_string()
}

/// The resource of every exported span: `service.name`, `service.version` and the SDK
/// defaults.
fn resource(service_name: &str) -> Resource {
    Resource::builder()
        .with_service_name(service_name.to_owned())
        .with_attribute(opentelemetry::KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION"),
        ))
        .build()
}

/// A batch tracer provider over `exporter`.
pub fn tracer_provider(
    exporter: impl SpanExporter + 'static,
    service_name: &str,
) -> SdkTracerProvider {
    SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource(service_name))
        .build()
}

/// The tracing → OpenTelemetry layer: `RUST_LOG` (default `info`) like the logs, never the
/// audit stream.
pub fn otel_layer(provider: &SdkTracerProvider) -> Box<dyn Layer<Registry> + Send + Sync> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(TRACER_NAME))
        .with_filter(filter.and(filter_fn(|meta| meta.target() != AUDIT_TARGET)))
        .boxed()
}

/// Reads W3C trace-context headers.
struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(axum::http::HeaderName::as_str).collect()
    }
}

/// Continues the trace of a trusted proxy's `traceparent` on the request span.
pub fn trace_context_hook() -> TraceContextHook {
    TraceContextHook::new(|headers, span| {
        let parent = TraceContextPropagator::new().extract(&HeaderExtractor(headers));
        // Fails only when no OpenTelemetry layer is installed; then there is nothing to continue.
        let _ = span.set_parent(parent);
    })
}

/// Keeps the trace exporter alive; [`Self::shutdown`] flushes it.
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl TelemetryGuard {
    /// The trusted-proxy trace-context hook when traces are exported.
    pub fn trace_context_hook(&self) -> Option<TraceContextHook> {
        self.provider.as_ref().map(|_| trace_context_hook())
    }

    /// Flushes and stops the trace exporter (blocking: run it off the async workers).
    pub fn shutdown(self) {
        if let Some(provider) = self.provider
            && let Err(e) = provider.shutdown()
        {
            tracing::warn!(error = %e, "flushing traces on shutdown failed");
        }
    }
}

/// Logs go to stderr, filtered by `RUST_LOG` (default `info`). Audit events go to stdout as JSON
/// lines through a separate layer that is always enabled at `info` for the `audit` target,
/// independent of `RUST_LOG`, and are excluded from the stderr log. Stdout otherwise carries only
/// command output (`config show`, `admin setup-url`, `keys rotate`). With `otel`, spans are
/// exported over OTLP/HTTP as well.
pub fn init_tracing(format: LogFormat, otel: Option<OtelConfig>) -> anyhow::Result<TelemetryGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let general = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let general = match format {
        LogFormat::Json => general.json().boxed(),
        LogFormat::Pretty => general.with_ansi(std::io::stderr().is_terminal()).boxed(),
    };
    let general = general
        .with_filter(filter.and(filter_fn(|meta| meta.target() != AUDIT_TARGET)))
        .boxed();
    let audit = AuditStdout
        .with_filter(Targets::new().with_target(AUDIT_TARGET, LevelFilter::INFO))
        .boxed();
    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = vec![general, audit];
    let provider = match otel {
        Some(otel) => {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(otel.traces_url)
                .build()
                // The error may quote the endpoint, which may carry credentials.
                .map_err(|_| anyhow::anyhow!("otel_endpoint: failed to build the OTLP exporter"))?;
            let provider = tracer_provider(exporter, &otel.service_name);
            layers.push(otel_layer(&provider));
            Some(provider)
        }
        None => None,
    };
    tracing_subscriber::registry().with(layers).init();
    anvil_core::service::audit::install_mirror(Box::new(TracingMirror));
    if provider.is_some() {
        tracing::info!("exporting traces over OTLP/HTTP");
    }
    Ok(TelemetryGuard { provider })
}

/// How often [`upkeep`] runs.
pub const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);

/// The exporter configuration: explicit latency buckets, so the duration renders as a real
/// histogram instead of a summary.
pub fn metrics_builder() -> anyhow::Result<PrometheusBuilder> {
    PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full(HTTP_REQUEST_DURATION_SECONDS.to_owned()),
            DURATION_BUCKETS,
        )
        .context("invalid metrics buckets")
}

/// Installs the process-wide recorder and registers the metric descriptions. Call once.
pub fn install_metrics() -> anyhow::Result<PrometheusHandle> {
    let handle = metrics_builder()?
        .install_recorder()
        .context("failed to install the metrics recorder")?;
    describe_metrics();
    Ok(handle)
}

/// The `/metrics` renderer over an exporter handle.
pub fn endpoint(handle: PrometheusHandle) -> MetricsEndpoint {
    MetricsEndpoint::new(move || handle.render())
}

/// Runs the exporter maintenance (histogram rollover, idle cleanup) every
/// [`UPKEEP_INTERVAL`] until shutdown.
pub async fn upkeep(handle: PrometheusHandle, mut shutdown: watch::Receiver<bool>) {
    let mut ticks = tokio::time::interval(UPKEEP_INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.wait_for(|stop| *stop) => break,
            _ = ticks.tick() => handle.run_upkeep(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use anvil_core::clock::SystemClock;
    use anvil_core::ports::{Clock, Storage};
    use anvil_web::observability::{JOBS_RUNS_TOTAL, METRIC_NAMES, record_request};

    use super::*;
    use crate::jobs::{LeaseRunner, PeriodicJob};

    fn local_handle() -> (
        metrics_exporter_prometheus::PrometheusRecorder,
        PrometheusHandle,
    ) {
        let recorder = metrics_builder().expect("builder").build_recorder();
        let handle = recorder.handle();
        (recorder, handle)
    }

    /// Records spans in memory and keeps the resource the provider hands to the exporter.
    #[derive(Debug, Default)]
    struct Recording {
        spans: opentelemetry_sdk::trace::InMemorySpanExporter,
        resource: Arc<std::sync::Mutex<Option<Resource>>>,
    }

    impl SpanExporter for Recording {
        fn export(
            &self,
            batch: Vec<opentelemetry_sdk::trace::SpanData>,
        ) -> impl std::future::Future<Output = opentelemetry_sdk::error::OTelSdkResult> + Send
        {
            self.spans.export(batch)
        }

        fn set_resource(&mut self, resource: &Resource) {
            *self.resource.lock().expect("resource") = Some(resource.clone());
        }
    }

    fn recording_provider(
        service: &str,
    ) -> (
        SdkTracerProvider,
        opentelemetry_sdk::trace::InMemorySpanExporter,
        Arc<std::sync::Mutex<Option<Resource>>>,
    ) {
        let exporter = Recording::default();
        let spans = exporter.spans.clone();
        let resource = Arc::clone(&exporter.resource);
        (tracer_provider(exporter, service), spans, resource)
    }

    #[test]
    fn telemetry_spans_are_exported_with_the_service_name_and_without_audit_events() {
        let (provider, spans, resource) = recording_provider("anvilid-test");
        let subscriber = tracing_subscriber::registry().with(otel_layer(&provider));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http.request", route = "/token");
            span.in_scope(|| {
                tracing::info!(target: AUDIT_TARGET, event = "audit-only-payload");
                tracing::info!(route = "/token", "request");
            });
        });
        provider.force_flush().expect("flush");
        let finished = spans.get_finished_spans().expect("spans");
        let span = finished
            .iter()
            .find(|s| s.name == "http.request")
            .expect("exported span");
        assert!(
            span.attributes
                .iter()
                .any(|kv| kv.key.as_str() == "route" && kv.value.as_str() == "/token"),
            "{:?}",
            span.attributes
        );
        let events = format!("{:?}", span.events);
        assert!(events.contains("request"), "{events}");
        assert!(!events.contains("audit-only-payload"), "{events}");
        let resource = resource
            .lock()
            .expect("resource")
            .clone()
            .expect("resource set");
        assert_eq!(
            resource
                .get(&opentelemetry::Key::new("service.name"))
                .map(|v| v.as_str().into_owned()),
            Some("anvilid-test".to_owned())
        );
        assert_eq!(
            resource
                .get(&opentelemetry::Key::new("service.version"))
                .map(|v| v.as_str().into_owned()),
            Some(env!("CARGO_PKG_VERSION").to_owned())
        );
        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn telemetry_trace_context_hook_continues_the_incoming_trace() {
        let (provider, spans, _) = recording_provider("anvilid");
        let subscriber = tracing_subscriber::registry().with(otel_layer(&provider));
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
                .parse()
                .expect("header"),
        );
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http.request");
            trace_context_hook().call(&headers, &span);
            span.in_scope(|| {});
        });
        provider.force_flush().expect("flush");
        let finished = spans.get_finished_spans().expect("spans");
        let span = finished.first().expect("exported span");
        assert_eq!(
            span.span_context.trace_id().to_string(),
            "0af7651916cd43dd8448eb211c80319c"
        );
        assert_eq!(span.parent_span_id.to_string(), "b7ad6b7169203331");
        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn telemetry_traces_url_appends_the_signal_path_once() {
        for (base, want) in [
            ("http://127.0.0.1:4318", "http://127.0.0.1:4318/v1/traces"),
            ("http://127.0.0.1:4318/", "http://127.0.0.1:4318/v1/traces"),
            (
                "https://otel.example.test/otlp",
                "https://otel.example.test/otlp/v1/traces",
            ),
            (
                "https://otel.example.test/v1/traces",
                "https://otel.example.test/v1/traces",
            ),
        ] {
            assert_eq!(
                traces_url(&url::Url::parse(base).expect("url")),
                want,
                "{base}"
            );
        }
    }

    #[test]
    fn telemetry_duration_renders_as_histogram_with_class_labels_only() {
        let (recorder, handle) = local_handle();
        metrics::with_local_recorder(&recorder, || {
            describe_metrics();
            record_request("token", 200, Duration::from_millis(3));
            record_request("auth", 429, Duration::from_millis(40));
        });
        let text = handle.render();
        assert!(
            text.contains(
                "anvil_http_request_duration_seconds_bucket{route_class=\"token\",le=\"0.005\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "anvil_http_requests_total{route_class=\"token\",status_class=\"2xx\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains("anvil_http_requests_total{route_class=\"auth\",status_class=\"4xx\"} 1"),
            "{text}"
        );
        assert!(text.contains("# HELP anvil_http_requests_total"), "{text}");
        // Only class labels (plus the histogram's `le`).
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let Some(labels) = line.split_once('{').map(|(_, rest)| rest) else {
                continue;
            };
            let labels = labels.split('}').next().unwrap_or_default();
            for pair in labels.split(',') {
                let name = pair.split('=').next().unwrap_or_default();
                assert!(
                    matches!(name, "route_class" | "status_class" | "le"),
                    "unexpected label {name} in {line}"
                );
            }
        }
        assert!(METRIC_NAMES.contains(&HTTP_REQUEST_DURATION_SECONDS));
    }

    struct NoopJob;

    impl PeriodicJob for NoopJob {
        fn name(&self) -> &'static str {
            "telemetry_test_job"
        }

        fn run(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(async {})
        }
    }

    #[test]
    fn telemetry_job_runs_are_counted() {
        let (recorder, handle) = local_handle();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let storage = anvil_storage_sqlite::SqliteStorage::connect("sqlite::memory:")
                    .await
                    .expect("sqlite");
                storage.migrate().await.expect("migrate");
                let storage: Arc<dyn Storage> = Arc::new(storage);
                let clock: Arc<dyn Clock> = Arc::new(SystemClock);
                let runner = LeaseRunner::new(storage, clock);
                assert!(runner.run_once(&NoopJob).await);
            });
        });
        let text = handle.render();
        assert!(
            text.contains(&format!(
                "{JOBS_RUNS_TOTAL}{{job=\"telemetry_test_job\",outcome=\"ran\"}} 1"
            )),
            "{text}"
        );
    }

    #[tokio::test]
    async fn telemetry_metrics_listener_serves_only_metrics() {
        let (recorder, handle) = local_handle();
        metrics::with_local_recorder(&recorder, || {
            record_request("token", 200, Duration::from_millis(1));
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(crate::server::run_metrics(listener, endpoint(handle), rx));
        let resp = reqwest::get(format!("http://{addr}/metrics"))
            .await
            .expect("metrics");
        assert_eq!(resp.status(), 200);
        assert!(
            resp.headers()["content-type"]
                .to_str()
                .expect("ascii")
                .starts_with("text/plain")
        );
        let body = resp.text().await.expect("body");
        assert!(body.contains("anvil_http_requests_total"), "{body}");
        for path in [
            "/",
            "/healthz",
            "/authorize",
            "/.well-known/openid-configuration",
        ] {
            let status = reqwest::get(format!("http://{addr}{path}"))
                .await
                .expect("request")
                .status();
            assert_eq!(status, 404, "{path}");
        }
        tx.send(true).expect("stop");
        server.await.expect("join").expect("clean stop");
    }
}
