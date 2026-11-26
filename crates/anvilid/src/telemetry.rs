//! Telemetry installation (OPS-08): the Prometheus recorder behind `/metrics`.
//!
//! The recorder is process-wide and installed once, only when metrics are exposed
//! (`metrics_listen` or `metrics_on_main_port`); otherwise the metric macros are no-ops. The
//! exporter runs without its own listener: `/metrics` is our axum route
//! (`anvil_web::observability::metrics_router`) and [`upkeep`] does the periodic maintenance the
//! listener would otherwise do.

use std::time::Duration;

use anvil_web::observability::{
    DURATION_BUCKETS, HTTP_REQUEST_DURATION_SECONDS, MetricsEndpoint, describe_metrics,
};
use anyhow::Context;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tokio::sync::watch;

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
