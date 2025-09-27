use log::info;
use tonic::{transport::Server, Request, Response, Status};
use crate::metrics::proto::{MetricsBatch, metrics_service_server::{MetricsService, MetricsServiceServer}};

#[derive(Debug)]
pub struct MetricsReceiver;

#[tonic::async_trait]
impl MetricsService for MetricsReceiver {
    async fn send_metrics(
        &self,
        request: Request<MetricsBatch>,
    ) -> Result<Response<()>, Status> {
        let batch = request.into_inner();
        info!("Received batch with {} metrics", batch.metrics.len());
        Ok(Response::new(()))
    }
}

pub async fn run_server(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let receiver = MetricsReceiver;
    Server::builder()
        .add_service(MetricsServiceServer::new(receiver))
        .serve(addr.parse()?)
        .await?;
    Ok(())
}
