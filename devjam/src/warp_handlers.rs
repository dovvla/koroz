use std::convert::Infallible;

use prometheus::{Encoder, TextEncoder};
use warp::http::StatusCode;
use warp::{
    reply::{self, Reply},
    Filter,
};

use crate::structs::Universe;

pub fn with_universe(
    universe: Universe,
) -> impl Filter<Extract = (Universe,), Error = Infallible> + Clone {
    warp::any().map(move || universe.clone())
}

pub async fn get_universe(universe: Universe) -> Result<impl Reply, warp::Rejection> {
    let universe = universe.read().await;

    std::result::Result::Ok(reply::with_status(
        reply::json(&universe.clone()),
        StatusCode::OK,
    ))
}

pub async fn metrics() -> Result<impl Reply, warp::Rejection> {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    std::result::Result::Ok(String::from_utf8(buffer.clone()).unwrap())
}
