use std::convert::Infallible;

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
