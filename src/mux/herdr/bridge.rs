use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "watchme.herdr";
pub const SCHEMA_VERSION: u16 = 1;

#[derive(Serialize)]
pub(super) struct Request<'a, P> {
    pub schema_version: u16,
    pub protocol: &'static str,
    pub request_id: &'a str,
    pub method: &'a str,
    pub params: P,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Response<T> {
    pub schema_version: u16,
    pub protocol: String,
    pub request_id: String,
    pub method: String,
    pub ok: bool,
    pub result: Option<T>,
    pub error: Option<String>,
}
